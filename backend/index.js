import express from 'express';
import cors from 'cors';
import multer from 'multer';
import mammoth from 'mammoth';
import pdfParse from 'pdf-parse';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { ethers } from 'ethers';
import dotenv from 'dotenv';
import { createHelia } from 'helia';
import { strings } from '@helia/strings';
import contractJSON from './abi/ReportValidator.json' assert { type: 'json' };

dotenv.config();

// ---- Env checks ----
const requiredEnv = ['RPC_URL', 'PRIVATE_KEY', 'CONTRACT_ADDRESS', 'ENCRYPTION_KEY'];
for (const k of requiredEnv) {
  if (!process.env[k]) {
    console.error(`Missing env var: ${k}`);
    process.exit(1);
  }
}

const app = express();
const port = process.env.PORT || 3000;

// ---- Rate limiting ----
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again after 15 minutes.'
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// ---- Helia (IPFS) ----
const helia = await createHelia();
const s = strings(helia);

// ---- Ethers (contract) ----
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractJSON.abi, wallet);

// ---- Multer (file upload) ----
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const okExt = ['.pdf', '.docx'].includes(path.extname(file.originalname).toLowerCase());
    const okType = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ].includes(file.mimetype);
    if (okExt && okType) cb(null, true);
    else cb(new Error('Only .pdf and .docx files are allowed.'));
  }
});

// ---- Canonicalization helpers ----

// Remove zero-width and BOM chars
const removeInvisible = (str) => str.replace(/[\u200B-\u200D\uFEFF]/g, '');

// Replace fancy quotes/dashes with simple ones
const normalizePunctuation = (str) =>
  str
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[–—]/g, '-') // en/em dash -> hyphen
    .replace(/\u00A0/g, ' '); // non-breaking space -> space

// Basic unit/test-name normalization maps (extend as needed)
const UNIT_MAP = new Map([
  ['mg per dl', 'mg/dl'],
  ['mg/dl', 'mg/dl'],
  ['mg dl', 'mg/dl'],
  ['mmol/l', 'mmol/l']
]);

const normalizeUnitsInline = (str) => {
  // Replace common unit phrases with canonical ones (case-insensitive)
  let out = str.replace(/\bmg\s*per\s*dl\b/gi, 'mg/dl').replace(/\bmg\s*dl\b/gi, 'mg/dl');
  return out;
};

// Level-1 and Level-2 canonicalization combined
const canonicalizeText = (raw) => {
  if (!raw) return '';

  let text = raw.normalize('NFKC');
  text = removeInvisible(text);
  text = normalizePunctuation(text);

  // Normalize line endings, remove hyphenation at line breaks (multi-\nline -> multiline)
  text = text.replace(/\r/g, '\n').replace(/-\n/g, '');

  // Collapse spaces/tabs and excessive newlines
  text = text.replace(/[ \t]+/g, ' ').replace(/\n{2,}/g, '\n');

  // Normalize common unit synonyms
  text = normalizeUnitsInline(text);

  // Lowercase and trim
  text = text.trim().toLowerCase();

  return text;
};

// Optional: Section splitting (stub for future Merkle)
// For now, we just return everything as one section.
// You can extend this to detect "labs:", "medications:", etc.
const splitSections = (text) => {
  return [{ name: 'full', content: text }];
};

// ---- Encryption (AES-256-GCM with scrypt key derivation) ----
const encryptText = (text) => {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const key = crypto.scryptSync(String(process.env.ENCRYPTION_KEY), salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    alg: 'AES-256-GCM',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: enc.toString('base64')
  };
};

// ---- Route: upload ----
app.post('/upload', upload.single('file'), async (req, res) => {
  const cleanup = () => {
    try {
      if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    } catch {}
  };

  try {
    const file = req.file;
    if (!file) return res.status(400).send('No file uploaded.');

    const ext = path.extname(file.originalname).toLowerCase();
    let rawText = '';

    if (ext === '.pdf') {
      const dataBuffer = fs.readFileSync(file.path);
      const pdfData = await pdfParse(dataBuffer);
      // Remove hyphenation artifacts specific to PDFs (some already covered)
      rawText = pdfData.text.replace(/-\n/g, '');
    } else if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: file.path });
      rawText = result.value || '';
    } else {
      return res.status(400).send('Unsupported file type.');
    }

    // Delete temp file as early as possible
    cleanup();

    // Canonicalize
    const normalized = canonicalizeText(rawText);

    // Optional: sectioning (returns a single "full" section for now)
    const sections = splitSections(normalized);

    // Hash (ethers keccak256 over UTF-8 bytes)
    const hash = ethers.keccak256(ethers.toUtf8Bytes(normalized)); // 0x-prefixed 66-char

    // Encrypt canonical text for storage
    const encryptedPayload = JSON.stringify(encryptText(normalized));

    // Upload to IPFS via Helia
    const textCID = await s.addString(encryptedPayload);

    // Optional: also store hash string on IPFS (can be skipped)
    // const hashCID = await s.addString(hash);

    // Call smart contract (bytes32 + string)
    // Optional: add gasLimit if your RPC underestimates
    const tx = await contract.uploadReport(hash, textCID.toString());
    await tx.wait();

    return res.status(200).json({
      textCID: textCID.toString(),
      hash: hash,
      sections: sections.map((sec) => sec.name),
      hashPreview: hash.slice(0, 12),
      txHash: tx.hash
    });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).send('Server error processing file.');
  } finally {
    // Safety cleanup in case of early return
    try {
      if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    } catch {}
  }
});

// ---- Health & graceful shutdown ----
app.get('/health', (req, res) => res.status(200).send('ok'));

const server = app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

const shutdown = async () => {
  console.log('Shutting down...');
  server.close(() => process.exit(0));
  try {
    await helia.stop();
  } catch {}
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

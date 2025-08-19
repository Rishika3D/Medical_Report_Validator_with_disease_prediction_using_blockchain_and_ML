import express from 'express';
import cors from 'cors';
import multer from 'multer';
import mammoth from 'mammoth';
import PdfParse from 'pdf-parse';
import fs from 'fs';
import path from 'path';
import { keccak256 } from 'js-sha3';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { ethers } from 'ethers';
import dotenv from 'dotenv';
import { createHelia } from 'helia';
import { strings } from '@helia/strings';
import contractJSON from './abi/ReportValidator.json' assert { type: 'json' };

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Apply rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many requests from this IP, please try again after 15 minutes.'
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// Helia setup for IPFS
const helia = await createHelia();
const s = strings(helia);

// Multer setup
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.pdf' || ext === '.docx') cb(null, true);
    else cb(new Error('Only .pdf and .docx files are allowed.'));
  }
});

// Ethers setup
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractJSON.abi, signer);

// AES encryption function for IPFS storage
const encryptText = (text) => {
  const key = crypto.createHash('sha256').update(String(process.env.ENCRYPTION_KEY)).digest('base64').slice(0, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return { iv: iv.toString('base64'), data: encrypted };
};

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).send('No file uploaded.');

    const ext = path.extname(file.originalname).toLowerCase();
    let text = '';

    if (ext === '.pdf') {
      const dataBuffer = fs.readFileSync(file.path);
      const pdfData = await PdfParse(dataBuffer);
      text = pdfData.text;
    } else if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: file.path });
      text = result.value;
    }

    fs.unlinkSync(file.path);

    // Normalize text for hashing
    const normalizedText = text.replace(/\s+/g, ' ').trim().toLowerCase();

    // Hash for verification
    const hash = keccak256(normalizedText);

    // Encrypt text for IPFS
    const encrypted = encryptText(normalizedText);
    const encryptedPayload = JSON.stringify(encrypted);

    // Upload encrypted text to IPFS
    const textCID = await s.addString(encryptedPayload);
    const hashCID = await s.addString(hash);

    // Smart contract call
    const tx = await contract.uploadReport('0x' + hash, textCID.toString());
    await tx.wait();

    res.status(200).json({
      textCID: textCID.toString(),
      hashCID: hashCID.toString(),
      hashPreview: hash.slice(0, 20),
      txHash: tx.hash
    });
  } catch (err) {
    console.error('Upload error:', err.message);
    res.status(500).send(`Server error: ${err.message}`);
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

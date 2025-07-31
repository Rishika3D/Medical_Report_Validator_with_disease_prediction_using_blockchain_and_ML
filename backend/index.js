import express from 'express'
import cors from 'cors'
import multer from 'multer'
import mammoth from 'mammoth'
import PdfParse from 'pdf-parse'
import fs from 'fs'
import path from 'path'
import { createHelia } from 'helia'
import { strings } from '@helia/strings'
import { keccak256 } from 'js-sha3'
import rateLimit from 'express-rate-limit'

const app = express()
const port = 3000

// Rate Limiter – max 20 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many requests from this IP, please try again after 15 minutes.'
})

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(limiter) // Apply to all routes

// Initialize Helia and Strings
const helia = await createHelia()
const s = strings(helia)

// File Size Limit = 5MB
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase()
    if (ext === '.pdf' || ext === '.docx') {
      cb(null, true)
    } else {
      cb(new Error('Only .pdf and .docx files are allowed.'))
    }
  }
})

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file
    if (!file) return res.status(400).send('No file uploaded.')

    const ext = path.extname(file.originalname).toLowerCase()
    let text = ''

    if (ext === '.pdf') {
      const dataBuffer = fs.readFileSync(file.path)
      const pdfData = await PdfParse(dataBuffer)
      text = pdfData.text
    } else if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: file.path })
      text = result.value
    }

    // Clean up uploaded file
    fs.unlinkSync(file.path)

    // Upload to IPFS
    const textCID = await s.addString(text)
    const hash = keccak256(text)
    const hashCID = await s.addString(hash)

    console.log('Uploaded to IPFS:', textCID.toString())

    res.status(200).json({
      textCID: textCID.toString(),
      hashCID: hashCID.toString(),
      hashPreview: hash.slice(0, 20),
      textPreview: text.slice(0, 500)
    })
  } catch (err) {
    console.error('Upload error:', err.message)
    res.status(500).send(`Server error: ${err.message}`)
  }
})

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})

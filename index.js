import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'

dotenv.config()
const app = express()
const PORT = process.env.PORT || 8000  // 1. Railway 8000 expect karta hai

// 2. CORS ko sab se pehle lagao
app.use(cors({ 
  origin: "https://threatwatch-client-production.up.railway.app",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}))

app.use(express.json())

// 3. Routes
import authRoutes from './routes/authRoutes.js'
import scanRoutes from './routes/scanRoutes.js'
import adminRoutes from './routes/adminRoutes.js'
import moderatorRoutes from './routes/moderatorRoutes.js'

app.use('/api/auth', authRoutes)
app.use('/api/scan', scanRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/moderator', moderatorRoutes)

// 4. Health check
app.get('/', (req, res) => {
  res.json({message: "ThreatWatch-AI Server is running 🚀"})
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'

dotenv.config() // 1. Sab se pehle ye
const app = express()
const PORT = process.env.PORT || 8000

console.log("PORT:", PORT) // 2. Debug ke liye add karo
console.log("MONGO:", process.env.MONGO_URI ? "YES" : "NO")
console.log("GEMINI:", process.env.GEMINI_API_KEY ? "YES" : "NO")

app.use(cors({ 
  origin: "https://threatwatch-client-production.up.railway.app",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}))

app.use(express.json())

// Routes
import authRoutes from './routes/authRoutes.js'
import scanRoutes from './routes/scanRoutes.js'
import adminRoutes from './routes/adminRoutes.js'
import moderatorRoutes from './routes/moderatorRoutes.js'

app.use('/api/auth', authRoutes)
app.use('/api/scan', scanRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/moderator', moderatorRoutes)

app.get('/', (req, res) => {
  res.json({message: "ThreatWatch-AI Server is running 🚀"})
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
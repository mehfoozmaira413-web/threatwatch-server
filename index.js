import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'

dotenv.config()
const app = express()
const PORT = process.env.PORT || 5001

app.use(cors({ 
  origin: "https://threatwatch-client-production.up.railway.app",
  credentials: true
}))

app.use(express.json())

// 1. یہاں import کیا
import authRoutes from './routes/authRoutes.js'
import scanRoutes from './routes/scanRoutes.js'
import adminRoutes from './routes/adminRoutes.js'
import moderatorRoutes from './routes/moderatorRoutes.js'

// 2. یہاں use کیا
app.use('/api/auth', authRoutes)
app.use('/api/scan', scanRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/moderator', moderatorRoutes)

app.get('/', (req, res) => {
  res.send('Server is running')
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
}) 
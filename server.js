require("dotenv").config();

const express = require("express");
const cors = require("cors");
const http = require("http");
const mongoose = require("mongoose");

const { Server } = require("socket.io");
const { GoogleGenAI } = require("@google/genai");

const connectDB = require("./config/db");

const authRoutes = require("./routes/authRoutes");
const authMiddleware = require("./middleware/authMiddleware");

const Scan = require("./models/Scan");

const scanRoutes = require("./routes/scanRoutes");
const adminRoutes = require("./routes/adminRoutes");
const moderatorRoutes = require("./routes/moderatorRoutes");

const setupSocket = require("./socket");

const {
  runVerificationPipeline,
} = require("./agents/verificationPipeline");

// =====================================================
// APP & PORT
// =====================================================

const app = express();
const server = http.createServer(app);

// Railway PORT
const PORT = process.env.PORT || 8000;

// Your deployed frontend + Local dev
const allowedOrigins = [
  "https://threatwatch-client-production.up.railway.app", // production
  "http://localhost:5173" // local dev vite
];

// =====================================================
// CORS - Allow both Local + Production
// =====================================================
app.use(
  cors({
    origin: function (origin, callback) {
      // Postman / curl ke liye allow
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        return callback(new Error('CORS not allowed by server'), false);
      }
      return callback(null, true);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// =====================================================
// SOCKET.IO
// =====================================================

const io = new Server(server, {
  cors: {
    origin: allowedOrigins, // yahan bhi same array
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  },
});

setupSocket(io);

app.set("io", io);

// =====================================================
// AI MODELS
// =====================================================

const TEXT_MODEL = "gemini-3.1-flash-lite";
const IMAGE_MODEL = "gemini-3.6-flash";

// =====================================================
// DATABASE
// =====================================================

connectDB();

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json({ limit: "15mb" }));

// =====================================================
// HEALTH
// =====================================================

app.get("/api/health", (req, res) => {
  return res.status(200).json({
    status: "ok",
    message: "ThreatWatch-AI API is running",
    socketIO: true,
    port: PORT,
    env: process.env.NODE_ENV || "development",
    models: {
      text: TEXT_MODEL,
      image: IMAGE_MODEL,
    },
  });
});

// =====================================================
// AUTH
// =====================================================

app.use("/api/auth", authRoutes);

// =====================================================
// SCAN HISTORY
// =====================================================

app.use("/api/scans", scanRoutes);

// =====================================================
// MODERATOR
// =====================================================

app.use("/api/moderator", moderatorRoutes);

// =====================================================
// ADMIN
// =====================================================

app.use("/api/admin", adminRoutes);

// =====================================================
// GEMINI API KEY
// =====================================================

const GEMINI_KEY = process.env.GEMINI_API_KEY;

console.log("====================================");
console.log("🔐 GEMINI API CONFIG");
console.log(
  "GEMINI_API_KEY EXISTS:",
  !!process.env.GEMINI_API_KEY
);
console.log(
  "GOOGLE_API_KEY EXISTS:",
  !!process.env.GOOGLE_API_KEY
);
console.log(
  "GEMINI KEY LENGTH:",
  GEMINI_KEY ? GEMINI_KEY.length : 0
);
console.log("====================================");

if (!GEMINI_KEY) {
  console.error("❌ GEMINI_API_KEY is missing!");
}

// Gemini client
const ai = new GoogleGenAI({
  apiKey: GEMINI_KEY,
});

// =====================================================
// CLEAN GEMINI JSON
// =====================================================

function cleanGeminiJSON(text) {
  if (!text) {
    throw new Error("Gemini returned an empty response.");
  }

  let cleaned = String(text).trim();

  cleaned = cleaned
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (error) {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");

    if (start !== -1 && end !== -1 && end > start) {
      try {
        return JSON.parse(
          cleaned.substring(start, end + 1)
        );
      } catch (e) {
        throw new Error(
          "Gemini returned invalid JSON."
        );
      }
    }

    throw new Error(
      "Gemini returned invalid JSON."
    );
  }
}

// =====================================================
// ARRAY HELPERS
// =====================================================

function safeStringArray(value) {
  if (!Array.isArray(value)) return [];

  return value
    .filter(
      (item) =>
        item !== null &&
        item !== undefined
    )
    .map((item) =>
      String(item).trim()
    )
    .filter(Boolean);
}

function toArray(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return [];
  }

  return Array.isArray(value)
    ? value
    : [value];
}

// =====================================================
// NORMALIZE EVIDENCE
// =====================================================

function normalizeEvidence(value) {
  return toArray(value)
    .map((item) => {
      if (typeof item === "string") {
        return {
          claim: "",
          finding: item,
          sourceTitle: "AI Analysis",
          sourceUrl: "",
          sourceType: "AI",
          supportsClaim: false,
        };
      }

      if (
        !item ||
        typeof item !== "object"
      ) {
        return null;
      }

      return {
        claim: String(item.claim || ""),
        finding: String(item.finding || ""),
        sourceTitle: String(
          item.sourceTitle || ""
        ),
        sourceUrl: String(
          item.sourceUrl || ""
        ),
        sourceType: String(
          item.sourceType || "WEB"
        ),
        supportsClaim:
          item.supportsClaim === true,
      };
    })
    .filter(Boolean);
}

// =====================================================
// NORMALIZE SOURCES
// =====================================================

function normalizeSources(value) {
  return toArray(value)
    .map((item) => {
      if (typeof item === "string") {
        return {
          title: item,
          url: "",
          publisher: "",
          publishedAt: "",
        };
      }

      if (
        !item ||
        typeof item !== "object"
      ) {
        return null;
      }

      return {
        title: String(item.title || ""),
        url: String(item.url || ""),
        publisher: String(
          item.publisher || ""
        ),
        publishedAt: String(
          item.publishedAt || ""
        ),
      };
    })
    .filter(Boolean);
}

// =====================================================
// VALIDATE REPORT
// =====================================================

function validateReport(data = {}) {
  let riskScore = Number(
    data.riskScore
  );

  let confidenceScore = Number(
    data.confidenceScore
  );

  if (Number.isNaN(riskScore)) {
    riskScore = 0;
  }

  if (
    Number.isNaN(confidenceScore)
  ) {
    confidenceScore = 0;
  }

  riskScore = Math.min(
    100,
    Math.max(0, riskScore)
  );

  confidenceScore = Math.min(
    100,
    Math.max(0, confidenceScore)
  );

  const allowedVerdicts = [
    "SAFE",
    "THREAT",
    "LIKELY_TRUE",
    "LIKELY_FALSE",
    "UNCERTAIN",
  ];

  const verdict =
    allowedVerdicts.includes(
      data.verdict
    )
      ? data.verdict
      : "UNCERTAIN";

  return {
    riskScore,
    confidenceScore,
    verdict,
    claims: safeStringArray(
      data.claims
    ),
    threats: safeStringArray(
      data.threats
    ),
    summary:
      typeof data.summary === "string"
        ? data.summary
        : "No summary provided.",
    report:
      typeof data.report === "string"
        ? data.report
        : "",
    evidence:
      normalizeEvidence(
        data.evidence
      ),
    sources:
      normalizeSources(
        data.sources
      ),
    isSafe: riskScore < 40,
  };
}

// =====================================================
// BROADCAST NEW SCAN
// =====================================================

function broadcastScan(
  io,
  savedScan
) {
  if (!io || !savedScan) return;

  const scanPayload = {
    _id: savedScan._id,
    user: savedScan.user,
    url: savedScan.url,
    scanType: savedScan.scanType,
    riskScore:
      savedScan.riskScore,
    confidenceScore:
      savedScan.confidenceScore,
    verdict:
      savedScan.verdict,
    claims:
      savedScan.claims,
    threats:
      savedScan.threats,
    summary:
      savedScan.summary,
    report:
      savedScan.report,
    evidence:
      savedScan.evidence,
    sources:
      savedScan.sources,
    isSafe:
      savedScan.isSafe,
    createdAt:
      savedScan.createdAt,
  };

  io.to("moderators").emit(
    "scan_completed",
    scanPayload
  );

  io.to("admins").emit(
    "scan_completed",
    scanPayload
  );

  io.to(
    `user:${savedScan.user}`
  ).emit(
    "scan_completed",
    scanPayload
  );

  console.log(
    "📡 scan_completed emitted"
  );
}

// =====================================================
// GEMINI JSON
// =====================================================

async function generateJSON(prompt) {
  if (!GEMINI_KEY) {
    throw new Error(
      "GEMINI_API_KEY is not configured on the server."
    );
  }

  const result =
    await ai.models.generateContent({
      model: TEXT_MODEL,
      contents: prompt,
      config: {
        responseMimeType:
          "application/json",
      },
    });

  return cleanGeminiJSON(
    result.text
  );
}

// =====================================================
// URL SCANNER
// =====================================================

app.post(
  "/api/scan",
  authMiddleware,
  async (req, res) => {
    try {
      const { url } = req.body;

      if (
        !url ||
        typeof url !== "string" ||
        !url.trim()
      ) {
        return res.status(400).json({
          message: "URL is required.",
        });
      }

      const cleanUrl =
        url.trim();

      const io =
        req.app.get("io");

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "started",
          type: "URL",
          message:
            "URL scan started...",
        }
      );

      console.log(
        "🌐 URL SCAN:",
        cleanUrl
      );

      const prompt = `
You are ThreatWatch AI.
Analyze ONLY the URL structure below.
URL: ${cleanUrl}
Return ONLY JSON.
`;

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status:
            "ai_processing",
          type: "URL",
          message:
            "AI is analyzing URL...",
        }
      );

      const aiResult =
        await generateJSON(
          prompt
        );

      const data =
        validateReport(
          aiResult
        );

      const savedScan =
        await Scan.create({
          user: req.user.id,
          url: cleanUrl,
          scanType: "URL",
          ...data,
        });

      broadcastScan(
        io,
        savedScan
      );

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "completed",
          type: "URL",
          message:
            "URL scan completed.",
          result: data,
        }
      );

      return res
        .status(200)
        .json(data);

    } catch (error) {
      console.error(
        "❌ URL SCAN ERROR:",
        error
      );

      const io =
        req.app.get("io");

      if (
        io &&
        req.user?.id
      ) {
        io.to(
          `user:${req.user.id}`
        ).emit(
          "scan_status",
          {
            status: "error",
            type: "URL",
            message:
              error.message ||
              "URL scan failed.",
          }
        );
      }

      return res
        .status(500)
        .json({
          message:
            "URL scan failed.",
          details:
            error.message,
        });
    }
  }
);

// =====================================================
// TEXT SCANNER
// =====================================================

app.post(
  "/api/scan/text",
  authMiddleware,
  async (req, res) => {
    try {
      const { text } =
        req.body;

      if (
        !text ||
        typeof text !== "string" ||
        !text.trim()
      ) {
        return res.status(400).json({
          message:
            "Text is required.",
        });
      }

      const cleanText =
        text.trim();

      const io =
        req.app.get("io");

      const pipelineResult =
        await runVerificationPipeline(
          cleanText
        );

      const data =
        validateReport(
          pipelineResult
        );

      const finalData = {
        ...data,
        report:
          data.report ||
          data.summary,
      };

      const savedScan =
        await Scan.create({
          user: req.user.id,
          url:
            "TEXT_SCAN: " +
            cleanText.substring(
              0,
              100
            ),
          scanType: "TEXT",
          ...finalData,
        });

      broadcastScan(
        io,
        savedScan
      );

      return res
        .status(200)
        .json(finalData);

    } catch (error) {
      console.error(
        "❌ TEXT SCAN ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          message:
            "Text verification failed.",
          details:
            error.message,
        });
    }
  }
);

// =====================================================
// IMAGE SCANNER
// =====================================================

app.post(
  "/api/scan/image",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        image,
        mimeType,
      } = req.body;

      if (!image) {
        return res.status(400).json({
          message:
            "Image is required.",
        });
      }

      if (!mimeType) {
        return res.status(400).json({
          message:
            "Image MIME type is required.",
        });
      }

      const base64Data =
        image.includes(",")
          ? image.split(",")[1]
          : image;

      const prompt = `
You are ThreatWatch AI.
Analyze this image for phishing, scams, fake screenshots.
Return ONLY JSON.
`;

      const result =
        await ai.models.generateContent(
          {
            model:
              IMAGE_MODEL,
            contents: [
              {
                role: "user",
                parts: [
                  {
                    inlineData: {
                      mimeType,
                      data: base64Data,
                    },
                  },
                  {
                    text: prompt,
                  },
                ],
              },
            ],
            config: {
              responseMimeType:
                "application/json",
            },
          }
        );

      const aiData =
        cleanGeminiJSON(
          result.text
        );

      const data =
        validateReport(
          aiData
        );

      const savedScan =
        await Scan.create({
          user: req.user.id,
          url: "IMAGE_SCAN",
          scanType: "IMAGE",
          ...data,
        });

      broadcastScan(
        io,
        savedScan
      );

      return res
        .status(200)
        .json(data);

    } catch (error) {
      console.error(
        "❌ IMAGE SCAN ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          message:
            "Image scan failed.",
          details:
            error.message,
        });
    }
  }
);

// =====================================================
// ROOT
// =====================================================

app.get("/", (req, res) => {
  res.json({
    message:
      "ThreatWatch-AI Server is running 🚀",
    socketIO: true,
    port: PORT,
  });
});

// =====================================================
// 404
// =====================================================

app.use(
  (req, res) => {
    res.status(404).json({
      message:
        "API route not found.",
    });
  }
);

// =====================================================
// ERROR HANDLER
// =====================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      message:
        "Internal server error.",
      details:
        error.message,
    });
  }
);

// =====================================================
// START SERVER
// =====================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log("");
    console.log(
      "===================================="
    );
    console.log(
      "🚀 ThreatWatch-AI Server Started"
    );
    console.log(
      `📡 PORT: ${PORT}`
    );
    console.log(
      "🌐 Host: 0.0.0.0"
    );
    console.log(
      "🔌 Socket.IO ENABLED"
    );
    console.log(
      `📝 Text/URL Model: ${TEXT_MODEL}`
    );
    console.log(
      `🖼️ Image Model: ${IMAGE_MODEL}`
    );
    console.log(
      "===================================="
    );
  }
);
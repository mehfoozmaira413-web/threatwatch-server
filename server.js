require("dotenv").config();

const express = require("express");
const cors = require("cors");
const http = require("http");

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
// APP
// =====================================================

const app = express();

const server = http.createServer(app);

const PORT = 5001;

// =====================================================
// SOCKET.IO
// =====================================================

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true,
  },
});

// Setup Socket.IO authentication + rooms
setupSocket(io);

// Make io available inside routes
app.set("io", io);

// =====================================================
// AI MODELS
// =====================================================

const TEXT_MODEL =
  "gemini-3.1-flash-lite";

const IMAGE_MODEL =
  "gemini-3.6-flash";

// =====================================================
// DATABASE
// =====================================================

connectDB();

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(
  express.json({
    limit: "15mb",
  })
);

// =====================================================
// HEALTH
// =====================================================

app.get(
  "/api/health",
  (req, res) => {
    return res.status(200).json({
      status: "ok",

      message:
        "ThreatWatch-AI API is running",

      socketIO: true,

      models: {
        text: TEXT_MODEL,
        image: IMAGE_MODEL,
      },
    });
  }
);

// =====================================================
// AUTH
// =====================================================

app.use(
  "/api/auth",
  authRoutes
);

// =====================================================
// SCAN HISTORY
// =====================================================

app.use(
  "/api/scans",
  scanRoutes
);

// =====================================================
// MODERATOR
// =====================================================

app.use(
  "/api/moderator",
  moderatorRoutes
);

// =====================================================
// ADMIN
// =====================================================

app.use(
  "/api/admin",
  adminRoutes
);

// =====================================================
// GEMINI
// =====================================================

const GOOGLE_KEY =
  process.env.GOOGLE_API_KEY ||
  process.env.GEMINI_API_KEY;

if (!GOOGLE_KEY) {
  console.warn(
    "⚠️ GOOGLE_API_KEY / GEMINI_API_KEY missing"
  );
}

const ai =
  new GoogleGenAI({
    apiKey: GOOGLE_KEY,
  });

// =====================================================
// CLEAN GEMINI JSON
// =====================================================

function cleanGeminiJSON(text) {
  if (!text) {
    throw new Error(
      "Gemini returned an empty response."
    );
  }

  let cleaned =
    String(text).trim();

  cleaned =
    cleaned
      .replace(
        /^```json\s*/i,
        ""
      )
      .replace(
        /^```\s*/i,
        ""
      )
      .replace(
        /\s*```$/i,
        ""
      )
      .trim();

  try {
    return JSON.parse(cleaned);
  } catch (error) {
    const start =
      cleaned.indexOf("{");

    const end =
      cleaned.lastIndexOf("}");

    if (
      start !== -1 &&
      end !== -1 &&
      end > start
    ) {
      try {
        return JSON.parse(
          cleaned.substring(
            start,
            end + 1
          )
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
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter(
      (item) =>
        item !== null &&
        item !== undefined
    )
    .map(
      (item) =>
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
      if (
        typeof item === "string"
      ) {
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
        claim: String(
          item.claim || ""
        ),

        finding: String(
          item.finding || ""
        ),

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
      if (
        typeof item === "string"
      ) {
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
        title: String(
          item.title || ""
        ),

        url: String(
          item.url || ""
        ),

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
  let riskScore =
    Number(data.riskScore);

  let confidenceScore =
    Number(
      data.confidenceScore
    );

  if (Number.isNaN(riskScore)) {
    riskScore = 0;
  }

  if (
    Number.isNaN(
      confidenceScore
    )
  ) {
    confidenceScore = 0;
  }

  riskScore = Math.min(
    100,
    Math.max(0, riskScore)
  );

  confidenceScore =
    Math.min(
      100,
      Math.max(
        0,
        confidenceScore
      )
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

    claims:
      safeStringArray(
        data.claims
      ),

    threats:
      safeStringArray(
        data.threats
      ),

    summary:
      typeof data.summary ===
      "string"
        ? data.summary
        : "No summary provided.",

    report:
      typeof data.report ===
      "string"
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

    isSafe:
      riskScore < 40,
  };
}

// =====================================================
// BROADCAST NEW SCAN
// =====================================================

function broadcastScan(io, savedScan) {
  if (!io || !savedScan) {
    return;
  }

  const scanPayload = {
    _id: savedScan._id,
    user: savedScan.user,
    url: savedScan.url,
    scanType: savedScan.scanType,
    riskScore: savedScan.riskScore,
    confidenceScore:
      savedScan.confidenceScore,
    verdict: savedScan.verdict,
    claims: savedScan.claims,
    threats: savedScan.threats,
    summary: savedScan.summary,
    report: savedScan.report,
    evidence: savedScan.evidence,
    sources: savedScan.sources,
    isSafe: savedScan.isSafe,
    createdAt: savedScan.createdAt,
  };

  // Moderator dashboard
  io.to("moderators").emit(
    "scan_completed",
    scanPayload
  );

  // Admin dashboard
  io.to("admins").emit(
    "scan_completed",
    scanPayload
  );

  // Specific user
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
          message:
            "URL is required.",
        });
      }

      const cleanUrl =
        url.trim();

      const io =
        req.app.get("io");

      // -------------------------------------------------
      // LIVE STATUS
      // -------------------------------------------------

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

URL:
${cleanUrl}

You have NOT visited this website.

Do not claim that you accessed,
browsed or searched the website.

Analyze:

- HTTPS usage
- suspicious domain
- typosquatting
- impersonation
- suspicious subdomains
- unusual paths
- query parameters
- phishing indicators
- scam indicators
- deceptive patterns

Return ONLY JSON.

{
  "riskScore": 0,
  "confidenceScore": 0,
  "verdict": "UNCERTAIN",
  "claims": [],
  "threats": [],
  "summary": "",
  "report": "",
  "evidence": [],
  "sources": []
}

Verdict must be:
SAFE
THREAT
UNCERTAIN

Do not invent sources.
`;

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "ai_processing",
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

          riskScore:
            data.riskScore,

          confidenceScore:
            data.confidenceScore,

          verdict:
            data.verdict,

          claims:
            data.claims,

          threats:
            data.threats,

          summary:
            data.summary,

          report:
            data.report,

          evidence:
            data.evidence,

          sources:
            data.sources,

          isSafe:
            data.isSafe,
        });

      // -------------------------------------------------
      // SOCKET BROADCAST
      // -------------------------------------------------

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

      return res.status(200).json(
        data
      );
    } catch (error) {
      console.error(
        "❌ URL SCAN ERROR:",
        error
      );

      const io =
        req.app.get("io");

      if (io && req.user?.id) {
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

      return res.status(500).json({
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
      const { text } = req.body;

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

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "started",
          type: "TEXT",
          message:
            "Text verification started...",
        }
      );

      // -------------------------------------------------
      // AGENT 1
      // -------------------------------------------------

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "agent_1",
          type: "TEXT",
          message:
            "Agent 1 → Claim Extraction",
        }
      );

      // -------------------------------------------------
      // AGENT PIPELINE
      // -------------------------------------------------

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "agent_2",
          type: "TEXT",
          message:
            "Agent 2 → Research",
        }
      );

      const pipelineResult =
        await runVerificationPipeline(
          cleanText
        );

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "agent_3",
          type: "TEXT",
          message:
            "Agent 3 → Analysis",
        }
      );

      const data =
        validateReport(
          pipelineResult
        );

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "agent_4",
          type: "TEXT",
          message:
            "Agent 4 → Report Generation",
        }
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

          riskScore:
            finalData.riskScore,

          confidenceScore:
            finalData.confidenceScore,

          verdict:
            finalData.verdict,

          claims:
            finalData.claims,

          threats:
            finalData.threats,

          summary:
            finalData.summary,

          report:
            finalData.report,

          evidence:
            finalData.evidence,

          sources:
            finalData.sources,

          isSafe:
            finalData.isSafe,
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
          type: "TEXT",
          message:
            "Text verification completed.",
          result: finalData,
        }
      );

      return res.status(200).json(
        finalData
      );
    } catch (error) {
      console.error(
        "❌ TEXT SCAN ERROR:",
        error
      );

      const io =
        req.app.get("io");

      if (io && req.user?.id) {
        io.to(
          `user:${req.user.id}`
        ).emit(
          "scan_status",
          {
            status: "error",
            type: "TEXT",
            message:
              error.message ||
              "Text verification failed.",
          }
        );
      }

      return res.status(500).json({
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

      const io =
        req.app.get("io");

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "started",
          type: "IMAGE",
          message:
            "Image scan started...",
        }
      );

      const base64Data =
        image.includes(",")
          ? image.split(",")[1]
          : image;

      const prompt = `
You are ThreatWatch AI.

Analyze this image for:

- phishing
- scams
- fake screenshots
- misleading claims
- suspicious messages
- deceptive information
- manipulated visual information

You have NOT performed external web research.

Do not invent sources.

Return ONLY JSON:

{
  "riskScore": 0,
  "confidenceScore": 0,
  "verdict": "UNCERTAIN",
  "claims": [],
  "threats": [],
  "summary": "",
  "report": "",
  "evidence": [],
  "sources": []
}

Verdict:
SAFE
THREAT
UNCERTAIN
`;

      io.to(
        `user:${req.user.id}`
      ).emit(
        "scan_status",
        {
          status: "ai_processing",
          type: "IMAGE",
          message:
            "AI is analyzing image...",
        }
      );

      const result =
        await ai.models.generateContent({
          model: IMAGE_MODEL,

          contents: [
            {
              role: "user",

              parts: [
                {
                  inlineData: {
                    mimeType,
                    data:
                      base64Data,
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
        });

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

          url:
            "IMAGE_SCAN",

          scanType: "IMAGE",

          riskScore:
            data.riskScore,

          confidenceScore:
            data.confidenceScore,

          verdict:
            data.verdict,

          claims:
            data.claims,

          threats:
            data.threats,

          summary:
            data.summary,

          report:
            data.report,

          evidence:
            data.evidence,

          sources:
            data.sources,

          isSafe:
            data.isSafe,
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
          type: "IMAGE",
          message:
            "Image scan completed.",
          result: data,
        }
      );

      return res.status(200).json(
        data
      );
    } catch (error) {
      console.error(
        "❌ IMAGE SCAN ERROR:",
        error
      );

      const io =
        req.app.get("io");

      if (io && req.user?.id) {
        io.to(
          `user:${req.user.id}`
        ).emit(
          "scan_status",
          {
            status: "error",
            type: "IMAGE",
            message:
              error.message ||
              "Image scan failed.",
          }
        );
      }

      return res.status(500).json({
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

app.get(
  "/",
  (req, res) => {
    res.json({
      message:
        "ThreatWatch-AI Server is running 🚀",

      socketIO: true,

      endpoints: {
        health:
          "GET /api/health",

        login:
          "POST /api/auth/login",

        register:
          "POST /api/auth/register",

        url:
          "POST /api/scan",

        text:
          "POST /api/scan/text",

        image:
          "POST /api/scan/image",

        history:
          "GET /api/scans",

        moderator:
          "/api/moderator",

        admin:
          "/api/admin",
      },
    });
  }
);

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
  () => {
    console.log("");
    console.log(
      "===================================="
    );
    console.log(
      "🚀 ThreatWatch-AI Server Started"
    );
    console.log(
      `📡 http://localhost:${PORT}`
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
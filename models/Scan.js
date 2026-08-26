const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema(
  {
    // =====================================================
    // USER WHO CREATED THE SCAN
    // =====================================================

    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // =====================================================
    // SCAN TARGET
    // =====================================================

    url: {
      type: String,
      required: true,
      trim: true,
    },

    // =====================================================
    // SCAN TYPE
    // =====================================================

    scanType: {
      type: String,
      enum: ["URL", "TEXT", "IMAGE"],
      default: "URL",
    },

    // =====================================================
    // AI RISK SCORE
    // =====================================================

    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
      default: 0,
    },

    // =====================================================
    // AI CONFIDENCE SCORE
    // =====================================================

    confidenceScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    // =====================================================
    // AI VERDICT
    // =====================================================

    verdict: {
      type: String,
      enum: [
        "SAFE",
        "THREAT",
        "LIKELY_TRUE",
        "LIKELY_FALSE",
        "UNCERTAIN",
      ],
      default: "UNCERTAIN",
    },

    // =====================================================
    // CLAIMS
    // =====================================================

    claims: {
      type: [String],
      default: [],
    },

    // =====================================================
    // THREATS DETECTED BY AI
    // =====================================================

    threats: {
      type: [String],
      default: [],
    },

    // =====================================================
    // SUMMARY
    // =====================================================

    summary: {
      type: String,
      default: "",
    },

    // =====================================================
    // REPORT
    // =====================================================

    report: {
      type: String,
      default: "",
    },

    // =====================================================
    // EVIDENCE
    // =====================================================

    evidence: [
      {
        claim: {
          type: String,
          default: "",
        },

        finding: {
          type: String,
          default: "",
        },

        sourceTitle: {
          type: String,
          default: "",
        },

        sourceUrl: {
          type: String,
          default: "",
        },

        sourceType: {
          type: String,
          default: "WEB",
        },

        supportsClaim: {
          type: Boolean,
          default: false,
        },
      },
    ],

    // =====================================================
    // SOURCES
    // =====================================================

    sources: [
      {
        title: {
          type: String,
          default: "",
        },

        url: {
          type: String,
          default: "",
        },

        publisher: {
          type: String,
          default: "",
        },

        publishedAt: {
          type: String,
          default: "",
        },
      },
    ],

    // =====================================================
    // SAFE STATUS
    // =====================================================

    isSafe: {
      type: Boolean,
      required: true,
      default: false,
    },

    // =====================================================
    // 🚩 MODERATOR / ADMIN FLAG SYSTEM
    // =====================================================

    // Whether the scan has been manually flagged
    isFlagged: {
      type: Boolean,
      default: false,
    },

    // User who flagged this scan
    flaggedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // Role of the person who flagged it
    flaggedByRole: {
      type: String,
      enum: ["Admin", "Moderator", null],
      default: null,
    },

    // Reason for flagging
    flagReason: {
      type: String,
      default: "",
      trim: true,
    },

    // Time when scan was flagged
    flaggedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Scan", scanSchema);
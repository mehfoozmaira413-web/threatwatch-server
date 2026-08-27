const express = require("express");
const router = express.Router();
const Scan = require("../models/Scan");
const Permission = require("../models/Permission"); // <-- 1. YE ADD KIYA
const authMiddleware = require("../middleware/authMiddleware");

// =====================================================
// MODERATOR ROLE CHECK
// =====================================================

function moderatorOnly(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
    });
  }

  const role = String(req.user.role || "").toLowerCase();

  if (role !== "moderator" && role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Moderator access required.",
    });
  }

  next();
}

// =====================================================
// TEST ROUTE
// GET /api/moderator
// =====================================================

router.get("/", authMiddleware, moderatorOnly, (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Moderator API is working.",
    role: req.user.role,
  });
});

// =====================================================
// MODERATOR STATS
// GET /api/moderator/stats
// =====================================================

router.get("/stats", authMiddleware, moderatorOnly, async (req, res) => {
  try {
    const [totalScans, safeScans, threatScans, uncertainScans, urlScans, textScans, imageScans] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ verdict: "SAFE" }),
      Scan.countDocuments({ verdict: "THREAT" }),
      Scan.countDocuments({ verdict: { $in: ["UNCERTAIN", "LIKELY_TRUE", "LIKELY_FALSE"] } }),
      Scan.countDocuments({ scanType: "URL" }),
      Scan.countDocuments({ scanType: "TEXT" }),
      Scan.countDocuments({ scanType: "IMAGE" }),
    ]);

    return res.status(200).json({
      success: true,
      scans: { total: totalScans, url: urlScans, text: textScans, image: imageScans },
      results: { safe: safeScans, threats: threatScans, uncertain: uncertainScans },
    });
  } catch (error) {
    console.error("MODERATOR STATS ERROR:", error);
    return res.status(500).json({ success: false, message: "Could not load moderator statistics.", details: error.message });
  }
});

// =====================================================
// ALL SECURITY SCANS
// GET /api/moderator/scans
// =====================================================

router.get("/scans", authMiddleware, moderatorOnly, async (req, res) => {
  try {
    const scans = await Scan.find().populate("user", "name email role").sort({ createdAt: -1 }).lean();
    return res.status(200).json({ success: true, count: scans.length, scans });
  } catch (error) {
    console.error("MODERATOR SCANS ERROR:", error);
    return res.status(500).json({ success: false, message: "Could not load security scans.", details: error.message });
  }
});

// =====================================================
// FLAG SCAN AS THREAT
// POST /api/moderator/scans/:id/flag
// =====================================================

router.post("/scans/:id/flag", authMiddleware, moderatorOnly, async (req, res) => {
  try {
    const scanId = req.params.id;
    const reason = String(req.body?.reason || "").trim();

    if (!reason) {
      return res.status(400).json({
        success: false,
        message: "Please provide a reason for flagging this scan.",
      });
    }

    // =====================================================
    // 2. PERMISSION CHECK - YE NAYA BLOCK ADD KIYA
    // =====================================================
    const myPerm = await Permission.findOne({ role: req.user.role });
    const userRole = String(req.user.role).toLowerCase();
    if(!myPerm?.permissions?.canFlag && userRole !== "admin") {
      return res.status(403).json({
        success: false,
        message: "You don't have permission to flag scans",
      });
    }
    // =====================================================

    const scan = await Scan.findById(scanId);
    if (!scan) {
      return res.status(404).json({ success: false, message: "Scan not found." });
    }

    scan.isFlagged = true;
    scan.flaggedBy = req.user.id;
    scan.flagReason = reason;
    scan.flaggedAt = new Date();
    await scan.save();

    const updatedScan = await Scan.findById(scan._id)
      .populate("user", "name email role")
      .populate("flaggedBy", "name email role")
      .lean();

    return res.status(200).json({
      success: true,
      message: "Scan flagged successfully.",
      scan: updatedScan,
    });

  } catch (error) {
    console.error("MODERATOR FLAG SCAN ERROR:", error);
    if (error.name === "CastError") {
      return res.status(400).json({ success: false, message: "Invalid scan ID." });
    }
    return res.status(500).json({ success: false, message: "Failed to flag scan.", details: error.message });
  }
});

// =====================================================
// GET FLAGGED THREATS
// GET /api/moderator/flags
// =====================================================

router.get("/flags", authMiddleware, moderatorOnly, async (req, res) => {
  try {
    const flaggedScans = await Scan.find({ isFlagged: true })
      .populate("user", "name email role")
      .populate("flaggedBy", "name email role")
      .sort({ flaggedAt: -1 })
      .lean();

    return res.status(200).json({ success: true, count: flaggedScans.length, flags: flaggedScans });
  } catch (error) {
    console.error("GET FLAGGED THREATS ERROR:", error);
    return res.status(500).json({ success: false, message: "Could not load flagged threats.", details: error.message });
  }
});

module.exports = router;
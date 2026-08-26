const express = require("express");

const Scan = require("../models/Scan");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();


// =====================================================
// MODERATOR ONLY MIDDLEWARE
// =====================================================

const moderatorOrAdmin = (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        message: "Authentication required.",
      });
    }

    const role = String(req.user.role || "")
      .trim()
      .toLowerCase();

    if (role !== "moderator" && role !== "admin") {
      return res.status(403).json({
        message:
          "Only Moderator or Admin can perform this action.",
      });
    }

    next();

  } catch (error) {
    console.error(
      "MODERATOR AUTH ERROR:",
      error.message
    );

    return res.status(500).json({
      message:
        "Moderator authorization failed.",
    });
  }
};


// =====================================================
// GET: USER KI HISTORY
// GET /api/scans
// =====================================================

router.get(
  "/",
  authMiddleware,
  async (req, res) => {
    try {

      const scans = await Scan.find({
        user: req.user.id,
      }).sort({
        createdAt: -1,
      });

      return res.status(200).json(scans);

    } catch (error) {

      console.error(
        "GET HISTORY ERROR:",
        error.message
      );

      return res.status(500).json({
        message:
          "Failed to load history.",
      });
    }
  }
);


// =====================================================
// 🚩 FLAG SCAN AS THREAT
//
// PATCH /api/scans/:id/flag
//
// Moderator + Admin can flag a scan.
// =====================================================

router.patch(
  "/:id/flag",
  authMiddleware,
  moderatorOrAdmin,
  async (req, res) => {
    try {

      const scanId = req.params.id;

      const reason =
        String(
          req.body?.reason ||
          "Flagged as a potential threat by moderator."
        ).trim();

      // -------------------------------------------------
      // FIND SCAN
      // -------------------------------------------------

      const scan =
        await Scan.findById(scanId);

      if (!scan) {
        return res.status(404).json({
          message:
            "Scan not found.",
        });
      }

      // -------------------------------------------------
      // FLAG SCAN
      // -------------------------------------------------

      scan.isFlagged = true;

      scan.flaggedBy =
        req.user.id;

      scan.flaggedByRole =
        String(
          req.user.role
        ).trim();

      scan.flagReason =
        reason;

      scan.flaggedAt =
        new Date();

      await scan.save();

      // -------------------------------------------------
      // SUCCESS RESPONSE
      // -------------------------------------------------

      return res.status(200).json({
        success: true,

        message:
          "Scan flagged successfully.",

        scan: {
          id: scan._id,
          isFlagged:
            scan.isFlagged,

          flaggedBy:
            scan.flaggedBy,

          flaggedByRole:
            scan.flaggedByRole,

          flagReason:
            scan.flagReason,

          flaggedAt:
            scan.flaggedAt,
        },
      });

    } catch (error) {

      console.error(
        "FLAG SCAN ERROR:",
        error.message
      );

      // Invalid MongoDB ID
      if (
        error.name ===
        "CastError"
      ) {
        return res.status(400).json({
          message:
            "Invalid scan ID.",
        });
      }

      return res.status(500).json({
        message:
          "Failed to flag scan.",
        details:
          error.message,
      });
    }
  }
);


// =====================================================
// 🚩 UNFLAG SCAN
//
// PATCH /api/scans/:id/unflag
//
// Moderator + Admin can remove their flag.
// =====================================================

router.patch(
  "/:id/unflag",
  authMiddleware,
  moderatorOrAdmin,
  async (req, res) => {
    try {

      const scanId =
        req.params.id;

      const scan =
        await Scan.findById(
          scanId
        );

      if (!scan) {
        return res.status(404).json({
          message:
            "Scan not found.",
        });
      }

      // -------------------------------------------------
      // REMOVE FLAG
      // -------------------------------------------------

      scan.isFlagged = false;

      scan.flaggedBy = null;

      scan.flaggedByRole = null;

      scan.flagReason = "";

      scan.flaggedAt = null;

      await scan.save();

      return res.status(200).json({
        success: true,

        message:
          "Scan flag removed successfully.",

        scan,
      });

    } catch (error) {

      console.error(
        "UNFLAG SCAN ERROR:",
        error.message
      );

      if (
        error.name ===
        "CastError"
      ) {
        return res.status(400).json({
          message:
            "Invalid scan ID.",
        });
      }

      return res.status(500).json({
        message:
          "Failed to remove scan flag.",
      });
    }
  }
);


// =====================================================
// DELETE: USER APNI HISTORY DELETE KARE
// DELETE /api/scans/:id
// =====================================================

router.delete(
  "/:id",
  authMiddleware,
  async (req, res) => {
    try {

      const scanId =
        req.params.id;

      // -------------------------------------------------
      // USER KA APNA SCAN HI DELETE HOGA
      // -------------------------------------------------

      const deletedScan =
        await Scan.findOneAndDelete({
          _id: scanId,

          // IMPORTANT SECURITY
          // Sirf current logged-in user ka scan
          user: req.user.id,
        });

      // -------------------------------------------------
      // SCAN NOT FOUND / DOOSRE USER KA SCAN
      // -------------------------------------------------

      if (!deletedScan) {
        return res.status(404).json({
          message:
            "Scan not found or you are not authorized to delete it.",
        });
      }

      // -------------------------------------------------
      // SUCCESS
      // -------------------------------------------------

      return res.status(200).json({
        success: true,

        message:
          "Scan deleted successfully.",
      });

    } catch (error) {

      console.error(
        "DELETE SCAN ERROR:",
        error.message
      );

      // Invalid MongoDB ID
      if (
        error.name ===
        "CastError"
      ) {
        return res.status(400).json({
          message:
            "Invalid scan ID.",
        });
      }

      return res.status(500).json({
        message:
          "Failed to delete scan.",
      });
    }
  }
);


module.exports = router;
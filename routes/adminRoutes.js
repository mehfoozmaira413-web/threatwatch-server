const express = require("express");
const { ObjectId } = require("mongodb");

const User = require("../models/User");
const Scan = require("../models/Scan");
const authMiddleware = require("../middleware/authMiddleware");
const Permission = require("../models/Permission");

const router = express.Router();

// =====================================================
// ADMIN ONLY MIDDLEWARE
// =====================================================
const adminOnly = (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required." });
    }
    if (req.user.role !== "Admin") {
      return res.status(403).json({ message: "Admin access required." });
    }
    next();
  } catch (error) {
    console.error("ADMIN AUTH ERROR:", error.message);
    return res.status(500).json({ message: "Admin authorization failed." });
  }
};

// =====================================================
// ADMIN DASHBOARD STATS
// GET /api/admin/stats
// =====================================================
router.get("/stats", authMiddleware, adminOnly, async (req, res) => {
  try {
    const [
      totalUsers,
      totalScans,
      totalUrlScans,
      totalTextScans,
      totalImageScans,
      totalThreats,
      totalSafe,
      totalUncertain,
      totalAdmins,
      totalModerators,
      totalNormalUsers,
    ] = await Promise.all([
      User.countDocuments(),
      Scan.countDocuments(),
      Scan.countDocuments({ scanType: "URL" }),
      Scan.countDocuments({ scanType: "TEXT" }),
      Scan.countDocuments({ scanType: "IMAGE" }),
      Scan.countDocuments({ verdict: "THREAT" }),
      Scan.countDocuments({ isSafe: true }),
      Scan.countDocuments({ verdict: "UNCERTAIN" }),
      User.countDocuments({ role: "Admin" }),
      User.countDocuments({ role: "Moderator" }),
      User.countDocuments({ role: "User" }),
    ]);

    return res.status(200).json({
      success: true,
      users: { total: totalUsers, admins: totalAdmins, moderators: totalModerators, users: totalNormalUsers },
      scans: { total: totalScans, url: totalUrlScans, text: totalTextScans, image: totalImageScans },
      results: { threats: totalThreats, safe: totalSafe, uncertain: totalUncertain },
    });
  } catch (error) {
    console.error("ADMIN STATS ERROR:", error.message);
    return res.status(500).json({ message: "Failed to load admin statistics.", details: error.message });
  }
});

// =====================================================
// GET ALL USERS
// GET /api/admin/users
// =====================================================
router.get("/users", authMiddleware, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    return res.status(200).json({ success: true, count: users.length, users });
  } catch (error) {
    console.error("ADMIN USERS ERROR:", error.message);
    return res.status(500).json({ message: "Failed to load users.", details: error.message });
  }
});

// =====================================================
// GET ALL SCANS
// GET /api/admin/scans
// =====================================================
router.get("/scans", authMiddleware, adminOnly, async (req, res) => {
  try {
    const scans = await Scan.find().populate("user", "name email role").sort({ createdAt: -1 });
    return res.status(200).json({ success: true, count: scans.length, scans });
  } catch (error) {
    console.error("ADMIN SCANS ERROR:", error.message);
    return res.status(500).json({ message: "Failed to load scans.", details: error.message });
  }
});

// =====================================================
// GET RECENT SCANS
// GET /api/admin/recent-scans
// =====================================================
router.get("/recent-scans", authMiddleware, adminOnly, async (req, res) => {
  try {
    const scans = await Scan.find().populate("user", "name email role").sort({ createdAt: -1 }).limit(10);
    return res.status(200).json({ success: true, scans });
  } catch (error) {
    console.error("RECENT SCANS ERROR:", error.message);
    return res.status(500).json({ message: "Failed to load recent scans.", details: error.message });
  }
});

// =====================================================
// UPDATE USER ROLE
// PATCH /api/admin/users/:id/role
// =====================================================
router.patch("/users/:id/role", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { role } = req.body;
    const allowedRoles = ["User", "Moderator", "Admin"];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role. Role must be User, Moderator, or Admin." });
    }

    const user = await User.findById(req.params.id);
    if (!user) { return res.status(404).json({ message: "User not found." }); }

    if (user._id.toString() === req.user.id) {
      return res.status(400).json({ message: "You cannot change your own admin role." });
    }

    user.role = role;
    await user.save();

    return res.status(200).json({ success: true, message: "User role updated successfully.", user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    console.error("UPDATE ROLE ERROR:", error.message);
    return res.status(500).json({ message: "Failed to update user role.", details: error.message });
  }
});

// =====================================================
// DELETE USER + USKI SAARI HISTORY
// DELETE /api/admin/users/:id
// =====================================================
router.delete("/users/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    if (req.user.id === req.params.id) {
      return res.status(400).json({ message: "You cannot delete your own admin account." });
    }

    const user = await User.findById(req.params.id);
    if (!user) { return res.status(404).json({ message: "User not found." }); }

    await Scan.deleteMany({ user: req.params.id });
    await User.findByIdAndDelete(req.params.id);

    return res.status(200).json({ success: true, message: "User and all scans deleted successfully." });
  } catch (error) {
    console.error("DELETE USER ERROR:", error.message);
    return res.status(500).json({ message: "Failed to delete user.", details: error.message });
  }
});

// =====================================================
// DELETE ANY SCAN
// DELETE /api/admin/scans/:id
// =====================================================
router.delete("/scans/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await Scan.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Scan not found." });
    }
    return res.status(200).json({ success: true, message: "Scan deleted successfully." });
  } catch (error) {
    console.error("DELETE SCAN ERROR:", error.message);
    return res.status(500).json({ message: "Failed to delete scan.", details: error.message });
  }
});

// =====================================================
// FLAGGED THREATS BY MODERATOR
// GET /api/admin/flags
// =====================================================
router.get("/flags", authMiddleware, adminOnly, async (req, res) => {
  try {
    const flaggedScans = await Scan.find({ isFlagged: true })
      .populate("user", "name email role")
      .populate("flaggedBy", "name email role")
      .sort({ flaggedAt: -1 })
      .lean();

    return res.status(200).json({ success: true, count: flaggedScans.length, flags: flaggedScans });
  } catch (error) {
    console.error("ADMIN FLAGGED SCANS ERROR:", error);
    return res.status(500).json({ success: false, message: "Could not load flagged threats.", details: error.message });
  }
});

// =====================================================
// GET ALL PERMISSIONS 
// GET /api/admin/permissions
// =====================================================
router.get("/permissions", authMiddleware, adminOnly, async (req, res) => {
  try {
    let permissions = await Permission.find();

    // Agar DB khali hai to default bana do - 4no fields k sath
    if (permissions.length === 0) {
      permissions = [
        { role: 'Admin', permissions: { canScan: true, canViewHistory: true, canFlag: true, canDelete: true } },
        { role: 'Moderator', permissions: { canScan: true, canViewHistory: true, canFlag: true, canDelete: false } },
        { role: 'User', permissions: { canScan: true, canViewHistory: true, canFlag: false, canDelete: false } }
      ];
      await Permission.insertMany(permissions);
    }

    return res.status(200).json({ success: true, permissions });
  } catch (error) {
    console.error("PERMISSIONS GET ERROR:", error);
    return res.status(500).json({ message: "Failed to load permissions.", details: error.message });
  }
});

// =====================================================
// GET MY PERMISSIONS
// GET /api/admin/permissions/me
// Admin, Moderator and User can read their own permissions
// =====================================================

router.get("/permissions/me", authMiddleware, async (req, res) => {
  try {
    const role = String(req.user?.role || "").trim();

    if (!role) {
      return res.status(401).json({
        success: false,
        message: "User role not found.",
      });
    }

    let permission = await Permission.findOne({ role });

    // If permission record doesn't exist, create default
    if (!permission) {
      const defaults = {
        Admin: {
          canScan: true,
          canViewHistory: true,
          canFlag: true,
          canDelete: true,
        },

        Moderator: {
          canScan: true,
          canViewHistory: true,
          canFlag: true,
          canDelete: false,
        },

        User: {
          canScan: true,
          canViewHistory: true,
          canFlag: false,
          canDelete: false,
        },
      };

      permission = await Permission.create({
        role,
        permissions: defaults[role] || {
          canScan: true,
          canViewHistory: true,
          canFlag: false,
          canDelete: false,
        },
      });
    }

    return res.status(200).json({
      success: true,
      role,
      permissions: permission.permissions,
    });

  } catch (error) {
    console.error("MY PERMISSIONS ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to load your permissions.",
      details: error.message,
    });
  }
});

// =====================================================
// UPDATE PERMISSIONS
// PUT /api/admin/permissions
// =====================================================
router.put("/permissions", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { permissions } = req.body;

    await Permission.deleteMany({});
    await Permission.insertMany(permissions);

    return res.status(200).json({ success: true, message: "Permissions updated successfully." });
  } catch (error) {
    console.error("PERMISSIONS UPDATE ERROR:", error);
    return res.status(500).json({ message: "Failed to update permissions.", details: error.message });
  }
});

module.exports = router;
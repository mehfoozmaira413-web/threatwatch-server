const mongoose = require("mongoose");

const permissionSchema = new mongoose.Schema({
  role: { 
    type: String, 
    enum: ["Admin", "User", "Moderator"], // 3no roles
    required: true, 
    unique: true 
  },
  permissions: {
    canScan: { type: Boolean, default: true },
    canViewHistory: { type: Boolean, default: true },
    canFlag: { type: Boolean, default: false },
    canDelete: { type: Boolean, default: false },
  }
}, { timestamps: true });

module.exports = mongoose.model("Permission", permissionSchema);
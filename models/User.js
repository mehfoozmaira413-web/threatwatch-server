const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// =====================================================
// USER SCHEMA
// =====================================================

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },

    role: {
      type: String,
      enum: ["User", "Moderator", "Admin"],
      default: "User",
    },
  },
  {
    timestamps: true,
  }
);

// =====================================================
// HASH PASSWORD BEFORE SAVE
// =====================================================

userSchema.pre("save", async function () {
  // If password has not changed, don't hash it again
  if (!this.isModified("password")) {
    return;
  }

  // Hash password
  this.password = await bcrypt.hash(
    this.password,
    10
  );
});

// =====================================================
// COMPARE PASSWORD
// =====================================================

userSchema.methods.comparePassword = async function (
  enteredPassword
) {
  return bcrypt.compare(
    enteredPassword,
    this.password
  );
};

// =====================================================
// USER MODEL
// =====================================================

const User = mongoose.model(
  "User",
  userSchema
);

module.exports = User;
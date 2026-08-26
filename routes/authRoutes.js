const express = require("express");
const router = express.Router();

const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// =====================================================
// HELPER — CREATE JWT TOKEN
// =====================================================

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "1d",
    }
  );
}

// =====================================================
// REGISTER
// POST /api/auth/register
// =====================================================

router.post("/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
    } = req.body;

    // -------------------------------------------------
    // VALIDATION
    // -------------------------------------------------

    if (
      !name ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        message:
          "Name, email and password are required.",
      });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email)
      .trim()
      .toLowerCase();

    // -------------------------------------------------
    // PASSWORD VALIDATION
    // -------------------------------------------------

    if (String(password).length < 6) {
      return res.status(400).json({
        message:
          "Password must be at least 6 characters.",
      });
    }

    // -------------------------------------------------
    // CHECK EXISTING USER
    // -------------------------------------------------

    const existingUser =
      await User.findOne({
        email: cleanEmail,
      });

    if (existingUser) {
      return res.status(409).json({
        message:
          "Email is already registered.",
      });
    }

    // -------------------------------------------------
    // CREATE USER
    // User model will hash password automatically
    // -------------------------------------------------

    const user =
      await User.create({
        name: cleanName,
        email: cleanEmail,
        password: password,
        role: "User",
      });

    // -------------------------------------------------
    // CREATE TOKEN
    // -------------------------------------------------

    const token =
      createToken(user);

    // -------------------------------------------------
    // REGISTER RESPONSE
    // -------------------------------------------------

    return res.status(201).json({
      message:
        "Account created successfully.",

      token,

      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    // Duplicate email protection
    if (error.code === 11000) {
      return res.status(409).json({
        message:
          "Email is already registered.",
      });
    }

    return res.status(500).json({
      message:
        "Registration failed.",
      details:
        error.message,
    });
  }
});

// =====================================================
// LOGIN
// POST /api/auth/login
// =====================================================

router.post("/login", async (req, res) => {
  try {
    const {
      email,
      password,
    } = req.body;

    // -------------------------------------------------
    // VALIDATION
    // -------------------------------------------------

    if (
      !email ||
      !password
    ) {
      return res.status(400).json({
        message:
          "Email and password are required.",
      });
    }

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    // -------------------------------------------------
    // FIND USER
    // -------------------------------------------------

    const user =
      await User.findOne({
        email: cleanEmail,
      });

    if (!user) {
      return res.status(401).json({
        message:
          "Invalid email or password.",
      });
    }

    // -------------------------------------------------
    // COMPARE PASSWORD
    // -------------------------------------------------

    const isMatch =
      await bcrypt.compare(
        String(password),
        user.password
      );

    if (!isMatch) {
      return res.status(401).json({
        message:
          "Invalid email or password.",
      });
    }

    // -------------------------------------------------
    // CREATE JWT
    // -------------------------------------------------

    const token =
      createToken(user);

    // -------------------------------------------------
    // LOGIN RESPONSE
    // -------------------------------------------------

    return res.status(200).json({
      message:
        "Login successful.",

      token,

      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      message:
        "Login failed.",
      details:
        error.message,
    });
  }
});

// =====================================================
// EXPORT
// =====================================================

module.exports = router;
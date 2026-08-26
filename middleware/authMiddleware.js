const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    console.log(
      "AUTH HEADER:",
      authHeader ? "RECEIVED" : "MISSING"
    );

    if (!authHeader) {
      return res.status(401).json({
        message: "Authentication required",
      });
    }

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Invalid authorization format",
      });
    }

    const token = authHeader.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        message: "Authentication token missing",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing from .env");

      return res.status(500).json({
        message: "JWT configuration error",
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    console.log("TOKEN DECODED:", decoded);

    req.user = {
      id: decoded.id,
      role: decoded.role,
    };

    next();

  } catch (error) {
    console.error(
      "AUTH MIDDLEWARE ERROR:",
      error.message
    );

    return res.status(401).json({
      message: "Invalid or expired authentication token",
    });
  }
};

module.exports = authMiddleware;
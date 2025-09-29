const jwt = require("jsonwebtoken");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;

// Token blacklist for logout functionality
const tokenBlacklist = new Set();

// Add token to blacklist
const blacklistToken = (token) => {
  tokenBlacklist.add(token);

  // Auto-cleanup expired tokens from blacklist every hour
  setTimeout(() => {
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        tokenBlacklist.delete(token);
      }
    }
  }, 60 * 60 * 1000); // 1 hour
};

// Check if token is blacklisted
const isTokenBlacklisted = (token) => {
  return tokenBlacklist.has(token);
};

// Authentication middleware
const authenticate = (req, res, next) => {
  try {
    const authHeader = req.get("authorization");

    if (!authHeader) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({ error: "Invalid authorization header format" });
    }

    // Check if token is blacklisted
    if (isTokenBlacklisted(token)) {
      return res.status(401).json({ error: "Token has been invalidated" });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      req.token = token;
      next();
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token has expired" });
      } else if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ error: "Invalid token" });
      } else {
        return res.status(401).json({ error: "Authentication failed" });
      }
    }
  } catch (error) {
    console.error("Authentication middleware error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Session validation middleware (checks if session is still active)
const validateSession = (activeSessions) => {
  return (req, res, next) => {
    if (!req.user || !req.user.sessionId) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const session = activeSessions.get(req.user.sessionId);

    if (!session) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }

    // Update session activity
    session.lastActivity = new Date().toISOString();

    next();
  };
};

// Rate limiting by user ID
const userRateLimit = (maxRequests, windowMs) => {
  const userRequests = new Map();

  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userId = req.user.userId;
    const now = Date.now();

    if (!userRequests.has(userId)) {
      userRequests.set(userId, []);
    }

    const requests = userRequests.get(userId);

    // Remove old requests outside the window
    const validRequests = requests.filter(
      (timestamp) => now - timestamp < windowMs
    );
    userRequests.set(userId, validRequests);

    if (validRequests.length >= maxRequests) {
      return res.status(429).json({
        error: "Too many requests from this user",
        retryAfter: Math.round(windowMs / 1000)
      });
    }

    // Add current request
    validRequests.push(now);
    next();
  };
};

// Combined authentication middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  const adminKey = req.headers["x-admin-key"];

  // Block any admin key attempts (admin bypass disabled)
  if (adminKey) {
    return res.status(403).json({
      success: false,
      message: "Admin bypass disabled for security"
    });
  }

  // Require valid JWT token for ALL requests
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access token required"
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid token"
    });
  }
};

module.exports = {
  authenticate,
  validateSession,
  userRateLimit,
  blacklistToken,
  isTokenBlacklisted,
  authMiddleware
};

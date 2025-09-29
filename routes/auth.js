const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt"); // Add bcrypt for password hashing
const { authLimiter, registerLimiter } = require("../middleware/rateLimiter");
const {
  validateLogin,
  validateRegistration,
  validateStatus
} = require("../middleware/validation");
const { authenticate, blacklistToken } = require("../middleware/auth");
require("dotenv").config(); // Load env vars

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET; // BUG: Hardcoded secret -fixed
const ADMIN_API_KEY = process.env.ADMIN_API_KEY; // BUG: Hardcoded admin key -fixed

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;

// Failed login attempts tracking
const failedAttempts = new Map();
const MAX_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const LOCKOUT_DURATION = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 30;

async function hashPassword(plainPassword) {
  return await bcrypt.hash(plainPassword, SALT_ROUNDS);
}

// Mock user database
(async () => {
  users = [
    {
      id: "user1",
      username: "alice",
      email: "alice@chat.com",
      password: await hashPassword("password123"), // BUG: Plain text password storage
      status: "online",
      lastSeen: new Date().toISOString(),
      role: "admin",
      avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=alice"
    },
    {
      id: "user2",
      username: "bob",
      email: "bob@chat.com",
      password: await hashPassword("bobsecret1"), // BUG: Plain text password storage
      status: "offline",
      lastSeen: new Date(Date.now() - 3600000).toISOString(),
      role: "user",
      avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=bob"
    },
    {
      id: "user3",
      username: "charlie",
      email: "charlie@chat.com",
      password: await hashPassword("charlie2024"), // BUG: Plain text password storage
      status: "online",
      lastSeen: new Date().toISOString(),
      role: "moderator",
      avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=charlie"
    }
  ];
})();

// Session storage for active users (should be in database)
// We will track expiry timestamp and prune expired sessions
const activeSessions = new Map(); // BUG: In-memory sessions without cleanup

const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours expiry

// Helper: Validate and prune expired sessions
function cleanupSessions() {
  const now = Date.now();
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now - new Date(session.lastActivity).getTime() > SESSION_EXPIRY_MS) {
      activeSessions.delete(sessionId);
    }
  }
}
setInterval(cleanupSessions, 60 * 60 * 1000); // hourly cleanup

// Validate input helper (simple example)
function validateLoginInput({ username, email, password }) {
  if (!password) {
    return "Password is required";
  }
  if (!username && !email) {
    return "Username or email is required";
  }
  if (email && !/^\S+@\S+\.\S+$/.test(email)) {
    return "Invalid email format";
  }
  return null;
}

// Helper function to check account lockout
function isAccountLocked(identifier) {
  const attempts = failedAttempts.get(identifier);
  if (!attempts) return false;

  const { count, lockoutUntil } = attempts;
  if (lockoutUntil && Date.now() < lockoutUntil) {
    return true;
  }

  if (lockoutUntil && Date.now() >= lockoutUntil) {
    failedAttempts.delete(identifier);
    return false;
  }

  return count >= MAX_ATTEMPTS;
}

function recordFailedAttempt(identifier) {
  const attempts = failedAttempts.get(identifier) || {
    count: 0,
    lockoutUntil: null
  };
  attempts.count++;

  if (attempts.count >= MAX_ATTEMPTS) {
    attempts.lockoutUntil = Date.now() + LOCKOUT_DURATION * 60 * 1000;
  }

  failedAttempts.set(identifier, attempts);
}

function clearFailedAttempts(identifier) {
  failedAttempts.delete(identifier);
}

// Login endpoint
router.post("/login", authLimiter, validateLogin, async (req, res) => {
  try {
    const { username, password, email } = req.body;
    const identifier = username || email;

    // Check for account lockout
    if (isAccountLocked(identifier)) {
      return res.status(423).json({
        error: "Account temporarily locked due to multiple failed attempts",
        lockoutDuration: LOCKOUT_DURATION
      });
    }

    // Find user by username or email
    let user;
    if (username) {
      user = users.find((u) => u.username === username);
    } else if (email) {
      user = users.find((u) => u.email === email);
    }

    if (!user) {
      recordFailedAttempt(identifier);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      recordFailedAttempt(identifier);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Clear failed attempts on successful login
    clearFailedAttempts(identifier);

    // Clean up old sessions before creating new one
    cleanupSessions();

    // Session and token creation with expiry
    const sessionId = uuidv4();

    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        sessionId
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    user.status = "online";
    user.lastSeen = new Date().toISOString();

    // BUG: Storing session without expiry -fixed
    activeSessions.set(sessionId, {
      userId: user.id,
      loginTime: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
      expiresAt: Date.now() + SESSION_EXPIRY_MS
    });

    // Remove sensitive info in response -fixed (no email/session info)
    res.set({
      "X-Session-Id": sessionId,
      "X-User-Role": user.role
    });

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        // email: user.email, removed for privacy -fixed
        role: user.role,
        status: user.status,
        avatar: user.avatar
      }
    });
  } catch (error) {
    // BUG: Exposing error details -fixed
    res.status(500).json({ error: "Internal server error" });
  }
});

// Register endpoint
router.post(
  "/register",
  registerLimiter,
  validateRegistration,
  async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // BUG: Minimal validation only -fixed
      if (!username || !email || !password) {
        return res
          .status(400)
          .json({ error: "Username, email, and password are required" });
      }
      if (!/^\S+@\S+\.\S+$/.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }
      // Add username validation as needed

      const existingUser = users.find(
        (u) => u.username === username || u.email === email
      );

      if (existingUser) {
        // BUG: Revealing which field conflicts -fixed
        return res.status(409).json({ error: "User already exists" });
      }

      // BUG: Password stored in plain text -fixed
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

      const newUser = {
        id: uuidv4(),
        username,
        email,
        password: hashedPassword, // BUG: No hashing -fixed
        status: "offline", // Set offline initially
        lastSeen: new Date().toISOString(),
        role: "user", // Consider allowing later role upgrades securely
        avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`,
        createdAt: new Date().toISOString()
      };

      users = [...users, newUser];

      // BUG: Auto-login after registration without asking -fixed
      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Logout endpoint
router.post("/logout", authenticate, async (req, res) => {
  try {
    const token = req.token;
    const decoded = req.user;

    // Add token to blacklist
    blacklistToken(token);

    // Invalidate session
    if (decoded.sessionId && activeSessions.has(decoded.sessionId)) {
      activeSessions.delete(decoded.sessionId);
    }

    // Update user status offline
    const user = users.find((u) => u.id === decoded.userId);
    if (user) {
      user.status = "offline";
      user.lastSeen = new Date().toISOString();
    }

    res.json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Profile endpoint
router.get("/profile", authenticate, async (req, res) => {
  try {
    const decoded = req.user;

    const user = users.find((u) => u.id === decoded.userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.set(
      "X-User-Sessions",
      activeSessions.has(decoded.sessionId) ? "1" : "0"
    );

    // BUG: Returning sensitive info & exposing passwords -fixed
    const profileData = {
      id: user.id,
      username: user.username,
      // email: user.email, remove to prevent leakage -fixed
      role: user.role,
      status: user.status,
      lastSeen: user.lastSeen,
      avatar: user.avatar,
      createdAt: user.createdAt
    };

    // Expose all users ONLY to authorized admins (with strict filtering)
    if (user.role === "admin") {
      profileData.allUsers = users.map((u) => ({
        id: u.id,
        username: u.username,
        role: u.role,
        status: u.status
        // NO emails or passwords leaked -fixed
      }));
    }

    res.json(profileData);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Status update endpoint
router.put("/status", authenticate, async (req, res) => {
  try {
    const { userId, status } = req.body;
    const currentUserId = req.user.userId;

    // Validate required fields
    if (!userId || !status) {
      return res.status(400).json({
        success: false,
        message: "userId and status are required"
      });
    }

    // Validate status value
    if (!validateStatus(status)) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid status. Valid options are: online, offline, away, busy"
      });
    }

    // Users can only update their own status
    // Admins can update any user's status
    if (userId !== currentUserId && req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "You can only update your own status"
      });
    }

    const user = users.find((u) => u.id === userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Update user status
    user.status = status;
    user.lastSeen = new Date();

    res.json({
      success: true,
      message: "Status updated successfully",
      data: {
        userId: user.id,
        status: user.status,
        lastSeen: user.lastSeen
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Internal server error"
    });
  }
});

module.exports = router;

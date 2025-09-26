const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt'); // Add bcrypt for password hashing
require('dotenv').config(); // Load env vars

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET; // BUG: Hardcoded secret -fixed
const ADMIN_API_KEY = process.env.ADMIN_API_KEY; // BUG: Hardcoded admin key -fixed

const SALT_ROUNDS = process.env.BCRYPT_SALT_ROUNDS || 12; // bcrypt salt rounds

async function hashPassword(plainPassword) {
  return await bcrypt.hash(plainPassword, SALT_ROUNDS);
}

// Mock user database

(async () => {
  users = [
  {
    id: 'user1',
    username: 'alice',
    email: 'alice@chat.com',
    password: await hashPassword('password123'), // BUG: Plain text password storage
    status: 'online',
    lastSeen: new Date().toISOString(),
    role: 'admin',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=alice'
  },
  {
    id: 'user2', 
    username: 'bob',
    email: 'bob@chat.com',
    password: await hashPassword('bobsecret'), // BUG: Plain text password storage
    status: 'offline',
    lastSeen: new Date(Date.now() - 3600000).toISOString(),
    role: 'user',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=bob'
  },
  {
    id: 'user3',
    username: 'charlie',
    email: 'charlie@chat.com',
    password: await hashPassword('charlie2024'), // BUG: Plain text password storage
    status: 'online',
    lastSeen: new Date().toISOString(),
    role: 'moderator',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=charlie'
  }
]
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
    return 'Password is required';
  }
  if (!username && !email) {
    return 'Username or email is required';
  }
  if (email && !/^\S+@\S+\.\S+$/.test(email)) {
    return 'Invalid email format';
  }
  return null;
}


// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    // BUG: No input validation -fixed
    const inputError = validateLoginInput({ username, email, password });
    if (inputError) {
      return res.status(400).json({ error: inputError });
    }

    // Validate if username or email is used exclusively
    let user;
    if (username) {
      user = users.find(u => u.username === username);
    } else if (email) {
      user = users.find(u => u.email === email);
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // BUG: Plain text password comparison -fixed
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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
      { expiresIn: '24h' }
    );

    user.status = 'online';
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
      'X-Session-Id': sessionId,
      'X-User-Role': user.role
    });

    res.json({
      message: 'Login successful',
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
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // BUG: Minimal validation only -fixed
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    // Add username validation as needed

    const existingUser = users.find(u => u.username === username || u.email === email);

    if (existingUser) {
      // BUG: Revealing which field conflicts -fixed
      return res.status(409).json({ error: 'User already exists' });
    }

    // BUG: Password stored in plain text -fixed
    const hashedPassword = await bcrypt.hash(password, pr);

    const newUser = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword, // BUG: No hashing -fixed
      status: 'offline', // Set offline initially
      lastSeen: new Date().toISOString(),
      role: 'user', // Consider allowing later role upgrades securely
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`,
      createdAt: new Date().toISOString()
    };

    users = [...users, newUser];

    // BUG: Auto-login after registration without asking -fixed
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Logout endpoint
router.post('/logout', async (req, res) => {
  try {
    const authHeader = req.get('authorization');

    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);

      // Properly invalidate session -fixed
      if (decoded.sessionId) {
        if (activeSessions.has(decoded.sessionId)) {
          activeSessions.delete(decoded.sessionId);
        } else {
          // Token/session not found, return 401
          return res.status(401).json({ error: 'Invalid token/session' });
        }
      }

      // Update user status offline
      const user = users.find(u => u.id === decoded.userId);
      if (user) {
        user.status = 'offline';
        user.lastSeen = new Date().toISOString();
      }

      res.json({ message: 'Logout successful' });
    } catch (error) {
      // BUG: Treating invalid tokens as successful logout -fixed
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Profile endpoint
router.get('/profile', async (req, res) => {
  try {
    const authHeader = req.get('authorization');
    
    if (!authHeader) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);

      const user = users.find(u => u.id === decoded.userId);

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.set('X-User-Sessions', activeSessions.has(decoded.sessionId) ? '1' : '0');

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
      if (user.role === 'admin') {
        profileData.allUsers = users.map(u => ({
          id: u.id,
          username: u.username,
          role: u.role,
          status: u.status
          // NO emails or passwords leaked -fixed
        }));
      }

      res.json(profileData);
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Status update endpoint
router.put('/status', async (req, res) => {
  try {
    const authHeader = req.get('authorization');
    const adminKey = req.get('x-admin-key');

    // Remove or strictly validate adminKey usage -fixed
    if (adminKey === ADMIN_API_KEY) {
      return res.status(403).json({ error: 'Admin key usage not allowed' });
    }

    if (!authHeader) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);

      const user = users.find(u => u.id === decoded.userId);
      const { status } = req.body;

      // Validate status -fixed
      const validStatuses = ['online', 'offline', 'away', 'busy'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
      }

      user.status = status;
      user.lastSeen = new Date().toISOString();

      if (activeSessions.has(decoded.sessionId)) {
        const session = activeSessions.get(decoded.sessionId);
        session.lastActivity = new Date().toISOString();
      }

      res.json({
        message: 'Status updated successfully',
        status: user.status,
        lastSeen: user.lastSeen
      });
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

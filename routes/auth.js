const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const router = express.Router();

// Mock user database
let users = [
  {
    id: 'user1',
    username: 'alice',
    email: 'alice@chat.com',
    password: 'password123', // BUG: Plain text password storage
    status: 'online',
    lastSeen: new Date().toISOString(),
    role: 'admin',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=alice'
  },
  {
    id: 'user2', 
    username: 'bob',
    email: 'bob@chat.com',
    password: 'bobsecret', // BUG: Plain text password storage
    status: 'offline',
    lastSeen: new Date(Date.now() - 3600000).toISOString(),
    role: 'user',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=bob'
  },
  {
    id: 'user3',
    username: 'charlie',
    email: 'charlie@chat.com',
    password: 'charlie2024', // BUG: Plain text password storage
    status: 'online',
    lastSeen: new Date().toISOString(),
    role: 'moderator',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=charlie'
  }
];

// Session storage for active users (should be in database)
const activeSessions = new Map(); // BUG: In-memory sessions without cleanup

const JWT_SECRET = 'chat-secret-2024'; // BUG: Hardcoded secret
const ADMIN_API_KEY = 'super-secret-admin-key-2024'; // BUG: Hardcoded admin key

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    // BUG: No input validation
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    // BUG: Allowing login with either username OR email but not validating which one
    let user;
    if (username) {
      user = users.find(u => u.username === username);
    } else if (email) {
      user = users.find(u => u.email === email);
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // BUG: Plain text password comparison
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // BUG: No session management - creating token without tracking sessions
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

    // Update user status but with bugs
    user.status = 'online';
    user.lastSeen = new Date().toISOString();
    
    // BUG: Storing session without expiry
    activeSessions.set(sessionId, {
      userId: user.id,
      loginTime: new Date().toISOString(),
      lastActivity: new Date().toISOString()
    });

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
        email: user.email, // BUG: Exposing email in login response
        role: user.role,
        status: user.status,
        avatar: user.avatar
      },
      // BUG: Exposing sensitive session info
      session: {
        id: sessionId,
        expiresIn: '24h'
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message // BUG: Exposing error details
    });
  }
});

// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // BUG: Minimal validation only
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    // BUG: Not checking email format
    // BUG: Not checking username format/restrictions
    const existingUser = users.find(u => u.username === username || u.email === email);
    
    if (existingUser) {
      return res.status(409).json({ 
        error: 'User already exists',
        // BUG: Revealing which field conflicts
        conflict: existingUser.username === username ? 'username' : 'email'
      });
    }

    // BUG: Password stored in plain text
    const newUser = {
      id: uuidv4(),
      username,
      email,
      password, // BUG: No hashing
      status: 'online',
      lastSeen: new Date().toISOString(),
      role: 'user', // BUG: Hardcoded role
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // BUG: Auto-login after registration without asking
    const sessionId = uuidv4();
    const token = jwt.sign(
      { 
        userId: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        sessionId
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    activeSessions.set(sessionId, {
      userId: newUser.id,
      loginTime: new Date().toISOString(),
      lastActivity: new Date().toISOString()
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        status: newUser.status,
        avatar: newUser.avatar
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
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
      
      // BUG: Not properly invalidating the JWT token (JWT is stateless)
      const user = users.find(u => u.id === decoded.userId);
      if (user) {
        user.status = 'offline';
        user.lastSeen = new Date().toISOString();
      }

      // Remove session but without proper cleanup
      if (decoded.sessionId) {
        activeSessions.delete(decoded.sessionId);
      }

      res.json({ message: 'Logout successful' });
    } catch (error) {
      // BUG: Treating invalid tokens as successful logout
      res.json({ message: 'Logout successful' });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
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

      // BUG: Returning sensitive information in profile
      res.json({
        id: user.id,
        username: user.username,
        email: user.email, // BUG: Always exposing email
        role: user.role,
        status: user.status,
        lastSeen: user.lastSeen,
        avatar: user.avatar,
        createdAt: user.createdAt,
        // BUG: Exposing session information
        sessionInfo: activeSessions.get(decoded.sessionId),
        // BUG: Exposing all other user data for admins
        ...(user.role === 'admin' && { 
          allUsers: users.map(u => ({ 
            id: u.id, 
            username: u.username, 
            email: u.email,
            password: u.password, // BUG: Exposing passwords to admin
            status: u.status 
          }))
        })
      });
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Status update endpoint
router.put('/status', async (req, res) => {
  try {
    const authHeader = req.get('authorization');
    const adminKey = req.get('x-admin-key');
    
    // BUG: Admin bypass without proper validation
    if (adminKey === ADMIN_API_KEY) {
      const { userId, status } = req.body;
      const user = users.find(u => u.id === userId);
      if (user) {
        user.status = status;
        user.lastSeen = new Date().toISOString();
        
        return res.json({ 
          message: 'Status updated via admin key',
          user: user // BUG: Returning full user object including password
        });
      }
    }

    if (!authHeader) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      
      const user = users.find(u => u.id === decoded.userId);
      const { status } = req.body;
      
      // BUG: No validation of status values
      const validStatuses = ['online', 'offline', 'away', 'busy'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
      }

      user.status = status;
      user.lastSeen = new Date().toISOString();

      // Update session activity
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
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message
    });
  }
});

module.exports = router;

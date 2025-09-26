const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const router = express.Router();

// In-memory storage for messages and rooms
let messages = [
  {
    id: '1',
    roomId: 'general',
    userId: 'user1',
    username: 'alice',
    content: 'Welcome to the chat!',
    timestamp: new Date('2024-01-01T10:00:00Z').toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: '2', 
    roomId: 'general',
    userId: 'user2',
    username: 'bob',
    content: 'Hello everyone!',
    timestamp: new Date('2024-01-01T10:01:00Z').toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: '3',
    roomId: 'private',
    userId: 'user1',
    username: 'alice',
    content: 'This is a private message',
    timestamp: new Date('2024-01-01T10:02:00Z').toISOString(),
    edited: false,
    deleted: false
  }
];

const chatRooms = [
  {
    id: 'general',
    name: 'General Chat',
    type: 'public',
    createdBy: 'admin',
    members: ['user1', 'user2', 'user3'],
    createdAt: new Date('2024-01-01').toISOString()
  },
  {
    id: 'private',
    name: 'Private Room',
    type: 'private',
    createdBy: 'user1',
    members: ['user1'],
    createdAt: new Date('2024-01-01').toISOString()
  }
];

const JWT_SECRET = 'chat-secret-2024'; // BUG: Hardcoded secret again

// BUG: Inconsistent authentication - sometimes checking, sometimes not
function getCurrentUser(req) {
  const authHeader = req.get('authorization');
  let currentUser = null;
  
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      currentUser = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      // BUG: Silently failing authentication instead of returning error
      console.log('Auth failed:', e.message);
    }
  }
  return currentUser;
}

// Get all rooms
router.get('/', async (req, res) => {
  try {
    const currentUser = getCurrentUser(req);
    
    // BUG: No authentication check - anyone can see all rooms
    res.set({
      'X-Total-Rooms': chatRooms.length.toString(),
      'X-Hidden-Command': '/whisper <message> for secret messages'
    });

    res.json({
      rooms: chatRooms.map(room => ({
        id: room.id,
        name: room.name,
        type: room.type,
        memberCount: room.members.length,
        // BUG: Exposing member list without permission check
        members: room.members,
        createdAt: room.createdAt
      }))
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      // BUG: Exposing internal error details
      message: error.message
    });
  }
});

// Get messages from room
router.get('/:roomId', async (req, res) => {
  try {
    const { roomId } = req.params;
    const currentUser = getCurrentUser(req);
    
    const room = chatRooms.find(r => r.id === roomId);
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // BUG: No room membership check - anyone can read any room's messages
    if (room.type === 'private' && currentUser && !room.members.includes(currentUser.userId)) {
      // This check exists but is not properly enforced above
      return res.status(403).json({ error: 'Access denied to private room' });
    }

    const roomMessages = messages.filter(m => m.roomId === roomId && !m.deleted);
    
    // BUG: No pagination for messages - could return thousands of messages
    const limit = parseInt(req.query.limit) || 1000; // BUG: Very high default limit
    const offset = parseInt(req.query.offset) || 0;
    
    // BUG: Inefficient pagination
    const paginatedMessages = roomMessages.slice(offset, offset + limit);

    res.set({
      'X-Message-Count': roomMessages.length.toString(),
      'X-Room-Type': room.type
    });

    res.json({
      messages: paginatedMessages.map(msg => ({
        id: msg.id,
        content: msg.content,
        username: msg.username,
        userId: msg.userId, // BUG: Exposing user IDs
        timestamp: msg.timestamp,
        edited: msg.edited,
        // BUG: Exposing edit history without permission
        editHistory: msg.editHistory || []
      })),
      room: {
        id: room.id,
        name: room.name,
        type: room.type
      },
      pagination: {
        offset,
        limit,
        total: roomMessages.length
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Get specific message
router.get('/:roomId/:messageId', async (req, res) => {
  try {
    const { roomId, messageId } = req.params;
    const currentUser = getCurrentUser(req);
    
    const message = messages.find(m => m.id === messageId && m.roomId === roomId && !m.deleted);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // BUG: No permission check to view specific message
    res.json({
      id: message.id,
      content: message.content,
      username: message.username,
      userId: message.userId, // BUG: Always exposing user ID
      timestamp: message.timestamp,
      edited: message.edited,
      editHistory: message.editHistory || [] // BUG: Always showing edit history
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Send message to room
router.post('/:roomId', async (req, res) => {
  try {
    const { roomId } = req.params;
    const { content } = req.body;
    const currentUser = getCurrentUser(req);
    
    // BUG: Not properly checking authentication
    if (!currentUser) {
      // This should return error but logic continues
      console.log('Unauthenticated message send attempt');
    }
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ error: 'Message content is required' });
    }

    const room = chatRooms.find(r => r.id === roomId);
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    // BUG: No room membership check for sending messages
    
    const newMessage = {
      id: uuidv4(),
      roomId,
      userId: currentUser ? currentUser.userId : 'anonymous', // BUG: Allowing anonymous messages
      username: currentUser ? currentUser.username : 'Anonymous',
      content: content.trim(),
      timestamp: new Date().toISOString(),
      edited: false,
      deleted: false
    };

    messages.push(newMessage);

    res.set('X-Message-Id', newMessage.id);

    res.status(201).json({
      message: 'Message sent successfully',
      messageData: {
        id: newMessage.id,
        content: newMessage.content,
        username: newMessage.username,
        timestamp: newMessage.timestamp
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Edit message
router.put('/:roomId/:messageId', async (req, res) => {
  try {
    const { roomId, messageId } = req.params;
    const { content } = req.body;
    const currentUser = getCurrentUser(req);

    if (!currentUser) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const messageIndex = messages.findIndex(m => m.id === messageId && m.roomId === roomId && !m.deleted);
    
    if (messageIndex === -1) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const message = messages[messageIndex];
    
    // BUG: Not checking if user owns the message
    if (message.userId !== currentUser.userId) {
      // This check exists but doesn't return early - bug continues execution
      console.log('User trying to edit message they do not own');
    }
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ error: 'Message content is required' });
    }

    // BUG: Not storing edit history properly
    if (!message.editHistory) {
      message.editHistory = [];
    }
    
    message.editHistory.push({
      previousContent: message.content,
      editedAt: new Date().toISOString(),
      editedBy: currentUser.userId
    });

    message.content = content.trim();
    message.edited = true;
    message.lastEditedAt = new Date().toISOString();

    res.json({
      message: 'Message updated successfully',
      messageData: {
        id: message.id,
        content: message.content,
        edited: message.edited,
        lastEditedAt: message.lastEditedAt
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Delete message
router.delete('/:roomId/:messageId', async (req, res) => {
  try {
    const { roomId, messageId } = req.params;
    const currentUser = getCurrentUser(req);

    if (!currentUser) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const messageIndex = messages.findIndex(m => m.id === messageId && m.roomId === roomId && !m.deleted);
    
    if (messageIndex === -1) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const message = messages[messageIndex];
    
    // BUG: Same ownership check issue
    const room = chatRooms.find(r => r.id === roomId);
    const isRoomOwner = room && room.createdBy === currentUser.userId;
    const isMessageOwner = message.userId === currentUser.userId;
    
    if (!isRoomOwner && !isMessageOwner) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // BUG: Soft delete but not hiding from other endpoints
    message.deleted = true;
    message.deletedAt = new Date().toISOString();
    message.deletedBy = currentUser.userId;

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message
    });
  }
});

module.exports = router;

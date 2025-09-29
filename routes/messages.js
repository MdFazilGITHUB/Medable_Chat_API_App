const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");

// Import middleware
const { messageLimiter } = require("../middleware/rateLimiter");
const {
  validateMessage,
  validateRoomParams
} = require("../middleware/validation");
const { authenticate } = require("../middleware/auth");

const router = express.Router();

// In-memory storage for messages and rooms
let messages = [
  {
    id: "2e0754a6-d19b-4b45-8a3c-17c8b4d97ba3",
    roomId: "general",
    userId: "user1",
    username: "alice",
    content: "Welcome to the chat!",
    timestamp: new Date("2024-01-01T10:00:00Z").toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: "ee06224a-ba54-4bbc-8117-74079917d9a8",
    roomId: "general",
    userId: "user2",
    username: "bob",
    content: "Hello everyone!",
    timestamp: new Date("2024-01-01T10:01:00Z").toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: "a6d19082-fa4f-4d66-807f-7b4d5b23f04e",
    roomId: "private",
    userId: "user1",
    username: "alice",
    content: "This is a private message",
    timestamp: new Date("2024-01-01T10:02:00Z").toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: "81683f71-adaa-4f38-9516-278f7bf03d86",
    roomId: "general",
    userId: "user3",
    username: "charlie",
    content: "Welcome to the chat!",
    timestamp: new Date("2024-01-01T10:00:00Z").toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: "a8bb517b-631d-4e90-8ebc-34419743dcc6",
    roomId: "general",
    userId: "user3",
    username: "charlie",
    content: "Hello everyone!",
    timestamp: new Date("2024-01-01T10:01:00Z").toISOString(),
    edited: false,
    deleted: false
  },
  {
    id: "7dd3249f-d832-4607-acb0-489abfb178fb",
    roomId: "general",
    userId: "user1",
    username: "alice",
    content: "This is a general message",
    timestamp: new Date("2024-01-01T10:02:00Z").toISOString(),
    edited: false,
    deleted: false
  }
];

const chatRooms = [
  {
    id: "general",
    name: "General Chat",
    type: "public",
    createdBy: "admin",
    members: ["user1", "user2", "user3"],
    createdAt: new Date("2024-01-01").toISOString()
  },
  {
    id: "private",
    name: "Private Room",
    type: "private",
    createdBy: "user1",
    members: ["user1"],
    createdAt: new Date("2024-01-01").toISOString()
  }
];

const JWT_SECRET = process.env.JWT_SECRET;

// WebSocket server instance (will be injected)
let wsServer = null;

// Set WebSocket server reference
function setWebSocketServer(server) {
  wsServer = server;
}

// Room membership check
function checkRoomMembership(room, userId) {
  if (room.type === "public") {
    return true; // Public rooms are accessible to all authenticated users
  }
  return room.members.includes(userId);
}

// Enhanced ownership check with data validation
function checkMessageOwnership(message, userId, userRole) {
  // Validate message data consistency
  if (!message.userId) {
    console.error("Message missing userId:", message.id);
    return false;
  }

  // Message owner can always edit their own message
  if (message.userId === userId) {
    console.log(`✅ Owner access: User ${userId} editing own message`);
    return true;
  }

  // Admins can edit any message (for moderation purposes)
  if (userRole === "admin") {
    console.log(
      `✅ Admin access: Admin ${userId} editing message by ${message.userId}`
    );
    return true;
  }

  // Moderators can edit any message (for moderation purposes)
  if (userRole === "moderator") {
    console.log(
      `✅ Moderator access: Moderator ${userId} editing message by ${message.userId}`
    );
    return true;
  }

  // Regular users can only edit their own messages
  console.log(
    `❌ Access denied: User ${userId} (${userRole}) cannot edit message by ${message.userId}`
  );
  return false;
}

// Get all rooms - Require auth & hide member list
router.get("/", authenticate, async (req, res) => {
  try {
    res.set({
      "X-Total-Rooms": chatRooms.length.toString(),
      "X-Hidden-Command": "/whisper <message> for secret messages"
    });

    res.json({
      rooms: chatRooms.map((room) => ({
        id: room.id,
        name: room.name,
        type: room.type,
        memberCount: room.members.length
        // BUG: Exposing members removed -fixed
      }))
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" }); // BUG: Hide error details -fixed
  }
});

// Get messages from room - Require auth & membership check
router.get("/:roomId", authenticate, async (req, res) => {
  try {
    const { roomId } = req.params;
    const currentUser = req.user;

    const room = chatRooms.find((r) => r.id === roomId);

    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    // BUG: Enforce membership check -fixed
    if (room.type === "private" && !room.members.includes(currentUser.userId)) {
      return res.status(403).json({ error: "Access denied to private room" });
    }

    const roomMessages = messages.filter(
      (m) => m.roomId === roomId && !m.deleted
    );

    // Improved pagination with secure caps -fixed
    let limit = parseInt(req.query.limit, 10) || 50;
    limit = Math.min(limit, 100); // cap max limit at 100 to prevent overload
    const offset = parseInt(req.query.offset, 10) || 0;

    const paginatedMessages = roomMessages.slice(offset, offset + limit);

    res.set({
      "X-Message-Count": roomMessages.length.toString(),
      "X-Room-Type": room.type
    });

    res.json({
      messages: paginatedMessages.map((msg) => ({
        id: msg.id,
        content: msg.content,
        username: msg.username,
        // BUG: Hide userId -fixed
        timestamp: msg.timestamp,
        edited: msg.edited,
        // BUG: Hide edit history unless owner or admin -fixed
        editHistory:
          msg.userId === currentUser.userId || currentUser.role === "admin"
            ? msg.editHistory || []
            : undefined
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
    res.status(500).json({ error: "Internal server error" }); // BUG: Hide error details -fixed
  }
});

// Get specific message - Require auth and permission
router.get("/:roomId/:messageId", authenticate, async (req, res) => {
  try {
    const { roomId, messageId } = req.params;
    const currentUser = req.user;

    const message = messages.find(
      (m) => m.id === messageId && m.roomId === roomId && !m.deleted
    );
    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }

    // Check if user is member of the room (for private rooms)
    const room = chatRooms.find((r) => r.id === roomId);
    if (room.type === "private" && !room.members.includes(currentUser.userId)) {
      return res.status(403).json({ error: "Access denied" });
    }

    res.json({
      id: message.id,
      content: message.content,
      username: message.username,
      // BUG: Hide userId -fixed
      timestamp: message.timestamp,
      edited: message.edited,
      // BUG: Show edit history only to owners/admins -fixed
      editHistory:
        message.userId === currentUser.userId || currentUser.role === "admin"
          ? message.editHistory || []
          : undefined
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" }); // BUG: Hide error details -fixed
  }
});

// Send message - Require auth & membership check
router.post(
  "/:roomId",
  authenticate,
  messageLimiter,
  validateMessage,
  async (req, res) => {
    try {
      const { roomId } = req.params;
      const { content } = req.body;
      const currentUser = req.user;

      if (!content || content.trim() === "") {
        return res.status(400).json({ error: "Message content is required" });
      }

      const room = chatRooms.find((r) => r.id === roomId);
      if (!room) {
        return res.status(404).json({ error: "Room not found" });
      }

      // Check room membership
      if (!checkRoomMembership(room, currentUser.userId)) {
        return res
          .status(403)
          .json({ error: "You are not a member of this room" });
      }

      const newMessage = {
        id: uuidv4(),
        roomId,
        userId: currentUser.userId,
        username: currentUser.username,
        content: content.trim(),
        timestamp: new Date().toISOString(),
        edited: false,
        deleted: false
      };

      messages.push(newMessage);

      // Broadcast new message via WebSocket if available
      if (wsServer) {
        wsServer.broadcastToRoom(roomId, {
          type: "new_message",
          roomId,
          messageId: newMessage.id,
          content: newMessage.content,
          userId: currentUser.userId,
          username: currentUser.username,
          timestamp: newMessage.timestamp
        });
      }

      res.set("X-Message-Id", newMessage.id);

      res.status(201).json({
        message: "Message sent successfully",
        messageData: {
          id: newMessage.id,
          content: newMessage.content,
          username: newMessage.username,
          timestamp: newMessage.timestamp
        }
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" }); // BUG: Hide error message -fixed
    }
  }
);

// Edit message - Require auth & ownership
router.put(
  "/:roomId/:messageId",
  authenticate,
  validateRoomParams,
  validateMessage,
  async (req, res) => {
    try {
      const { roomId, messageId } = req.params;
      const { content } = req.body;
      const currentUser = req.user;

      if (!content || content.trim() === "") {
        return res.status(400).json({ error: "Message content is required" });
      }

      const messageIndex = messages.findIndex(
        (m) => m.id === messageId && m.roomId === roomId && !m.deleted
      );
      if (messageIndex === -1) {
        return res.status(404).json({ error: "Message not found" });
      }

      const message = messages[messageIndex];

      // Validate message-user consistency
      if (message.username && message.userId) {
        // Cross-reference with user database to ensure consistency
        const messageOwner = users.find((u) => u.id === message.userId);
        if (messageOwner && messageOwner.username !== message.username) {
          console.error(
            `Data inconsistency: Message ${messageId} has userId ${message.userId} but username ${message.username}, expected ${messageOwner.username}`
          );
          return res.status(500).json({ error: "Data consistency error" });
        }
      }

      // Check message ownership
      if (
        !checkMessageOwnership(message, currentUser.userId, currentUser.role)
      ) {
        return res
          .status(403)
          .json({ error: "You do not have permission to edit this message" });
      }

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

      // Broadcast message edit via WebSocket if available
      if (wsServer) {
        wsServer.broadcastToRoom(roomId, {
          type: "message_edited",
          roomId,
          messageId: message.id,
          content: message.content,
          editedBy: currentUser.userId,
          editedByUsername: currentUser.username,
          timestamp: message.lastEditedAt
        });
      }

      res.json({
        message: "Message updated successfully",
        messageData: {
          id: message.id,
          content: message.content,
          edited: message.edited,
          lastEditedAt: message.lastEditedAt
        }
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" }); // BUG: Hide error message -fixed
    }
  }
);

// Delete message - Require auth & ownership or room owner
router.delete(
  "/:roomId/:messageId",
  authenticate,
  validateRoomParams,
  async (req, res) => {
    try {
      const { roomId, messageId } = req.params;
      const currentUser = req.user;

      const messageIndex = messages.findIndex(
        (m) => m.id === messageId && m.roomId === roomId && !m.deleted
      );
      if (messageIndex === -1) {
        return res.status(404).json({ error: "Message not found" });
      }

      const message = messages[messageIndex];
      const room = chatRooms.find((r) => r.id === roomId);

      // Check permissions for deletion
      const isRoomOwner = room && room.createdBy === currentUser.userId;
      const isMessageOwner = message.userId === currentUser.userId;
      const isAdmin = currentUser.role === "admin";
      const isModerator = currentUser.role === "moderator";

      if (!isRoomOwner && !isMessageOwner && !isAdmin && !isModerator) {
        return res.status(403).json({ error: "Permission denied" });
      }

      // Soft delete message
      message.deleted = true;
      message.deletedAt = new Date().toISOString();
      message.deletedBy = currentUser.userId;

      // Broadcast message deletion via WebSocket if available
      if (wsServer) {
        wsServer.broadcastToRoom(roomId, {
          type: "message_deleted",
          roomId,
          messageId: message.id,
          deletedBy: currentUser.userId,
          deletedByUsername: currentUser.username,
          timestamp: message.deletedAt
        });
      }

      res.json({ message: "Message deleted successfully" });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" }); // BUG: Hide error message -fixed
    }
  }
);

module.exports = { router, setWebSocketServer };

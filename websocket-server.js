const WebSocket = require("ws");
const jwt = require("jsonwebtoken");
const url = require("url");
const axios = require("axios");
require("dotenv").config();

class WebSocketServer {
  constructor() {
    this.wss = null;
    this.clients = new Map(); // userId -> WebSocket connection
    this.rooms = new Map(); // roomId -> Set of userIds
    this.typingUsers = new Map(); // roomId -> Set of userIds currently typing
    this.JWT_SECRET = process.env.JWT_SECRET;
    this.apiBaseUrl = process.env.API_BASE_URL || "http://localhost:3004";
  }

  start(port = process.env.WEBSOCKET_PORT || 8080) {
    this.wss = new WebSocket.Server({
      port,
      verifyClient: (info) => {
        // Basic verification - full auth happens on connection
        return true;
      }
    });

    this.wss.on("connection", (ws, req) => {
      this.handleConnection(ws, req);
    });

    console.log(`🚀 WebSocket server running on port ${port}`);
    console.log(`🔌 Real-time chat features enabled!`);
  }

  handleConnection(ws, req) {
    const query = url.parse(req.url, true).query;
    const token = query.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      ws.close(1008, "Authentication required");
      return;
    }

    try {
      const decoded = jwt.verify(token, this.JWT_SECRET);
      const userId = decoded.userId;
      const username = decoded.username;
      const role = decoded.role;

      // ✅ Store client connection WITH token
      this.clients.set(userId, {
        ws,
        userId,
        username,
        role,
        token: token, // Store the JWT token for API calls
        joinedRooms: new Set(),
        lastActivity: Date.now()
      });

      ws.userId = userId;
      ws.username = username;
      ws.role = role;

      // Send welcome message
      this.sendToClient(userId, {
        type: "connected",
        message: "Connected to real-time chat",
        userId,
        username
      });

      // Handle incoming messages
      ws.on("message", (data) => {
        this.handleMessage(userId, data);
      });

      // Handle disconnection
      ws.on("close", () => {
        this.handleDisconnection(userId);
      });

      // Handle errors
      ws.on("error", (error) => {
        console.error(`WebSocket error for user ${userId}:`, error);
        this.handleDisconnection(userId);
      });

      console.log(`✅ User ${username} (${userId}) connected to WebSocket`);
    } catch (error) {
      console.error("WebSocket authentication failed:", error.message);
      ws.close(1008, "Invalid token");
    }
  }

  handleMessage(userId, data) {
    try {
      const message = JSON.parse(data);
      const client = this.clients.get(userId);

      if (!client) {
        return;
      }

      client.lastActivity = Date.now();

      switch (message.type) {
        case "join_room":
          this.handleJoinRoom(userId, message.roomId);
          break;

        case "leave_room":
          this.handleLeaveRoom(userId, message.roomId);
          break;

        case "typing_start":
          this.handleTypingStart(userId, message.roomId);
          break;

        case "typing_stop":
          this.handleTypingStop(userId, message.roomId);
          break;

        case "new_message":
          this.handleNewMessage(userId, message);
          break;

        case "message_edited":
          this.handleMessageEdited(userId, message);
          break;

        case "message_deleted":
          this.handleMessageDeleted(userId, message);
          break;

        case "user_status":
          this.handleUserStatus(userId, message.status);
          break;

        case "ping":
          this.sendToClient(userId, { type: "pong", timestamp: Date.now() });
          break;

        default:
          console.log(`Unknown message type: ${message.type}`);
      }
    } catch (error) {
      console.error(`Error handling message from ${userId}:`, error);
    }
  }

  handleJoinRoom(userId, roomId) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Add user to room
    if (!this.rooms.has(roomId)) {
      this.rooms.set(roomId, new Set());
    }

    this.rooms.get(roomId).add(userId);
    client.joinedRooms.add(roomId);

    // Notify room members
    this.broadcastToRoom(
      roomId,
      {
        type: "user_joined",
        roomId,
        userId,
        username: client.username,
        timestamp: new Date().toISOString()
      },
      userId
    );

    // Send confirmation to user
    this.sendToClient(userId, {
      type: "room_joined",
      roomId,
      message: `Joined room ${roomId}`,
      members: Array.from(this.rooms.get(roomId))
        .map((id) => {
          const member = this.clients.get(id);
          return member ? { userId: id, username: member.username } : null;
        })
        .filter(Boolean)
    });

    console.log(`📥 User ${client.username} joined room ${roomId}`);
  }

  handleLeaveRoom(userId, roomId) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Remove user from room
    if (this.rooms.has(roomId)) {
      this.rooms.get(roomId).delete(userId);
      if (this.rooms.get(roomId).size === 0) {
        this.rooms.delete(roomId);
      }
    }

    client.joinedRooms.delete(roomId);

    // Stop typing if user was typing
    this.handleTypingStop(userId, roomId);

    // Notify room members
    this.broadcastToRoom(roomId, {
      type: "user_left",
      roomId,
      userId,
      username: client.username,
      timestamp: new Date().toISOString()
    });

    console.log(`📤 User ${client.username} left room ${roomId}`);
  }

  handleTypingStart(userId, roomId) {
    const client = this.clients.get(userId);
    if (!client || !client.joinedRooms.has(roomId)) return;

    if (!this.typingUsers.has(roomId)) {
      this.typingUsers.set(roomId, new Set());
    }

    this.typingUsers.get(roomId).add(userId);

    // Broadcast typing indicator to room (excluding sender)
    this.broadcastToRoom(
      roomId,
      {
        type: "typing_start",
        roomId,
        userId,
        username: client.username,
        timestamp: new Date().toISOString()
      },
      userId
    );

    // Set timeout to auto-stop typing after 3 seconds
    setTimeout(() => {
      this.handleTypingStop(userId, roomId);
    }, 3000);
  }

  handleTypingStop(userId, roomId) {
    const client = this.clients.get(userId);
    if (!client) return;

    if (this.typingUsers.has(roomId)) {
      this.typingUsers.get(roomId).delete(userId);
      if (this.typingUsers.get(roomId).size === 0) {
        this.typingUsers.delete(roomId);
      }
    }

    // Broadcast typing stop to room (excluding sender)
    this.broadcastToRoom(
      roomId,
      {
        type: "typing_stop",
        roomId,
        userId,
        username: client.username,
        timestamp: new Date().toISOString()
      },
      userId
    );
  }

  // ✅ Add getUserToken method
  getUserToken(userId) {
    const client = this.clients.get(userId);
    return client ? client.token : null;
  }

  // ✅ Update handleNewMessage with better error handling
  async handleNewMessage(userId, message) {
    const client = this.clients.get(userId);
    if (!client || !client.joinedRooms.has(message.roomId)) {
      this.sendToClient(userId, {
        type: "message_error",
        error: "Not joined to this room",
        originalMessage: message
      });
      return;
    }

    const token = this.getUserToken(userId);
    if (!token) {
      this.sendToClient(userId, {
        type: "message_error",
        error: "Authentication token not available",
        originalMessage: message
      });
      return;
    }

    try {
      console.log(
        `📤 Saving WebSocket message from ${client.username} to ${message.roomId}`
      );

      const response = await axios.post(
        `${this.apiBaseUrl}/api/messages/${message.roomId}`,
        {
          content: message.content
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
          },
          timeout: 5000 // Add timeout
        }
      );

      if (response.data && response.data.message) {
        const savedMessage = response.data.message;

        // Stop typing
        this.handleTypingStop(userId, message.roomId);

        // Broadcast the saved message
        this.broadcastToRoom(message.roomId, {
          type: "new_message",
          ...savedMessage
        });

        console.log(`✅ Message saved and broadcast: ${savedMessage.id}`);
      } else {
        throw new Error("Invalid API response format");
      }
    } catch (error) {
      console.error("Failed to save WebSocket message:", error.message);

      // Send detailed error to client
      this.sendToClient(userId, {
        type: "message_error",
        error: error.response
          ? `API Error: ${error.response.status} - ${
              error.response.data?.error || error.response.statusText
            }`
          : `Network Error: ${error.message}`,
        originalMessage: message,
        statusCode: error.response?.status
      });
    }
  }

  handleMessageEdited(userId, message) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Broadcast edited message to room
    this.broadcastToRoom(message.roomId, {
      type: "message_edited",
      roomId: message.roomId,
      messageId: message.messageId,
      content: message.content,
      editedBy: userId,
      editedByUsername: client.username,
      timestamp: new Date().toISOString()
    });
  }

  handleMessageDeleted(userId, message) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Broadcast deleted message to room
    this.broadcastToRoom(message.roomId, {
      type: "message_deleted",
      roomId: message.roomId,
      messageId: message.messageId,
      deletedBy: userId,
      deletedByUsername: client.username,
      timestamp: new Date().toISOString()
    });
  }

  handleUserStatus(userId, status) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Broadcast status change to all rooms user is in
    client.joinedRooms.forEach((roomId) => {
      this.broadcastToRoom(
        roomId,
        {
          type: "user_status_changed",
          roomId,
          userId,
          username: client.username,
          status,
          timestamp: new Date().toISOString()
        },
        userId
      );
    });
  }

  handleDisconnection(userId) {
    const client = this.clients.get(userId);
    if (!client) return;

    // Leave all rooms
    client.joinedRooms.forEach((roomId) => {
      this.handleLeaveRoom(userId, roomId);
    });

    // Remove client
    this.clients.delete(userId);

    console.log(
      `❌ User ${client.username} (${userId}) disconnected from WebSocket`
    );
  }

  // Send message to specific client
  sendToClient(userId, message) {
    const client = this.clients.get(userId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  // Broadcast message to all users in a room
  broadcastToRoom(roomId, message, excludeUserId = null) {
    if (!this.rooms.has(roomId)) return;

    this.rooms.get(roomId).forEach((userId) => {
      if (userId !== excludeUserId) {
        this.sendToClient(userId, message);
      }
    });
  }

  // Broadcast message to all connected clients
  broadcastToAll(message, excludeUserId = null) {
    this.clients.forEach((client, userId) => {
      if (userId !== excludeUserId) {
        this.sendToClient(userId, message);
      }
    });
  }

  // Get online users in a room
  getRoomUsers(roomId) {
    if (!this.rooms.has(roomId)) return [];

    return Array.from(this.rooms.get(roomId))
      .map((userId) => {
        const client = this.clients.get(userId);
        return client
          ? {
              userId,
              username: client.username,
              role: client.role,
              lastActivity: client.lastActivity
            }
          : null;
      })
      .filter(Boolean);
  }

  // Get typing users in a room
  getTypingUsers(roomId) {
    if (!this.typingUsers.has(roomId)) return [];

    return Array.from(this.typingUsers.get(roomId))
      .map((userId) => {
        const client = this.clients.get(userId);
        return client
          ? {
              userId,
              username: client.username
            }
          : null;
      })
      .filter(Boolean);
  }

  // Clean up inactive connections
  cleanupInactiveConnections() {
    const now = Date.now();
    const INACTIVE_THRESHOLD = 5 * 60 * 1000; // 5 minutes

    this.clients.forEach((client, userId) => {
      if (now - client.lastActivity > INACTIVE_THRESHOLD) {
        console.log(
          `🧹 Cleaning up inactive connection for ${client.username}`
        );
        client.ws.close();
        this.handleDisconnection(userId);
      }
    });
  }
}

module.exports = WebSocketServer;

const express = require("express");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const http = require("http");
require("dotenv").config();

// Import WebSocket server
const WebSocketServer = require("./websocket-server");

// Import routes
const authRoutes = require("./routes/auth");
const {
  router: messagesRoutes,
  setWebSocketServer
} = require("./routes/messages");
const whisperRoutes = require("./routes/whisper");

// Import middleware
const { apiLimiter } = require("./middleware/rateLimiter");
const { securityHeaders } = require("./middleware/validation");

const app = express();
const PORT = process.env.PORT || 3004;

// Create HTTP server
const server = http.createServer(app);

// Initialize WebSocket server
const wsServer = new WebSocketServer();

// Updated CORS configuration for production
const allowedOrigins = [
  "http://localhost:3004",
  "http://localhost:8888",
  "http://127.0.0.1:3004",
  "https://medable-chat-api-app.onrender.com"
];

// Add environment-based origins
if (process.env.CORS_ORIGINS) {
  allowedOrigins.push(...process.env.CORS_ORIGINS.split(","));
}

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      if (allowedOrigins.some((allowed) => origin.startsWith(allowed))) {
        return callback(null, true);
      }

      console.log(`CORS blocked origin: ${origin}`);
      const msg =
        "CORS policy does not allow access from the specified Origin.";
      return callback(new Error(msg), false);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Admin-Key",
      "X-Decrypt-Key"
    ],
    credentials: true
  })
);

// Security middleware with updated CSP for production WebSocket
const productionWSUrl =
  process.env.NODE_ENV === "production"
    ? "wss://medable-chat-api-app.onrender.com"
    : "ws://localhost:8080 wss://localhost:8080";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: [
          "'self'",
          productionWSUrl,
          "ws://localhost:8080",
          "wss://localhost:8080"
        ],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(securityHeaders);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Rate limiting
app.use("/api/", apiLimiter);

app.use(express.static(path.join(__dirname, "public")));

// Custom headers for puzzle hints
app.use((req, res, next) => {
  res.set({
    "X-Chat-Protocol": "v1.0",
    "X-Message-Hint": "whisper_endpoint_needs_decryption_key"
  });
  next();
});

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/messages", messagesRoutes);
app.use("/api/whisper", whisperRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
    websocket: {
      enabled: process.env.WEBSOCKET_ENABLED !== "false",
      port: PORT,
      url:
        process.env.NODE_ENV === "production"
          ? `wss://medable-chat-api-app.onrender.com`
          : `ws://localhost:${PORT}`
    }
  });
});

// Serve static files
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Error handler
app.use((error, req, res, next) => {
  console.error("Error:", error);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
server.listen(PORT, "0.0.0.0", () => {
  console.log(`💬 Assessment 3: Chat/Messaging API running on port ${PORT}`);
  console.log(`📋 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Real-time features and security challenges await!`);

  // Start WebSocket server on the SAME server instance
  if (process.env.WEBSOCKET_ENABLED !== "false") {
    wsServer.start(PORT, server); // Pass the HTTP server instance

    // Set WebSocket server reference in messages routes
    setWebSocketServer(wsServer);

    // Cleanup inactive connections every 5 minutes
    setInterval(() => {
      wsServer.cleanupInactiveConnections();
    }, 5 * 60 * 1000);

    console.log(
      `🔌 WebSocket server running on ${
        process.env.NODE_ENV === "production" ? "wss" : "ws"
      }://localhost:${PORT}`
    );
  }
});

// Export server and WebSocket server for use in routes
module.exports = { app, server, wsServer };

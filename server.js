const express = require("express");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
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
const PORT = process.env.PORT || 3003;

// Initialize WebSocket server
const wsServer = new WebSocketServer();

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",")
  : [];

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg =
          "The CORS policy for this site does not allow access from the specified Origin.";
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Admin-Key",
      "X-Decrypt-Key"
    ]
  })
);

// Security middleware
app.use(helmet());
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
  res.json({ status: "OK", timestamp: new Date().toISOString() });
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

if (process.env.NODE_ENV !== "production") {
  app.use((req, res, next) => {
    res.set("X-Message-Hint", "whisper_endpoint_needs_decryption_key");
    next();
  });
}

app.listen(PORT, () => {
  console.log(
    `💬 Assessment 3: Chat/Messaging API running on http://localhost:${PORT}`
  );
  console.log(`📋 View instructions: http://localhost:${PORT}`);
  console.log(`🔐 Real-time features and security challenges await!`);

  // Start WebSocket server if enabled
  if (process.env.WEBSOCKET_ENABLED !== "false") {
    wsServer.start();

    // Set WebSocket server reference in messages routes
    setWebSocketServer(wsServer);

    // Cleanup inactive connections every 5 minutes
    setInterval(() => {
      wsServer.cleanupInactiveConnections();
    }, 5 * 60 * 1000);
  }
});

// Export WebSocket server for use in routes
module.exports = { app, wsServer };

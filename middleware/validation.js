const validator = require("validator");

// Input sanitization and validation helpers
const sanitizeInput = (input) => {
  if (typeof input !== "string") return input;

  // Remove control characters and normalize whitespace
  let sanitized = input
    .replace(/[\r\n\t]/g, " ") // Replace control chars with spaces
    .replace(/\s+/g, " ") // Normalize multiple spaces
    .trim();

  return validator.escape(sanitized);
};

const validateEmail = (email) => {
  return validator.isEmail(email);
};

const validateUsername = (username) => {
  // Username should be 3-20 characters, alphanumeric + underscore/dash
  return /^[a-zA-Z0-9_-]{3,20}$/.test(username);
};

const validatePassword = (password) => {
  // Password should be at least 8 characters with at least one letter and one number
  return (
    password &&
    password.length >= 8 &&
    /[a-zA-Z]/.test(password) &&
    /[0-9]/.test(password)
  );
};

const validateMessageContent = (content) => {
  if (!content || typeof content !== "string") return false;

  // Clean content first
  const cleaned = content
    .replace(/[\r\n\t]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.length > 0 && cleaned.length <= 1000;
};

const validateRoomId = (roomId) => {
  // Room ID should be alphanumeric with underscores/dashes, 3-50 characters
  return /^[a-zA-Z0-9_-]{3,50}$/.test(roomId);
};

const validateStatus = (status) => {
  const validStatuses = ["online", "offline", "away", "busy"];
  return validStatuses.includes(status);
};

// Validation middleware generators
const validateLogin = (req, res, next) => {
  const { username, email, password } = req.body;

  // Sanitize inputs
  if (username) req.body.username = sanitizeInput(username);
  if (email) req.body.email = sanitizeInput(email);

  // Validation
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  if (!username && !email) {
    return res.status(400).json({ error: "Username or email is required" });
  }

  if (username && !validateUsername(username)) {
    return res.status(400).json({ error: "Invalid username format" });
  }

  if (email && !validateEmail(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters long and contain at least one letter and one number"
    });
  }

  next();
};

const validateRegistration = (req, res, next) => {
  const { username, email, password } = req.body;

  // Sanitize inputs
  req.body.username = sanitizeInput(username);
  req.body.email = sanitizeInput(email);

  // Validation
  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ error: "Username, email, and password are required" });
  }

  if (!validateUsername(username)) {
    return res.status(400).json({
      error:
        "Username must be 3-20 characters long and contain only letters, numbers, underscores, or dashes"
    });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters long and contain at least one letter and one number"
    });
  }

  next();
};

const validateMessage = (req, res, next) => {
  try {
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({
        error: "Message content is required"
      });
    }

    // Sanitize content
    const sanitizedContent = content
      .replace(/[\r\n\t]/g, " ") // Replace control chars
      .replace(/\s+/g, " ") // Normalize spaces
      .trim();

    if (!validateMessageContent(sanitizedContent)) {
      return res.status(400).json({
        error: "Message content must be between 1 and 1000 characters"
      });
    }

    // Update the request body with sanitized content
    req.body.content = sanitizedContent;

    next();
  } catch (error) {
    return res.status(400).json({
      error: "Invalid message format"
    });
  }
};

const validateStatusUpdate = (req, res, next) => {
  const { status } = req.body;

  if (!validateStatus(status)) {
    return res.status(400).json({
      error: "Invalid status. Must be one of: online, offline, away, busy"
    });
  }

  next();
};

const validateRoomParams = (req, res, next) => {
  const { roomId, messageId } = req.params;

  if (roomId && !validateRoomId(roomId)) {
    return res.status(400).json({ error: "Invalid room ID format" });
  }

  if (messageId && !validator.isUUID(messageId)) {
    return res.status(400).json({ error: "Invalid message ID format" });
  }

  next();
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Set security headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Updated CSP to allow WebSocket connections
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "connect-src 'self' ws://localhost:8080 wss://localhost:8080",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'"
    ].join("; ")
  );

  // Add puzzle hint header
  res.setHeader("X-Message-Hint", "whisper_endpoint_needs_decryption_key");

  next();
};

module.exports = {
  sanitizeInput,
  validateEmail,
  validateUsername,
  validatePassword,
  validateMessageContent,
  validateRoomId,
  validateStatus,
  validateLogin,
  validateRegistration,
  validateMessage,
  validateStatusUpdate,
  validateRoomParams,
  securityHeaders
};

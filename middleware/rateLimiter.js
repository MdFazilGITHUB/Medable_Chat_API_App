const rateLimit = require('express-rate-limit');

// General API rate limiting
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req, res) => {
      res.status(429).json({
        error: message,
        retryAfter: Math.round(windowMs / 1000)
      });
    }
  });
};

// Authentication endpoints rate limiting (stricter)
const authLimiter = createRateLimiter(
  0.1 * 60 * 1000, // 15 minutes
  5, // 5 attempts
  'Too many authentication attempts, please try again later'
);

// General API rate limiting
const apiLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  100, // 100 requests
  'Too many requests, please try again later'
);

// Message sending rate limiting
const messageLimiter = createRateLimiter(
  1 * 60 * 1000, // 1 minute
  20, // 20 messages per minute
  'Too many messages, please slow down'
);

// Registration rate limiting (very strict)
const registerLimiter = createRateLimiter(
  0.1* 60 * 1000, // 1 hour
  3, // 3 registrations per hour per IP
  'Too many registration attempts, please try again later'
);

module.exports = {
  authLimiter,
  apiLimiter,
  messageLimiter,
  registerLimiter
};
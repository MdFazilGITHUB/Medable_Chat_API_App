# 💬 Assessment 3: Chat/Messaging API

Welcome to the Chat/Messaging API assessment! This project simulates a real-time chat system with **critical authentication vulnerabilities**, **authorization bypasses**, and **missing real-time features** that you need to identify and fix.

## 🎯 Objective

Your mission is to:
1. **🔐 Fix authentication and session management** vulnerabilities
2. **🛡️ Implement proper authorization** for rooms and messages
3. **⚡ Build missing real-time features** for a complete chat experience
4. **🧩 Solve cryptographic puzzles** and hidden challenges

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- Netlify CLI (for local development)

### Installation

```bash
npm install
npm run dev
```

The API will be available at `http://localhost:8888`

## 👥 Test Users

| Username | Email | Password | Role | Status |
|----------|-------|----------|------|--------|
| alice | alice@chat.com | password123 | admin | online |
| bob | bob@chat.com | bobsecret | user | offline |
| charlie | charlie@chat.com | charlie2024 | moderator | online |

## 📚 API Documentation

### Authentication Endpoints

#### POST /api/auth/login
Login with username or email
```bash
curl -X POST http://localhost:8888/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

#### POST /api/auth/register
Register new user
```bash
curl -X POST http://localhost:8888/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","email":"new@test.com","password":"password123"}'
```

#### GET /api/auth/profile
Get current user profile
```bash
curl http://localhost:8888/api/auth/profile \
  -H "Authorization: Bearer <token>"
```

### Messaging Endpoints

#### GET /api/messages
Get all chat rooms
```bash
curl http://localhost:8888/api/messages
```

#### GET /api/messages/:roomId
Get messages from specific room
```bash
curl http://localhost:8888/api/messages/general?limit=10&offset=0
```

#### POST /api/messages/:roomId
Send message to room
```bash
curl -X POST http://localhost:8888/api/messages/general \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"content":"Hello everyone!"}'
```

## 🚨 Critical Security Vulnerabilities

### Authentication Vulnerabilities
1. **Plain Text Password Storage** - Passwords stored without hashing
2. **Hardcoded JWT Secret** - JWT secret is hardcoded in source code
3. **Hardcoded Admin Keys** - Admin bypass keys in source code
4. **Silent Authentication Failures** - Auth failures don't return proper errors
5. **Session Management Issues** - In-memory sessions without cleanup
6. **Auto-Login After Registration** - Users auto-logged in without consent
7. **Invalid Token Success** - Logout succeeds even with invalid tokens

### Authorization Vulnerabilities
8. **No Room Membership Checks** - Anyone can read any room's messages
9. **Broken Message Ownership** - Edit/delete checks don't work properly
10. **Admin Privilege Escalation** - Admin endpoints expose all user data
11. **Cross-User Data Access** - Users can access other users' information
12. **Missing Authentication on Critical Operations** - Some endpoints don't check auth

### Data Exposure Issues
13. **Password Exposure** - Admin users can see all passwords
14. **Email Address Leakage** - Emails returned unnecessarily in responses
15. **User ID Exposure** - Internal user IDs exposed in API responses
16. **Session Information Disclosure** - Session details exposed to clients
17. **Edit History Without Permission** - Message edit history visible to everyone
18. **Internal Error Details** - Stack traces and error details exposed

## ⚡ Missing Features to Implement

### Must-Have Features
1. **Password Hashing** - Implement bcrypt for password storage
2. **JWT Secret from Environment** - Move secret to environment variables
3. **Room Membership Validation** - Proper access control for rooms
4. **Message Ownership Checks** - Verify user owns message before edit/delete
5. **Session Management** - Proper session storage and cleanup
6. **Input Validation** - Comprehensive validation for all inputs
7. **Secure Error Handling** - Remove sensitive data from error responses
8. **Rate Limiting** - Prevent spam and brute force attacks

### Real-Time Features
9. **WebSocket Integration** - Real-time message delivery
10. **Online Status Tracking** - Real-time user presence
11. **Typing Indicators** - Show when users are typing
12. **Message Delivery Receipts** - Confirm message delivery
13. **Room Notifications** - Notify users of room events

### Advanced Features
14. **Message Encryption** - End-to-end encryption for private messages
15. **File Upload Support** - Share images and files in chat
16. **Message Reactions** - Add emoji reactions to messages
17. **Thread Replies** - Reply to specific messages
18. **Message Search** - Search through chat history

## 🧩 Puzzles & Hidden Challenges

### Puzzle 1: Header Hint Discovery 🔍
Find and interpret the hint in the API response headers.
- **Location**: Check `X-Message-Hint` header in API responses
- **Challenge**: Decode what `whisper_endpoint_needs_decryption_key` means
- **Reward**: Discover the hidden whisper endpoint

### Puzzle 2: Whisper Endpoint Access 🤫
Find and access the secret whisper messaging system.
- **Endpoint**: `/api/whisper`
- **Access Method 1**: Valid JWT token (basic access)
- **Access Method 2**: `X-Decrypt-Key: chat-master-key-2024` (admin access)
- **Access Method 3**: `?code=system-whisper-2024` (system access)
- **Reward**: Access to encrypted admin messages

### Puzzle 3: Message Decryption 🔐
Decrypt the encrypted whisper messages using provided tools.
- **Caesar Cipher**: Shift value of 7
- **Example**: `"Whzzdvyk ylzla mvy bzly hspjl: altw123"` → `"Password reset for user alice: temp123"`
- **XOR Encryption**: Use key `chat-master-key-2024`
- **Final ROT13**: Decode the final puzzle message
- **Reward**: Ultimate challenge clue

### Puzzle 4: Real-Time Discovery ⚡
Decode the final ROT13 message to discover the ultimate challenge.
- **Encoded Message**: `"Pbatenghyngvbaf! Lbh qrpelcgrq gur juvfcre zrffntrf. Svany pyhrf: ERNY_GVZR_JROFBPXRG_2024"`
- **Decoded Message**: `"Congratulations! You decrypted the whisper messages. Final clues: REAL_TIME_WEBSOCKET_2024"`
- **Challenge**: Implement WebSocket functionality for real-time chat

## 🔧 Testing Your Solutions

### Authentication Security Tests
```bash
# Test plain text password storage (should fail after fix)
curl -X POST http://localhost:8888/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'

# Test admin key bypass (should be removed)
curl -X PUT http://localhost:8888/api/auth/status \
  -H "X-Admin-Key: super-secret-admin-key-2024" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user1","status":"offline"}'

# Test admin data exposure (should be filtered)
# Login as alice first, then check profile
curl http://localhost:8888/api/auth/profile \
  -H "Authorization: Bearer <alice-token>"
```

### Authorization Tests
```bash
# Test private room access without membership
curl http://localhost:8888/api/messages/private

# Test message editing without ownership
curl -X PUT http://localhost:8888/api/messages/general/1 \
  -H "Authorization: Bearer <bob-token>" \
  -H "Content-Type: application/json" \
  -d '{"content":"I can edit anyone\'s message!"}'

# Test cross-user data access
curl http://localhost:8888/api/auth/profile \
  -H "Authorization: Bearer <user-token>"
```

### Whisper Endpoint Tests
```bash
# Test basic JWT access
curl -H "Authorization: Bearer <token>" \
     http://localhost:8888/api/whisper

# Test admin decryption key access
curl -H "X-Decrypt-Key: chat-master-key-2024" \
     http://localhost:8888/api/whisper

# Test system whisper code access
curl "http://localhost:8888/api/whisper?code=system-whisper-2024"

# Send encrypted whisper message
curl -X POST http://localhost:8888/api/whisper \
  -H "X-Decrypt-Key: chat-master-key-2024" \
  -H "Content-Type: application/json" \
  -d '{"content":"Secret admin message","recipient":"alice","encrypt":true}'
```

## 📝 Expected Solutions

### Security Fixes
1. **Implement bcrypt** for password hashing
2. **Environment Variables** for all secrets
3. **Session Cleanup** with proper expiration
4. **Input Sanitization** for all user inputs
5. **Error Response Filtering** to remove sensitive data
6. **JWT Token Blacklisting** for proper logout
7. **Role-Based Access Control** for admin operations

### Authorization Implementation
1. **Room Membership Middleware** to verify access
2. **Message Ownership Validation** before edit/delete
3. **Private Room Protection** with proper access control
4. **Admin Action Logging** for accountability

### Real-Time Features
1. **WebSocket Server** for real-time communication
2. **User Presence System** for online/offline status
3. **Message Broadcasting** to room members
4. **Typing Indicators** with timeout handling
5. **Connection Management** with user mapping

## 🏆 Bonus Challenges

### Advanced Security
- **Two-Factor Authentication** for admin accounts
- **Account Lockout** after failed login attempts
- **Audit Logging** for security events
- **API Key Management** for service-to-service auth
- **Content Security Policy** headers

### Advanced Real-Time Features
- **Message Delivery Status** (sent, delivered, read)
- **Voice Message Support** with file handling
- **Screen Sharing** capabilities
- **Video Chat Integration**
- **Bot Integration** framework

### Performance Optimizations
- **Message Pagination** with cursor-based navigation
- **Database Integration** for persistent storage
- **Redis Caching** for session management
- **Message Queuing** for high-throughput scenarios

## 🚨 Common Pitfalls

1. **Don't just remove vulnerable features** - Implement them securely
2. **Test all authentication paths** - Both success and failure cases
3. **Validate authorization at every level** - Room, message, and user access
4. **Handle WebSocket disconnections** - Clean up resources properly
5. **Consider race conditions** - Multiple users editing simultaneously
6. **Don't break existing functionality** - Maintain API compatibility

## 📊 Evaluation Criteria

### Security Implementation (35%)
- All authentication vulnerabilities properly fixed
- Authorization implemented correctly
- No new security issues introduced
- Secure coding practices followed

### Feature Implementation (25%)
- Real-time messaging functionality
- Proper room and user management
- WebSocket integration working correctly

### Code Quality (20%)
- Clean, maintainable code
- Proper error handling
- Good separation of concerns
- Modern JavaScript practices

### Problem Solving (20%)
- All puzzles solved correctly
- Creative solutions to complex problems
- Understanding of cryptographic concepts
- Real-time system design knowledge

## 🛠️ Development Tips

### WebSocket Implementation Guide
```javascript
// Basic WebSocket setup for Netlify Functions
const WebSocket = require('ws');

// Connection handling
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
  // Authenticate user
  // Add to room
  // Handle messages
});

// Message broadcasting
function broadcastToRoom(roomId, message) {
  // Send to all room members
}
```

### Security Best Practices
- Always hash passwords with bcrypt (salt rounds >= 12)
- Use environment variables for all secrets
- Implement proper session management
- Validate all inputs before processing
- Use HTTPS in production
- Implement rate limiting for all endpoints

### Testing Strategy
1. **Unit Tests** for individual functions
2. **Integration Tests** for API endpoints
3. **Security Tests** for vulnerability validation
4. **Real-Time Tests** for WebSocket functionality
5. **Load Tests** for concurrent user handling

## 📞 Support

Document your approach to solving complex security issues and real-time challenges. Show your understanding of:
- Authentication vs Authorization
- Session management strategies
- WebSocket connection handling
- Message delivery guarantees
- Security threat modeling

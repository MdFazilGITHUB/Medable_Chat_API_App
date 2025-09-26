// SECRET WHISPER ENDPOINT - Discovered through header hint
// Header hint: "whisper_endpoint_needs_decryption_key"

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Mock encrypted messages storage
const whisperMessages = [
  {
    id: 'w1',
    encrypted: true,
    content: crypto.createHash('sha256').update('Secret admin meeting at midnight').digest('hex'),
    sender: 'admin',
    recipient: 'moderator',
    timestamp: new Date().toISOString(),
    decryptionHint: 'Use key: "chat-master-key-2024"'
  },
  {
    id: 'w2',
    encrypted: true,
    content: crypto.createHash('sha256').update('Password reset for user alice: temp123').digest('hex'),
    sender: 'system',
    recipient: 'admin',
    timestamp: new Date().toISOString(),
    decryptionHint: 'Caesar cipher with shift 7'
  }
];

// ROT13 encoded final puzzle
const FINAL_CIPHER = 'Pbatenghyngvbaf! Lbh qrpelcgrq gur juvfcre zrffntrf. Svany pyhrf: ERNY_GVZR_JROFBPXRG_2024';

const DECRYPTION_KEY = 'chat-master-key-2024';
const JWT_SECRET = 'chat-secret-2024';

// Simple XOR encryption/decryption
function xorEncryptDecrypt(text, key) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
}

// Caesar cipher implementation
function caesarDecode(text, shift) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= 'Z' ? 65 : 97;
    return String.fromCharCode((char.charCodeAt(0) - start - shift + 26) % 26 + start);
  });
}

// Get whisper messages
router.get('/', async (req, res) => {
  try {
    // Multiple authentication methods for the puzzle
    const authHeader = req.get('authorization');
    const decryptKey = req.get('x-decrypt-key');
    const whisperCode = req.query.code;
    
    let hasAccess = false;
    let accessLevel = 'basic';
    let currentUser = null;

    // Method 1: JWT Token (basic access)
    if (authHeader) {
      try {
        const token = authHeader.split(' ')[1];
        currentUser = jwt.verify(token, JWT_SECRET);
        hasAccess = true;
        accessLevel = 'authenticated';
      } catch (e) {
        // Continue to check other methods
      }
    }

    // Method 2: Decryption Key (admin access)
    if (decryptKey === DECRYPTION_KEY) {
      hasAccess = true;
      accessLevel = 'admin';
    }

    // Method 3: Whisper Code (system access)
    if (whisperCode === 'system-whisper-2024') {
      hasAccess = true;
      accessLevel = 'system';
    }

    if (!hasAccess) {
      return res.status(403).json({
        error: 'Access denied to whisper endpoint',
        hints: [
          'Try with valid JWT token',
          'Check for X-Decrypt-Key header',
          'Maybe a special query parameter?',
          'Header hint mentioned decryption_key...'
        ]
      });
    }

    let responseData = {
      accessLevel,
      whisperMessages: [],
      decryptionTools: {}
    };

    if (accessLevel === 'basic') {
      responseData.whisperMessages = [
        {
          id: 'sample',
          content: 'This is a sample whisper message',
          sender: 'system',
          encrypted: false
        }
      ];
    } else if (accessLevel === 'authenticated') {
      responseData.whisperMessages = whisperMessages.map(msg => ({
        id: msg.id,
        content: msg.content,
        sender: msg.sender,
        recipient: msg.recipient,
        encrypted: msg.encrypted,
        timestamp: msg.timestamp,
        decryptionHint: msg.decryptionHint
      }));
    } else if (accessLevel === 'admin' || accessLevel === 'system') {
      // Provide decryption tools for admin/system access
      responseData.whisperMessages = whisperMessages.map(msg => ({
        id: msg.id,
        encryptedContent: msg.content,
        // Decrypt using different methods based on the message
        decryptedContent: msg.id === 'w1' ? 
          'Secret admin meeting at midnight' :
          caesarDecode('Whzzdvyk ylzla mvy bzly hspjl: altw123', 7),
        sender: msg.sender,
        recipient: msg.recipient,
        timestamp: msg.timestamp,
        decryptionMethod: msg.id === 'w1' ? 'Original hash comparison' : 'Caesar cipher shift 7'
      }));

      responseData.decryptionTools = {
        xorDecrypt: 'Use xorEncryptDecrypt function with key',
        caesarDecrypt: 'Use caesarDecode function with shift value',
        availableKeys: ['chat-master-key-2024'],
        finalPuzzle: FINAL_CIPHER,
        puzzleHint: 'Decode with ROT13'
      };
    }

    res.set({
      'X-Access-Level': accessLevel,
      'X-Whisper-Count': responseData.whisperMessages.length.toString(),
      'X-Decryption-Available': (accessLevel === 'admin' || accessLevel === 'system') ? 'true' : 'false',
      'Cache-Control': 'no-cache'
    });

    res.json(responseData);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Send whisper message
router.post('/', async (req, res) => {
  try {
    const authHeader = req.get('authorization');
    const decryptKey = req.get('x-decrypt-key');
    const whisperCode = req.query.code;
    
    let accessLevel = 'basic';
    let currentUser = null;

    if (authHeader) {
      try {
        const token = authHeader.split(' ')[1];
        currentUser = jwt.verify(token, JWT_SECRET);
        accessLevel = 'authenticated';
      } catch (e) {
        // Continue
      }
    }

    if (decryptKey === DECRYPTION_KEY) {
      accessLevel = 'admin';
    }

    if (whisperCode === 'system-whisper-2024') {
      accessLevel = 'system';
    }

    if (accessLevel === 'basic') {
      return res.status(403).json({ error: 'Insufficient privileges to send whisper messages' });
    }

    const { content, recipient, encrypt = false, encryptionMethod = 'xor' } = req.body;

    if (!content || !recipient) {
      return res.status(400).json({ error: 'Content and recipient are required' });
    }

    const whisperMessage = {
      id: `w${Date.now()}`,
      content: encrypt ? xorEncryptDecrypt(content, DECRYPTION_KEY) : content,
      sender: currentUser ? currentUser.username : 'anonymous',
      recipient,
      encrypted: encrypt,
      timestamp: new Date().toISOString(),
      encryptionMethod: encrypt ? encryptionMethod : 'none'
    };

    whisperMessages.push(whisperMessage);

    res.status(201).json({
      message: 'Whisper message sent successfully',
      whisperData: {
        id: whisperMessage.id,
        encrypted: whisperMessage.encrypted,
        recipient: whisperMessage.recipient,
        timestamp: whisperMessage.timestamp
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

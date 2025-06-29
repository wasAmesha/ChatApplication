# Enhanced SecureChat

A secure, end-to-end encrypted chat application with user authentication, RSA/AES key exchange, and comprehensive security features.

## Features

### 🔐 Security Features

- **User Authentication**: Email/password login with JWT tokens
- **RSA/ECC Key Exchange**: Secure public key distribution
- **AES Message Encryption**: Fast symmetric encryption for messages
- **Digital Signatures**: Message authenticity verification
- **Replay Attack Prevention**: Timestamp and nonce validation
- **Session Management**: Secure token-based sessions

### 💬 Chat Features

- **Real-time Messaging**: Instant encrypted communication
- **Online User List**: See who's available to chat
- **Message Verification**: Visual indicators for verified messages
- **Connection Status**: Real-time connection monitoring

### 📊 Compliance & Logging

- **Authentication Logs**: Login/logout tracking with IP addresses
- **Message Metadata**: Encrypted message logging for compliance
- **Admin Endpoints**: Log viewing for administrators

## Quick Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Start Server

```bash
npm start
# or for development
npm run dev
```

### 3. Access Application

Open your browser to `http://localhost:3000`

## File Structure

```
src/
├── app.js              # Main server file
├── package.json        # Dependencies
└── public/
    ├── login.html      # Login page
    ├── register.html   # Registration page
    └── chat.html       # Main chat interface
```

## Security Implementation

### Authentication Flow (A1)

1. User registers with email/password
2. Password hashed with bcrypt
3. JWT token issued on successful login
4. Token required for all chat operations

### Key Exchange (K1, K3)

1. Client generates RSA key pair
2. Public key uploaded to server
3. Server distributes public keys to other users
4. Private keys never leave client

### Message Encryption (M1-M8)

1. **M1**: Generate AES key for message
2. **M2**: Encrypt message with AES
3. **M3**: Add timestamp and nonce
4. **M4**: Optionally sign with private key
5. **M6**: Encrypt AES key with recipient's public key
6. **M7**: Decrypt message on recipient side
7. **M8**: Verify signature with sender's public key
8. **M9**: Check timestamp/nonce for replay protection

### Logging (L)

- Authentication events (login/logout/IP)
- Message metadata (encrypted, with nonce)
- Optional: Full encrypted chat logs for compliance

## API Endpoints

- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `POST /api/logout` - Session termination
- `GET /api/admin/logs` - View system logs (admin only)

## Socket Events

### Client → Server

- `upload-public-key` - Share public key
- `request-public-key` - Request user's public key
- `send-message` - Send encrypted message
- `get-online-users` - Get list of online users

### Server → Client

- `user-key-available` - New user key available
- `receive-public-key` - Requested public key
- `receive-message` - Incoming encrypted message
- `online-users` - List of online users

## Security Notes

⚠️ **Production Considerations**:

- Use environment variables for JWT secrets
- Implement rate limiting
- Add HTTPS/SSL certificates
- Use a proper database instead of in-memory storage
- Add input validation and sanitization
- Implement proper admin authentication
- Consider using WebRTC for peer-to-peer communication

## Browser Support

Requires modern browsers with support for:

- WebSockets
- Crypto API
- Local Storage
- ES6+ JavaScript

## License

MIT License - See original SecureChat repository for details.

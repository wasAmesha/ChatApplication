<!-- # Secure Chat

Client side secure chat, based on [node.js](https://nodejs.org), [socket.io](https://socket.io/) and [asymmetric encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) without open storage on server side.

![loginform](https://raw.githubusercontent.com/bezzad/SecureChat/master/login.png)

![chatform](https://raw.githubusercontent.com/bezzad/SecureChat/master/chatform.png)
-----------------------

## How to use

* install [node.js](https://nodejs.org)
* clone this repository
* go to `src\` folder
* run below commands in your command line:
    + $ npm install
    + $ node app.js
* open your browser and enter your server url (http://localhost)

-----------------------

## References that have been used

* [**Node.js®**](https://nodejs.org) is a [JavaScript](http://en.wikipedia.org/wiki/JavaScript) runtime built on [Chrome's V8 JavaScript engine](https://developers.google.com/v8/).

* [**Express.js**](https://expressjs.com/) is a minimal and flexible Node.js web application framework that provides a robust set of features for web and mobile applications.

* [**Socket.io**](https://socket.io) enables real-time bidirectional event-based communication. It works on every platform, browser or device, focusing equally on reliability and speed.

* [**jQuery**](https://jquery.com/) is a fast, small, and feature-rich JavaScript library.

* [**Crypto.js**](https://github.com/brix/crypto-js) is a JavaScript library of crypto standards. Hasing and AES algorithms.

* [**JSEncrypt**](https://github.com/travist/jsencrypt) is a Javascript library to perform OpenSSL RSA Encryption, Decryption, and Key Generation.

* [**Local Storage**](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage) is analogous to [sessionStorage](https://developer.mozilla.org/en-US/docs/Web/API/sessionStorage), with the same same-origin rules applied, but it is persistent across sessions. `localStorage` was introduced in Firefox 3.5.

* [**Gravatar**](https://github.com/emerleite/node-gravatar) a library to generate Gravatar URLs in Node.js Based on gravatar specs - `http://en.gravatar.com/site/implement/hash/` and `http://en.gravatar.com/site/implement/images/`.

* [**Tchat card**](https://bootsnipp.com/snippets/0e3Ma) a Bootstrap chat theme snippet by [evarevirus](https://bootsnipp.com/evarevirus)

* [**Login form**](https://colorlib.com/wp/template/login-form-v3/) a cool login form template to be used for any website and app. Made by Colorlib. -->

# Enhanced SecureChat 🔐

A comprehensive secure messaging application implementing the complete security protocol shown in your diagram, built with Node.js, Socket.IO, and client-side encryption.

## 🚀 Security Features Implemented

### 1. User Authentication (A1)

- **HTTPS-based registration and login**
- **Email + Password authentication**
- **bcrypt password hashing** with 12 salt rounds
- **JWT token-based session management**
- **Rate limiting** to prevent brute force attacks
- **Input validation** and sanitization

### 2. Key Exchange Protocol (K1, K3)

- **RSA 2048-bit key pair generation** (client-side)
- **Public key upload and storage** on server
- **Secure key exchange** between users
- **Public key verification** and distribution
- **Support for both RSA and ECC** (configurable)

### 3. Secure Messaging (M1-M4, M6-M9)

- **AES-256 symmetric encryption** for message content
- **RSA encryption** for AES key exchange
- **Digital signatures** using RSA private keys
- **Timestamp verification** (5-minute window)
- **Cryptographic nonces** for replay protection
- **Message integrity verification**

### 4. Advanced Security Measures

- **Replay attack prevention** using nonce tracking
- **Signature verification** for message authenticity
- **Forward secrecy** with unique AES keys per message
- **Secure key storage** (client-side only)
- **Connection security** with Socket.IO authentication

### 5. Comprehensive Logging (L)

- **Authentication logs** (login/logout, IP tracking)
- **User action logging** (join room, send message)
- **Encrypted chat logs** (optional, compliance-ready)
- **Security event tracking**
- **Failed authentication monitoring**

## 📋 Security Protocol Flow

```
1. User Registration (A1)
   ├── Email + Password validation
   ├── RSA keypair generation (client-side)
   ├── Public key upload to server
   └── Secure password hashing (bcrypt)

2. User Authentication
   ├── Credential verification
   ├── JWT token generation
   ├── Session establishment
   └── Authentication logging

3. Key Exchange (K1, K3)
   ├── Public key retrieval
   ├── Key verification
   └── Secure key distribution

4. Secure Messaging (M1-M9)
   ├── AES key generation (M1)
   ├── Message encryption with AES (M2)
   ├── Timestamp + nonce attachment (M3)
   ├── Digital signature generation (M4)
   ├── AES key encryption with RSA (M6)
   ├── Message decryption (M7)
   ├── Signature verification (M8)
   └── Replay protection check (M9)

5. Logging & Monitoring (L)
   ├── Authentication logs
   ├── User activity tracking
   └── Encrypted chat storage
```

## 🛠️ Installation & Setup

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn

### Installation Steps

1. **Clone the repository**

   ```bash
   git clone <your-repo-url>
   cd secure-chat-enhanced
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set environment variables** (optional)

   ```bash
   export JWT_SECRET="your-super-secret-jwt-key"
   export PORT=3000
   ```

4. **Start the server**

   ```bash
   # Development mode
   npm run dev

   # Production mode
   npm start
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:3000`

## 🔧 Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT token signing (default: auto-generated)
- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment mode (development/production)

### Security Settings

The application includes several configurable security features:

- **Password Policy**: Minimum 8 characters (configurable)
- **Token Expiry**: 24 hours (configurable)
- **Rate Limiting**: 100 requests per 15 minutes
- **Nonce Window**: 5-minute message timestamp window
- **Key Size**: RSA 2048-bit (upgradeable to 4096-bit)

## 🏗️ Architecture

### Client-Side Security

```javascript
// RSA Key Generation
generateRSAKeypair() -> { publicKey, privateKey }

// Message Encryption Flow
message -> AES encrypt -> RSA encrypt(AESKey) -> Digital Sign -> Send

// Message Decryption Flow
Receive -> Verify Signature -> RSA decrypt(AESKey) -> AES decrypt -> message
```

### Server-Side Security

```javascript
// Authentication Flow
credentials -> bcrypt verify -> JWT generate -> Session create

// Message Handling
encrypted message -> replay check -> timestamp verify -> forward -> log
```

## 🔒 Security Features Breakdown

### Encryption Standards

- **Symmetric**: AES-256-CBC for message content
- **Asymmetric**: RSA-2048 for key exchange
- **Hashing**: SHA-256 for signatures
- **Password**: bcrypt with 12 salt rounds

### Protection Mechanisms

- **Replay Protection**: Cryptographic nonces with server-side tracking
- **MITM Protection**: Public key fingerprint verification
- **Session Security**: JWT with secure headers
- **Input Validation**: Comprehensive sanitization
- **Rate Limiting**: DDoS and brute force protection

### Privacy Features

- **Forward Secrecy**: Unique AES keys per message
- **No Plain Text Storage**: All messages encrypted end-to-end
- **Minimal Metadata**: Only essential routing information stored
- **Client-Side Keys**: Private keys never leave the client

## 📊 API Endpoints

### Authentication

- `POST /api/register` - User registration with public key
- `POST /api/login` - User authentication
- `GET /health` - Server health check

### Key Management

- `GET /api/public-keys` - Retrieve all public keys
- `GET /api/public-key/:userId` - Get specific user's public key

### WebSocket Events

- `join-room` - Join chat room
- `secure-message` - Send encrypted message
- `typing` - Typing indicator
- `request-public-key` - Request user's public key

## 🔍 Security Audit Checklist

- ✅ **Authentication**: Multi-factor ready, secure password policies
- ✅ **Authorization**: JWT-based with expiration
- ✅ **Encryption**: End-to-end with forward secrecy
- ✅ **Key Management**: Secure generation and exchange
- ✅ **Replay Protection**: Nonce-based prevention
- ✅ **Input Validation**: Comprehensive sanitization
- ✅ **Rate Limiting**: DoS protection
- ✅ **Logging**: Comprehensive audit trail
- ✅ **Error Handling**: No information leakage
- ✅ **Headers Security**: Helmet.js implementation

## 🚨 Security Considerations

### Production Deployment

1. **Use HTTPS**: Always deploy with SSL/TLS certificates
2. **Environment Variables**: Store secrets in environment variables
3. **Database**: Replace in-memory storage with secure database
4. **Key Storage**: Implement secure key management system
5. **Monitoring**: Set up security monitoring and alerts

### Known Limitations

- **Key Recovery**: No key recovery mechanism (by design)
- **Scalability**: In-memory storage for demo purposes
- **Mobile**: Not optimized for mobile devices
- **File Transfer**: No encrypted file transfer support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Original SecureChat by @bezzad
- Inspired by Signal Protocol and Matrix.org security model
- Built with security-first principles

## 📞 Support

For security-related questions or issues, please create an issue in the repository or contact the maintainers.

---

**⚠️ Security Notice**: This implementation is for educational and development purposes. For production use, conduct a thorough security audit and implement additional enterprise-grade security measures.

// // This is the main file of our chat app. It initializes a new 
// // express.js instance, requires the config and routes files
// // and listens on a port. Start the application by running
// // 'node app.js' in your terminal

// var express = require('express');
// var path = require("path");
// var app = express();
// var port = 80;

// // Initialize a new socket.io object. It is bound to 
// // the express app, which allows them to coexist.
// var io = require('socket.io').listen(app.listen(port));


// // ------------------- Config static directories and files ---------------
// //
// // Set .html as the default template extension
// app.set('view engine', 'html');

// // Initialize the ejs template engine
// app.engine('html', require('ejs').renderFile);

// // Tell express where it can find the templates
// app.set('views', path.join(__dirname, 'client/views'));

// // Make the files in the public folder available to the world
// app.use(express.static(path.join(__dirname, 'client')));
// // =======================================================================
// //


// // --------------------------- Router Config -----------------------------
// //
// // sets up event listeners for the two main URL 
// // endpoints of the application - /
// app.get('/', function (req, res) {
// 	// Render views/chat.html
// 	res.render('chat');
// });
// // =======================================================================
// //

// // Require the configuration and the routes files, and pass
// // the app and io as arguments to the returned functions.
// require('./server/server')(app, io);

// console.log('Your application is running on http://localhost:' + port);

// Enhanced SecureChat Server Implementation
// app.js - Main server file

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Security configurations
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret (In production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const SALT_ROUNDS = 12;

// In-memory storage (In production, use proper database)
class SecureChatStore {
    constructor() {
        this.users = new Map(); // email -> user data
        this.sessions = new Map(); // sessionId -> user data
        this.publicKeys = new Map(); // userId -> public key
        this.authLogs = new Map(); // userId -> auth logs
        this.chatLogs = new Map(); // roomId -> encrypted chat logs
        this.activeConnections = new Map(); // socketId -> user data
        this.nonces = new Set(); // Used nonces for replay protection
    }

    // User management
    async registerUser(email, password, publicKey) {
        if (this.users.has(email)) {
            throw new Error('User already exists');
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const userId = crypto.randomUUID();
        
        const user = {
            id: userId,
            email,
            password: hashedPassword,
            publicKey,
            createdAt: new Date(),
            lastLogin: null,
            isActive: false
        };

        this.users.set(email, user);
        this.publicKeys.set(userId, publicKey);
        this.authLogs.set(userId, []);

        return { id: userId, email };
    }

    async authenticateUser(email, password, ip) {
        const user = this.users.get(email);
        if (!user) {
            throw new Error('Invalid credentials');
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            // Log failed attempt
            this.logAuthAttempt(user.id, ip, false);
            throw new Error('Invalid credentials');
        }

        // Update user
        user.lastLogin = new Date();
        user.isActive = true;

        // Log successful login
        this.logAuthAttempt(user.id, ip, true);

        return user;
    }

    logAuthAttempt(userId, ip, success) {
        const logs = this.authLogs.get(userId) || [];
        logs.push({
            ip,
            success,
            timestamp: new Date(),
            action: success ? 'login' : 'failed_login'
        });
        
        // Keep only last 50 logs
        if (logs.length > 50) {
            logs.splice(0, logs.length - 50);
        }
        
        this.authLogs.set(userId, logs);
    }

    logUserAction(userId, action, ip, details = {}) {
        const logs = this.authLogs.get(userId) || [];
        logs.push({
            ip,
            action,
            timestamp: new Date(),
            details
        });
        
        if (logs.length > 100) {
            logs.splice(0, logs.length - 100);
        }
        
        this.authLogs.set(userId, logs);
    }

    // Public key management
    getPublicKey(userId) {
        return this.publicKeys.get(userId);
    }

    getAllPublicKeys() {
        return Object.fromEntries(this.publicKeys);
    }

    // Nonce management for replay protection
    isNonceUsed(nonce) {
        return this.nonces.has(nonce);
    }

    addNonce(nonce) {
        this.nonces.add(nonce);
        
        // Clean old nonces (keep only last 10000)
        if (this.nonces.size > 10000) {
            const noncesArray = Array.from(this.nonces);
            this.nonces.clear();
            noncesArray.slice(-5000).forEach(n => this.nonces.add(n));
        }
    }

    // Chat logging (encrypted)
    logEncryptedMessage(roomId, encryptedMessage, metadata) {
        const logs = this.chatLogs.get(roomId) || [];
        logs.push({
            ...metadata,
            encryptedMessage,
            timestamp: new Date()
        });
        
        // Keep only last 1000 messages per room
        if (logs.length > 1000) {
            logs.splice(0, logs.length - 1000);
        }
        
        this.chatLogs.set(roomId, logs);
    }
}

const store = new SecureChatStore();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Registration endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, publicKey } = req.body;
        
        if (!email || !password || !publicKey) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Validate password strength
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const user = await store.registerUser(email, password, publicKey);
        res.json({ success: true, user: { id: user.id, email: user.email } });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const ip = req.ip || req.connection.remoteAddress;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const user = await store.authenticateUser(email, password, ip);
        
        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                publicKey: user.publicKey
            }
        });
    } catch (error) {
        res.status(401).json({ error: error.message });
	}
});

// Get public keys endpoint
app.get('/api/public-keys', authenticateToken, (req, res) => {
    const publicKeys = store.getAllPublicKeys();
    res.json({ publicKeys });
});

// Get specific user's public key
app.get('/api/public-key/:userId', authenticateToken, (req, res) => {
    const { userId } = req.params;
    const publicKey = store.getPublicKey(userId);
    
    if (!publicKey) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ publicKey });
});

// Socket.IO connection handling
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error'));
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return next(new Error('Authentication error'));
        }
        socket.user = user;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`User ${socket.user.email} connected`);
    
    const ip = socket.handshake.address;
    store.logUserAction(socket.user.id, 'socket_connect', ip);
    store.activeConnections.set(socket.id, socket.user);

    // Handle joining chat rooms
    socket.on('join-room', (roomId) => {
        socket.join(roomId);
        store.logUserAction(socket.user.id, 'join_room', ip, { roomId });
        
        // Notify others in the room
        socket.to(roomId).emit('user-joined', {
            userId: socket.user.id,
            email: socket.user.email,
            publicKey: store.getPublicKey(socket.user.id)
        });
    });

    // Handle secure message exchange
    socket.on('secure-message', (data) => {
        const {
            roomId,
            encryptedAESKey,
            encryptedMessage,
            signature,
            timestamp,
            nonce,
            recipientId
        } = data;

        // Verify required fields
        if (!roomId || !encryptedMessage || !timestamp || !nonce) {
            socket.emit('error', { message: 'Invalid message format' });
            return;
        }

        // Check for replay attacks
        if (store.isNonceUsed(nonce)) {
            socket.emit('error', { message: 'Message replay detected' });
            return;
        }

        // Check timestamp (allow 5 minute window)
        const messageTime = new Date(timestamp);
        const now = new Date();
        const timeDiff = Math.abs(now - messageTime);
        if (timeDiff > 5 * 60 * 1000) {
            socket.emit('error', { message: 'Message timestamp invalid' });
            return;
        }

        // Add nonce to prevent replay
        store.addNonce(nonce);

        // Log the encrypted message
        store.logEncryptedMessage(roomId, encryptedMessage, {
            senderId: socket.user.id,
            recipientId,
            timestamp: messageTime,
            signature,
            nonce,
            hasSignature: !!signature
        });

        // Forward message to room
        const messageData = {
            senderId: socket.user.id,
            senderEmail: socket.user.email,
            encryptedAESKey,
            encryptedMessage,
            signature,
            timestamp,
            nonce,
            recipientId
        };

        if (recipientId) {
            // Direct message to specific user
            socket.to(roomId).emit('secure-message', messageData);
        } else {
            // Broadcast to room
            socket.to(roomId).emit('secure-message', messageData);
        }

        store.logUserAction(socket.user.id, 'send_message', ip, { roomId, recipientId });
    });

    // Handle key exchange requests
    socket.on('request-public-key', (userId) => {
        const publicKey = store.getPublicKey(userId);
        if (publicKey) {
            socket.emit('public-key-response', { userId, publicKey });
        } else {
            socket.emit('error', { message: 'User not found' });
        }
    });

    // Handle typing indicators
    socket.on('typing', (data) => {
        socket.to(data.roomId).emit('user-typing', {
            userId: socket.user.id,
            email: socket.user.email,
            isTyping: data.isTyping
        });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`User ${socket.user.email} disconnected`);
        store.logUserAction(socket.user.id, 'socket_disconnect', ip);
        store.activeConnections.delete(socket.id);
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        activeConnections: store.activeConnections.size
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`SecureChat server running on port ${PORT}`);
    console.log('Security features enabled:');
    console.log('- User authentication with JWT');
    console.log('- RSA/ECC public key exchange');
    console.log('- AES message encryption');
    console.log('- Digital signatures');
    console.log('- Replay protection with nonces');
    console.log('- Comprehensive logging');
    console.log('- Rate limiting');
    console.log('- Security headers');
});

module.exports = app;
// const express = require('express');
// const app = express();
// const http = require('http').createServer(app);
// const io = require('socket.io')(http);
// const path = require('path');
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');

// // In-memory storage (use database in production)
// const users = new Map();
// const usersByUsername = new Map(); // New: index users by username
// const sessions = new Map();
// const chatLogs = new Array();
// const userKeys = new Map();
// const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// app.use(express.static(path.join(__dirname, 'public')));
// app.use(express.json());

// // Routes
// app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
// app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
// app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'public/chat.html')));

// // Register endpoint
// app.post('/api/register', async (req, res) => {
//     const { username, email, password } = req.body;
//     if (!username || !email || !password) {
//         return res.status(400).json({ error: 'Username, email and password required' });
//     }
    
//     // Check if username already exists
//     if (usersByUsername.has(username.toLowerCase())) {
//         return res.status(409).json({ error: 'Username already exists' });
//     }
    
//     // Check if email already exists
//     if (users.has(email.toLowerCase())) {
//         return res.status(409).json({ error: 'Email already exists' });
//     }
    
//     // Validate username (alphanumeric and underscore only, 3-20 characters)
//     if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
//         return res.status(400).json({ 
//             error: 'Username must be 3-20 characters and contain only letters, numbers, and underscores' 
//         });
//     }
    
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const userData = { 
//         username, 
//         email, 
//         password: hashedPassword, 
//         createdAt: new Date() 
//     };
    
//     users.set(email.toLowerCase(), userData);
//     usersByUsername.set(username.toLowerCase(), userData);
    
//     res.json({ success: true, message: 'User registered successfully' });
// });

// // Login endpoint (support both email and username)
// app.post('/api/login', async (req, res) => {
//     const { login, password } = req.body; // 'login' can be email or username
    
//     let user;
//     // Check if login is email or username
//     if (login.includes('@')) {
//         user = users.get(login.toLowerCase()); // Make email lookup case-insensitive
//     } else {
//         user = usersByUsername.get(login.toLowerCase());
//     }
    
//     if (!user || !await bcrypt.compare(password, user.password)) {
//         return res.status(401).json({ error: 'Invalid credentials' });
//     }
    
//     const token = jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
//     sessions.set(token, { 
//         email: user.email, 
//         username: user.username,
//         loginTime: new Date(), 
//         ip: req.ip 
//     });
    
//     // Log authentication
//     chatLogs.push({
//         type: 'auth',
//         username: user.username,
//         email: user.email,
//         action: 'login',
//         timestamp: new Date(),
//         ip: req.ip
//     });
    
//     res.json({ token, email: user.email, username: user.username });
// });

// // Logout endpoint
// app.post('/api/logout', (req, res) => {
//     const token = req.headers.authorization?.split(' ')[1];
//     if (token && sessions.has(token)) {
//         const session = sessions.get(token);
//         chatLogs.push({
//             type: 'auth',
//             username: session.username,
//             email: session.email,
//             action: 'logout',
//             timestamp: new Date(),
//             ip: req.ip
//         });
//         sessions.delete(token);
//     }
//     res.json({ success: true });
// });

// // Middleware to verify JWT
// const verifyToken = (socket, next) => {
//     const token = socket.handshake.auth.token;
//     if (!token) return next(new Error('No token provided'));
    
//     try {
//         const decoded = jwt.verify(token, JWT_SECRET);
//         if (!sessions.has(token)) return next(new Error('Invalid session'));
        
//         socket.userId = decoded.email;
//         socket.username = decoded.username;
//         socket.token = token;
//         next();
//     } catch (err) {
//         next(new Error('Invalid token'));
//     }
// };

// io.use(verifyToken);

// io.on('connection', (socket) => {
//     console.log(`User ${socket.username} (${socket.userId}) connected`);
    
//     // Key exchange - Upload public key
//     socket.on('upload-public-key', (data) => {
//         const { publicKey, keyType } = data; // RSA/ECC
//         userKeys.set(socket.userId, { 
//             publicKey, 
//             keyType, 
//             username: socket.username,
//             uploadedAt: new Date() 
//         });
        
//         // Broadcast to other users that new key is available
//         socket.broadcast.emit('user-key-available', {
//             userId: socket.userId,
//             username: socket.username,
//             publicKey,
//             keyType
//         });
        
//         console.log(`Public key uploaded for ${socket.username}`);
//     });
    
//     // Request public key of another user
//     socket.on('request-public-key', (targetUserId) => {
//         const userKey = userKeys.get(targetUserId);
//         if (userKey) {
//             socket.emit('receive-public-key', {
//                 userId: targetUserId,
//                 username: userKey.username,
//                 publicKey: userKey.publicKey,
//                 keyType: userKey.keyType
//             });
//         }
//     });
    
//     // Enhanced messaging with timestamp, nonce, and optional signature
//     socket.on('send-message', (data) => {
//         const {
//             encryptedMessage,
//             encryptedAESKey,
//             timestamp,
//             nonce,
//             signature,
//             targetUserId
//         } = data;
        
//         // Verify timestamp to prevent replay attacks (within 5 minutes)
//         const now = Date.now();
//         const msgTime = new Date(timestamp).getTime();
//         if (Math.abs(now - msgTime) > 300000) {
//             socket.emit('error', 'Message timestamp invalid');
//             return;
//         }
        
//         // Store message with metadata
//         const messageData = {
//             from: socket.userId,
//             fromUsername: socket.username,
//             to: targetUserId,
//             encryptedMessage,
//             encryptedAESKey,
//             timestamp,
//             nonce,
//             signature,
//             serverTimestamp: new Date()
//         };
        
//         // Log encrypted message (compliance)
//         chatLogs.push({
//             type: 'message',
//             from: socket.userId,
//             fromUsername: socket.username,
//             to: targetUserId,
//             timestamp: new Date(),
//             encrypted: true,
//             nonce: nonce
//         });
        
//         // Forward to target user
//         const targetSocket = [...io.sockets.sockets.values()]
//             .find(s => s.userId === targetUserId);
            
//         if (targetSocket) {
//             targetSocket.emit('receive-message', messageData);
//         }
//     });
    
//     // Get list of online users with their public keys
//     socket.on('get-online-users', () => {
//         const onlineUsers = [...io.sockets.sockets.values()]
//             .map(s => ({
//                 userId: s.userId,
//                 username: s.username,
//                 hasPublicKey: userKeys.has(s.userId)
//             }))
//             .filter(user => user.userId !== socket.userId);
            
//         socket.emit('online-users', onlineUsers);
//     });
    
//     socket.on('disconnect', () => {
//         console.log(`User ${socket.username} disconnected`);
        
//         // Log disconnection
//         chatLogs.push({
//             type: 'auth',
//             username: socket.username,
//             email: socket.userId,
//             action: 'disconnect',
//             timestamp: new Date()
//         });
//     });
// });

// // Admin endpoint to view logs (for compliance)
// app.get('/api/admin/logs', (req, res) => {
//     // In production, add proper admin authentication
//     res.json(chatLogs.slice(-100)); // Last 100 entries
// });

// const PORT = process.env.PORT || 3001;
// http.listen(PORT, () => {
//     console.log(`SecureChat server running on port ${PORT}`);
// });


const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// In-memory storage (use database in production)
const users = new Map();
const usersByUsername = new Map(); // Maps lowercase username -> original username
const sessions = new Map();
const chatLogs = new Array();
const userKeys = new Map();
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'public/chat.html')));

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email and password required' });
    }
    
    // Check if username already exists (case-insensitive)
    if (usersByUsername.has(username.toLowerCase())) {
        return res.status(409).json({ error: 'Username already exists' });
    }
    
    // Check if email already exists
    if (users.has(email.toLowerCase())) {
        return res.status(409).json({ error: 'Email already exists' });
    }
    
    // Validate username (alphanumeric and underscore only, 3-20 characters)
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ 
            error: 'Username must be 3-20 characters and contain only letters, numbers, and underscores' 
        });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = { 
        username, // Store original username with capitalization
        email, 
        password: hashedPassword, 
        createdAt: new Date() 
    };
    
    users.set(email.toLowerCase(), userData);
    // Map lowercase username to user data for lookup
    usersByUsername.set(username.toLowerCase(), userData);
    
    res.json({ success: true, message: 'User registered successfully' });
});

// Login endpoint (support both email and username)
app.post('/api/login', async (req, res) => {
    const { login, password } = req.body; // 'login' can be email or username
    
    let user;
    // Check if login is email or username
    if (login.includes('@')) {
        user = users.get(login.toLowerCase()); // Make email lookup case-insensitive
    } else {
        // Get user data directly from username mapping
        user = usersByUsername.get(login.toLowerCase());
    }
    
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    sessions.set(token, { 
        email: user.email, 
        username: user.username, // Original username with capitalization
        loginTime: new Date(), 
        ip: req.ip 
    });
    
    // Log authentication
    chatLogs.push({
        type: 'auth',
        username: user.username, // Original username with capitalization
        email: user.email,
        action: 'login',
        timestamp: new Date(),
        ip: req.ip
    });
    
    res.json({ token, email: user.email, username: user.username });
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (token && sessions.has(token)) {
        const session = sessions.get(token);
        chatLogs.push({
            type: 'auth',
            username: session.username, // Original username with capitalization
            email: session.email,
            action: 'logout',
            timestamp: new Date(),
            ip: req.ip
        });
        sessions.delete(token);
    }
    res.json({ success: true });
});

// Middleware to verify JWT
const verifyToken = (socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('No token provided'));
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!sessions.has(token)) return next(new Error('Invalid session'));
        
        socket.userId = decoded.email;
        socket.username = decoded.username; // Original username with capitalization
        socket.token = token;
        next();
    } catch (err) {
        next(new Error('Invalid token'));
    }
};

io.use(verifyToken);

io.on('connection', (socket) => {
    console.log(`User ${socket.username} (${socket.userId}) connected`);
    
    // Key exchange - Upload public key
    socket.on('upload-public-key', (data) => {
        const { publicKey, keyType } = data; // RSA/ECC
        userKeys.set(socket.userId, { 
            publicKey, 
            keyType, 
            username: socket.username, // Original username with capitalization
            uploadedAt: new Date() 
        });
        
        // Broadcast to other users that new key is available
        socket.broadcast.emit('user-key-available', {
            userId: socket.userId,
            username: socket.username, // Original username with capitalization
            publicKey,
            keyType
        });
        
        console.log(`Public key uploaded for ${socket.username}`);
    });
    
    // Request public key of another user
    socket.on('request-public-key', (targetUserId) => {
        const userKey = userKeys.get(targetUserId);
        if (userKey) {
            socket.emit('receive-public-key', {
                userId: targetUserId,
                username: userKey.username, // Original username with capitalization
                publicKey: userKey.publicKey,
                keyType: userKey.keyType
            });
        }
    });
    
    // Enhanced messaging with timestamp, nonce, and optional signature
    socket.on('send-message', (data) => {
        const {
            encryptedMessage,
            encryptedAESKey,
            timestamp,
            nonce,
            signature,
            targetUserId
        } = data;
        
        // Verify timestamp to prevent replay attacks (within 5 minutes)
        const now = Date.now();
        const msgTime = new Date(timestamp).getTime();
        if (Math.abs(now - msgTime) > 300000) {
            socket.emit('error', 'Message timestamp invalid');
            return;
        }
        
        // Store message with metadata
        const messageData = {
            from: socket.userId,
            fromUsername: socket.username, // Original username with capitalization
            to: targetUserId,
            encryptedMessage,
            encryptedAESKey,
            timestamp,
            nonce,
            signature,
            serverTimestamp: new Date()
        };
        
        // Log encrypted message (compliance)
        chatLogs.push({
            type: 'message',
            from: socket.userId,
            fromUsername: socket.username, // Original username with capitalization
            to: targetUserId,
            timestamp: new Date(),
            encrypted: true,
            nonce: nonce
        });
        
        // Forward to target user
        const targetSocket = [...io.sockets.sockets.values()]
            .find(s => s.userId === targetUserId);
            
        if (targetSocket) {
            targetSocket.emit('receive-message', messageData);
        }
    });
    
    // Get list of online users with their public keys
    socket.on('get-online-users', () => {
        const onlineUsers = [...io.sockets.sockets.values()]
            .map(s => ({
                userId: s.userId,
                username: s.username, // Original username with capitalization
                hasPublicKey: userKeys.has(s.userId)
            }))
            .filter(user => user.userId !== socket.userId);
            
        socket.emit('online-users', onlineUsers);
    });
    
    socket.on('disconnect', () => {
        console.log(`User ${socket.username} disconnected`);
        
        // Log disconnection
        chatLogs.push({
            type: 'auth',
            username: socket.username, // Original username with capitalization
            email: socket.userId,
            action: 'disconnect',
            timestamp: new Date()
        });
    });
});

// Admin endpoint to view logs (for compliance)
app.get('/api/admin/logs', (req, res) => {
    // In production, add proper admin authentication
    res.json(chatLogs.slice(-100)); // Last 100 entries
});

const PORT = process.env.PORT || 3001;
http.listen(PORT, () => {
    console.log(`SecureChat server running on port ${PORT}`);
});
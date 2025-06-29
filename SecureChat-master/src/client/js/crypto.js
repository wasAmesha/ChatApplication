// /* Cryptology used Forge.js lib to encrypt/decrypt by symmetric or asymmetric algorithms */
// "use strict";

// // Create the encryption object for asymmetric RSA algorithm.
// var rsa = new JSEncrypt();

// // define the characters to pick from
// var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz*&-%/!?*+=()";

// // create a key for symmetric encryption
// // pass in the desired length of your key
// function generateKey(keyLength) {
//     var randomstring = '';

//     for (var i = 0; i < keyLength; i++) {
//         var rnum = Math.floor(Math.random() * chars.length);
//         randomstring += chars.substring(rnum, rnum + 1);
//     }
//     return randomstring;
// }

// // create the pair public and private key for asymmetric encryption
// var generateKeyPair = function () {
//     var crypt = new JSEncrypt({ default_key_size: 1024 });
//     crypt.getKey();

//     return {
//         privateKey: crypt.getPrivateKey(),
//         publicKey: crypt.getPublicKey()
//     }
// };

// // hasing text by sha-512 algorithm
// String.prototype.getHash = function () {
//     return CryptoJS.SHA512(this).toString();
// }

// // symmetric 3DES encryption
// String.prototype.symEncrypt = function (pass) {
//     return CryptoJS.TripleDES.encrypt(this, pass).toString();
// }

// // symmetric 3DES decryption
// String.prototype.symDecrypt = function (pass) {
//     var bytes = CryptoJS.TripleDES.decrypt(this, pass);
//     return bytes.toString(CryptoJS.enc.Utf8);
// }

// // asymmetric RSA encryption
// String.prototype.asymEncrypt = function (publicKey) {
//     rsa.setPublicKey(publicKey);
//     return rsa.encrypt(this);
// }

// // asymmetric RSA decryption
// String.prototype.asymDecrypt = function (privateKey) {
//     rsa.setPrivateKey(privateKey); // Set the private.
//     return rsa.decrypt(this);
// }

// function getCipherKeys() {
//     var keys = localStorage.cipherKeys; // read keys json 
//     if (keys == null) {
//         keys = generateKeyPair();

//         // store keys as json in localStorage
//         localStorage.cipherKeys = JSON.stringify(keys);
//         return keys;
//     }

//     return JSON.parse(keys);
// }

// security/config.js - Security Configuration Module

const crypto = require('crypto');

/**
 * Security Configuration for Enhanced SecureChat
 * This module contains all security-related settings and utilities
 */

const SecurityConfig = {
    // Authentication Settings
    auth: {
        // JWT Configuration
        jwt: {
            secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
            expiresIn: '24h',
            algorithm: 'HS256',
            issuer: 'SecureChat-Enhanced',
            audience: 'SecureChat-Users'
        },
        
        // Password Policy
        password: {
            minLength: 8,
            maxLength: 128,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecialChars: false,
            saltRounds: 12
        },
        
        // Session Management
        session: {
            maxConcurrentSessions: 5,
            inactivityTimeout: 30 * 60 * 1000, // 30 minutes
            refreshTokenExpiry: '7d'
        }
    },

    // Encryption Settings
    encryption: {
        // RSA Configuration
        rsa: {
            keySize: 2048, // Can be upgraded to 4096 for higher security
            publicExponent: 65537,
            hashAlgorithm: 'sha256'
        },
        
        // AES Configuration
        aes: {
            keySize: 256,
            mode: 'CBC',
            ivLength: 16
        },
        
        // ECC Configuration (alternative to RSA)
        ecc: {
            curve: 'secp256r1', // P-256
            hashAlgorithm: 'sha256'
        }
    },

    // Message Security
    messaging: {
        // Timestamp validation
        timestamp: {
            maxClockSkew: 5 * 60 * 1000, // 5 minutes
            replayWindow: 10 * 60 * 1000  // 10 minutes
        },
        
        // Nonce management
        nonce: {
            length: 16, // bytes
            maxCacheSize: 10000,
            cleanupInterval: 60 * 60 * 1000 // 1 hour
        },
        
        // Message limits
        limits: {
            maxMessageSize: 10 * 1024, // 10KB
            maxMessagesPerMinute: 60,
            maxRoomSize: 100
        }
    },

    // Rate Limiting
    rateLimiting: {
        // General API rate limiting
        api: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100, // requests per window
            skipSuccessfulRequests: false
        },
        
        // Authentication specific
        auth: {
            windowMs: 15 * 60 * 1000,
            max: 10, // login attempts per window
            skipSuccessfulRequests: true
        },
        
        // WebSocket rate limiting
        websocket: {
            messagesPerSecond: 10,
            burstSize: 20
        }
    },

    // Security Headers
    headers: {
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'", "ws:", "wss:"],
                fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"]
            }
        },
        hsts: {
            maxAge: 31536000, // 1 year
            includeSubDomains: true,
            preload: true
        }
    },

    // Logging Configuration
    logging: {
        // What to log
        events: {
            authentication: true,
            keyExchange: true,
            messagesSent: true,
            securityEvents: true,
            errors: true
        },
        
        // Log retention
        retention: {
            authLogs: 90 * 24 * 60 * 60 * 1000, // 90 days
            chatLogs: 30 * 24 * 60 * 60 * 1000, // 30 days
            securityLogs: 365 * 24 * 60 * 60 * 1000 // 1 year
        },
        
        // Log levels
        levels: {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3
        }
    },

    // Network Security
    network: {
        // CORS settings
        cors: {
            origin: process.env.NODE_ENV === 'production' 
                ? process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com']
                : ['http://localhost:3000', 'http://127.0.0.1:3000'],
            credentials: true,
            optionsSuccessStatus: 200
        },
        
        // TLS settings (for production
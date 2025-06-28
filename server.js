/**
 * Consent Cryptographic Server
 * Handles secure consent processing with RSA key exchange
 * and RSA digital signatures for authentication
 */

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cryptoUtils = require('./crypto-utils');

// Configuration
const CONFIG = {
	PORT: process.env.PORT || 3000,
	RSA_KEY_SIZE: 2048,
	CORS_ORIGIN: '*' // Restrict in production
};

class ConsentCryptoServer {
	constructor() {
		this.app = express();
		this.serverKeys = {
			rsaPrivateSigningKey: null,
			rsaPublicSigningKey: null
		};

		this.setupMiddleware();
		this.setupRoutes();
		this.initializeKeys();
	}

	/**
	 * Initialize server cryptographic keys
	 */
	initializeKeys() {
		console.log('* Initializing server cryptographic keys...');

		try {
			// Generate RSA signing key pair
			this.generateRSASigningKeys();

			console.log('✅ Server keys initialized successfully');
		} catch (error) {
			console.error('❌ Failed to initialize server keys:', error);
			process.exit(1);
		}
	}

	/**
	 * Generate RSA key pair for digital signatures
	 */
	generateRSASigningKeys() {
		const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
			modulusLength: CONFIG.RSA_KEY_SIZE,
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem'
			}
		});

		this.serverKeys.rsaPrivateSigningKey = privateKey;
		this.serverKeys.rsaPublicSigningKey = publicKey;

		console.log(`📝 RSA Signing Key Size: ${CONFIG.RSA_KEY_SIZE} bits`);
	}

	/**
	 * Setup Express middleware
	 */
	setupMiddleware() {
		this.app.use(bodyParser.json());
		this.app.use(express.static('public'));
		this.app.use(cors({
			origin: CONFIG.CORS_ORIGIN,
			methods: ['GET', 'POST'],
			allowedHeaders: ['Content-Type']
		}));

		// Request logging
		this.app.use((req, res, next) => {
			console.log(`* ${req.method} ${req.path} - ${new Date().toISOString()}`);
			next();
		});
	}

	/**
	 * Setup API routes
	 */
	setupRoutes() {
		// Get RSA public key for client key exchange
		this.app.get('/api/publickey', (req, res) => {
			try {
				const publicKeyData = this.serverKeys.rsaPublicSigningKey;
				res.json(publicKeyData);
				console.log('* RSA public key sent to client');
			} catch (error) {
				console.error('❌ Error sending RSA public key:', error);
				res.status(500).json({ error: 'Failed to get RSA public key' });
			}
		});

		// Process consent from client
		this.app.post('/api/consent', (req, res) => {
			try {
				console.log('📥 Processing consent package...');
				const result = this.processClientConsent(req.body);

				res.json({
					success: true,
					serverSignature: result.serverSignature,
					message: 'Signed Consent processed successfully'
				});

				console.log('✅ Consent processed and signed');
			} catch (error) {
				console.error('❌ Error processing consent:', error);
				res.status(400).json({
					success: false,
					error: error.message
				});
			}
		});

		// Health check endpoint
		this.app.get('/health', (req, res) => {
			res.json({
				status: 'healthy',
				timestamp: new Date().toISOString(),
				version: '1.0.0'
			});
		});
	}

	/**
	 * Process encrypted consent package from client
	 * @param {Object} clientPackage - Encrypted consent package
	 * @returns {Object} Processing result with server signature
	 */
	processClientConsent(clientPackage) {
		// Validate input
		this.validateClientPackage(clientPackage);

		const {
			clientSignature,
			clientPublicSigningKey,
			consentData
		} = clientPackage;

		console.log('🔍 Validating client package...');

		// Step 1: Verify client's digital signature
		this.verifyClientSignature(consentData, clientSignature, clientPublicSigningKey);
		console.log('✅ Client signature verified');

		// Step 2: Sign the consent with server's key
		const consentDataString = JSON.stringify(consentData);
		const serverSignature = this.signConsentData(consentDataString);
		console.log('📝 Server signature generated');

		return {
			serverSignature: serverSignature,
		};
	}

	/**
	 * Validate client package structure
	 */
	validateClientPackage(clientPackage) {
		const requiredFields = ['clientSignature', 'clientPublicSigningKey', 'consentData'];

		for (const field of requiredFields) {
			if (!clientPackage[field]) {
				throw new Error(`Missing required field: ${field}`);
			}
		}
	}

	/**
	 * Verify client's digital signature
	 */
	verifyClientSignature(consentData, clientSignature, clientPublicSigningKey) {
		const consentDataString = JSON.stringify(consentData);

		const isValid = cryptoUtils.verifySignature(
			clientPublicSigningKey,
			consentDataString,
			clientSignature
		);

		if (!isValid) {
			throw new Error('Invalid client signature - consent may have been tampered with');
		}
	}

	/**
	 * Sign consent data with server's RSA key
	 */
	signConsentData(consent) {
		return cryptoUtils.signData(this.serverKeys.rsaPrivateSigningKey, consent);
	}

	/**
	 * Start the server
	 */
	start() {
		this.app.listen(CONFIG.PORT, () => {
			console.log('\n🚀 Consent Cryptographic Server Started');
			console.log(`📡 Server listening on port ${CONFIG.PORT}`);
			console.log(`🔒 Security: RSA ${CONFIG.RSA_KEY_SIZE}-bit key exchange + RSA ${CONFIG.RSA_KEY_SIZE}-bit signing`);
			console.log(`🌐 CORS Origin: ${CONFIG.CORS_ORIGIN}`);
			console.log('─'.repeat(50));
		});
	}
}

// Error handling
process.on('uncaughtException', (error) => {
	console.error('💥 Uncaught Exception:', error);
	process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
	console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
	process.exit(1);
});

// Initialize and start server
const server = new ConsentCryptoServer();
server.start();

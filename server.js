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
			rsaPrivateKeyExchangeKey: null,
			rsaPublicKeyExchangeKey: null,
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
			// Generate RSA key exchange key pair
			this.generateRSAKeyExchangeKeys();

			// Generate RSA signing key pair
			this.generateRSASigningKeys();

			console.log('✅ Server keys initialized successfully');
		} catch (error) {
			console.error('❌ Failed to initialize server keys:', error);
			process.exit(1);
		}
	}

	/**
	 * Generate RSA key pair for key exchange (encryption/decryption)
	 */
	generateRSAKeyExchangeKeys() {
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

		this.serverKeys.rsaPrivateKeyExchangeKey = privateKey;
		this.serverKeys.rsaPublicKeyExchangeKey = publicKey;

		console.log(`🔑 RSA Key Exchange Size: ${CONFIG.RSA_KEY_SIZE} bits`);
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
				const publicKeyData = this.getPublicKeyForClient();
				res.json(publicKeyData);
				console.log('📤 RSA public key sent to client');
			} catch (error) {
				console.error('❌ Error sending RSA public key:', error);
				res.status(500).json({ error: 'Failed to get RSA public key' });
			}
		});

		// Process encrypted consent from client
		this.app.post('/api/consent', (req, res) => {
			try {
				console.log('📥 Processing encrypted consent package...');
				const result = this.processClientConsent(req.body);

				res.json({
					success: true,
					serverSignature: result.serverSignature,
					message: 'Consent processed successfully'
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

		// Fallback endpoint for simple consent (when extension not available)
		this.app.post('/api/consent-simple', (req, res) => {
			console.log('📝 Simple consent received (no encryption):', req.body);
			res.json({
				success: true,
				message: 'Consent received without cryptographic verification'
			});
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
	 * Get RSA public key for client
	 * @returns {Object} RSA public key information
	 */
	getPublicKeyForClient() {
		if (!this.serverKeys.rsaPublicKeyExchangeKey) {
			throw new Error('Server keys not initialized');
		}

		return {
			publicKey: this.serverKeys.rsaPublicKeyExchangeKey,
			keySize: CONFIG.RSA_KEY_SIZE
		};
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
			encryptedConsent,
			encryptedSymmetricKey,
			clientSignature,
			clientPublicSigningKey
		} = clientPackage;

		console.log('🔍 Validating client package...');

		// Step 1: Decrypt the symmetric key using server's RSA private key
		const symmetricKey = this.decryptSymmetricKey(encryptedSymmetricKey);
		console.log('🔓 Symmetric key decrypted');

		// Step 2: Verify client's digital signature
		this.verifyClientSignature(encryptedConsent, clientSignature, clientPublicSigningKey);
		console.log('✅ Client signature verified');

		// Step 3: Decrypt and validate consent
		const decryptedConsent = this.decryptAndValidateConsent(symmetricKey, encryptedConsent);
		console.log('🔓 Consent decrypted:', decryptedConsent);

		// Step 4: Sign the consent with server's key
		const serverSignature = this.signConsentData(encryptedConsent);
		console.log('📝 Server signature generated');

		return {
			symmetricKey: symmetricKey.toString('hex'),
			serverSignature: serverSignature,
			consentData: decryptedConsent
		};
	}

	/**
	 * Validate client package structure
	 */
	validateClientPackage(clientPackage) {
		const requiredFields = ['encryptedConsent', 'encryptedSymmetricKey', 'clientSignature', 'clientPublicSigningKey'];

		for (const field of requiredFields) {
			if (!clientPackage[field]) {
				throw new Error(`Missing required field: ${field}`);
			}
		}

		// Validate encrypted consent structure
		const { encryptedConsent } = clientPackage;
		if (!encryptedConsent.ciphertext || !encryptedConsent.iv || !encryptedConsent.tag) {
			throw new Error('Invalid encrypted consent structure');
		}
	}

	/**
	 * Decrypt symmetric key using RSA private key
	 */
	decryptSymmetricKey(encryptedSymmetricKeyHex) {
		try {
			const encryptedSymmetricKey = Buffer.from(encryptedSymmetricKeyHex, 'hex');

			// Decrypt using RSA-OAEP
			const decryptedKey = crypto.privateDecrypt({
				key: this.serverKeys.rsaPrivateKeyExchangeKey,
				padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash: 'sha256'
			}, encryptedSymmetricKey);

			return decryptedKey;
		} catch (error) {
			throw new Error(`Failed to decrypt symmetric key: ${error.message}`);
		}
	}

	/**
	 * Verify client's digital signature
	 */
	verifyClientSignature(encryptedConsent, clientSignature, clientPublicSigningKey) {
		// Prepare data that was signed by client
		const dataToVerify = encryptedConsent.iv + encryptedConsent.ciphertext + encryptedConsent.tag;

		const isValid = cryptoUtils.verifySignature(
			clientPublicSigningKey,
			dataToVerify,
			clientSignature
		);

		if (!isValid) {
			throw new Error('Invalid client signature - consent may have been tampered with');
		}
	}

	/**
	 * Decrypt and validate consent data
	 */
	decryptAndValidateConsent(symmetricKey, encryptedConsent) {
		try {
			const decryptedConsent = cryptoUtils.decryptConsent(symmetricKey, encryptedConsent);

			// Basic validation of consent structure
			if (!decryptedConsent || typeof decryptedConsent !== 'object') {
				throw new Error('Invalid consent data structure');
			}

			// Check for required consent fields
			if (!decryptedConsent.hasOwnProperty('confirmed') || !decryptedConsent.timestamp) {
				throw new Error('Missing required consent fields');
			}

			return decryptedConsent;
		} catch (error) {
			throw new Error(`Failed to decrypt consent: ${error.message}`);
		}
	}

	/**
	 * Sign consent data with server's RSA key
	 */
	signConsentData(encryptedConsent) {
		// Sign the encrypted consent data (not the decrypted version for privacy)
		const dataToSign = encryptedConsent.ciphertext + encryptedConsent.iv + encryptedConsent.tag;

		return cryptoUtils.signData(this.serverKeys.rsaPrivateSigningKey, dataToSign);
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

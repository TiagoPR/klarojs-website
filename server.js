/**
 * Consent Cryptographic Server with JWS
 * Handles secure consent processing with single JWS for entire transaction
 */

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

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

		// Process consent JWS from client
		this.app.post('/api/consent', (req, res) => {
			try {
				console.log('📥 Processing consent JWS...');
				const result = this.processClientJWS(req.body.jws);

				res.json({
					success: true,
					serverSignedJWS: result.serverSignedJWS,
					message: 'JWS processed and server-signed successfully'
				});

				console.log('✅ JWS processed and server-signed');
			} catch (error) {
				console.error('❌ Error processing JWS:', error);
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
	 * Process client JWS and return server-signed JWS
	 * @param {string} clientJWS - JWS from client
	 * @returns {Object} Processing result with server-signed JWS
	 */
	processClientJWS(clientJWS) {
		console.log('🔍 Validating client JWS...');

		// Log the incoming client JWS
		this.logJWSToken(clientJWS, 'Incoming Client JWS');

		// Step 1: Parse and validate client JWS
		const clientPayload = this.parseAndValidateClientJWS(clientJWS);
		console.log('✅ Client JWS verified');

		// Step 2: Create server-signed JWS with complete transaction data
		const serverSignedJWS = this.createServerSignedJWS(clientPayload);
		console.log('📝 Server JWS created');

		// Log the server-signed JWS
		this.logJWSToken(serverSignedJWS, 'Server-Signed JWS');

		return {
			serverSignedJWS: serverSignedJWS
		};
	}

	/**
	 * Parse and validate client JWS
	 */
	parseAndValidateClientJWS(jws) {
		const parts = jws.split('.');
		if (parts.length !== 3) {
			throw new Error('Invalid JWS format');
		}

		const [encodedHeader, encodedPayload, encodedSignature] = parts;

		// Decode header
		const headerBuffer = this.base64UrlDecode(encodedHeader);
		const header = JSON.parse(headerBuffer.toString());

		if (header.alg !== 'PS256') {
			throw new Error('Unsupported algorithm');
		}

		// Decode payload
		const payloadBuffer = this.base64UrlDecode(encodedPayload);
		const payload = JSON.parse(payloadBuffer.toString());

		// Verify client signature
		const signingInput = `${encodedHeader}.${encodedPayload}`;
		const signatureBuffer = this.base64UrlDecode(encodedSignature);

		const isValid = this.verifyClientSignature(
			payload.clientPublicKey,
			signingInput,
			signatureBuffer
		);

		if (!isValid) {
			throw new Error('Invalid client signature');
		}

		return payload;
	}

	/**
	 * Create server-signed JWS containing the complete transaction
	 */
	createServerSignedJWS(clientPayload) {
		// Server JWS Header
		const serverHeader = {
			alg: "PS256",
			typ: "JWT",
			kid: "server-key"
		};

		// Server JWS Payload - contains original client payload + server metadata
		const serverPayload = {
			...clientPayload, // Include all client data
			serverTimestamp: Math.floor(Date.now() / 1000),
			serverIssuer: "consent-server",
			transactionStatus: "verified"
		};

		// Encode header and payload
		const encodedHeader = this.base64UrlEncode(JSON.stringify(serverHeader));
		const encodedPayload = this.base64UrlEncode(JSON.stringify(serverPayload));

		// Create signing input
		const signingInput = `${encodedHeader}.${encodedPayload}`;

		// Sign with server private key
		const signature = this.signData(signingInput);
		const encodedSignature = this.base64UrlEncode(signature);

		// Return complete server-signed JWS
		return `${signingInput}.${encodedSignature}`;
	}

	/**
	 * Verify client signature using RSA-PSS
	 */
	verifyClientSignature(clientPublicKeyPem, signingInput, signatureBuffer) {
		try {
			const verify = crypto.createVerify('SHA256');
			verify.update(signingInput);
			verify.end();

			return verify.verify(
				{
					key: clientPublicKeyPem,
					padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
					saltLength: 32
				},
				signatureBuffer
			);
		} catch (error) {
			console.error('Error verifying client signature:', error);
			return false;
		}
	}

	/**
	 * Sign data with server private key using RSA-PSS
	 */
	signData(data) {
		const sign = crypto.createSign('SHA256');
		sign.update(data);
		sign.end();

		return sign.sign({
			key: this.serverKeys.rsaPrivateSigningKey,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: 32
		});
	}

	/**
	 * Base64 URL encoding (without padding)
	 */
	base64UrlEncode(data) {
		const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
		return buffer.toString('base64')
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	}

	/**
	 * Base64 URL decoding
	 */
	base64UrlDecode(str) {
		// Add padding if needed
		str += '='.repeat((4 - str.length % 4) % 4);
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		return Buffer.from(str, 'base64');
	}

	/**
	 * Pretty print JWS token with decoded header and payload
	 * @param {string} jws - The JWS token
	 * @param {string} title - Title for the log output
	 */
	logJWSToken(jws, title = 'JWS Token') {
		console.log(`\n🔍 ${title}:`);
		console.log('─'.repeat(50));

		// Print the raw JWS token
		console.log('📄 Raw JWS Token:');
		console.log(jws);
		console.log('');

		try {
			const parts = jws.split('.');
			if (parts.length !== 3) {
				console.log('❌ Invalid JWS format');
				return;
			}

			const [encodedHeader, encodedPayload, encodedSignature] = parts;

			// Decode and display header
			const headerBuffer = this.base64UrlDecode(encodedHeader);
			const header = JSON.parse(headerBuffer.toString());
			console.log('📋 Header:');
			console.log(JSON.stringify(header, null, 2));

			// Decode and display payload
			const payloadBuffer = this.base64UrlDecode(encodedPayload);
			const payload = JSON.parse(payloadBuffer.toString());
			console.log('📦 Payload:');
			console.log(JSON.stringify(payload, null, 2));

			// Display signature info
			console.log('🔐 Signature:');
			console.log(`Length: ${encodedSignature.length} characters`);
			console.log(`Preview: ${encodedSignature.substring(0, 50)}...`);

		} catch (error) {
			console.error('❌ Error decoding JWS:', error.message);
		}

		console.log('─'.repeat(50));
	}

	/**
	 * Start the server
	 */
	start() {
		this.app.listen(CONFIG.PORT, () => {
			console.log('\n🚀 Consent Cryptographic Server with JWS Started');
			console.log(`📡 Server listening on port ${CONFIG.PORT}`);
			console.log(`🔒 Security: JWS with RSA-PSS ${CONFIG.RSA_KEY_SIZE}-bit signatures`);
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

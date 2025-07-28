const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
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

	initializeKeys() {
		console.log('* Initializing server cryptographic keys...');

		try {
			// Generate RSA signing key pair
			this.loadRSASigningKeys();

			console.log('✅ Server keys initialized successfully');
		} catch (error) {
			console.error('❌ Failed to initialize server keys:', error);
			process.exit(1);
		}
	}

	loadRSASigningKeys() {
		const pem = fs.readFileSync('server.crt', 'utf8');
		const cert = forge.pki.certificateFromPem(pem);
		const publicKey = forge.pki.publicKeyToPem(cert.publicKey);

		console.log(publicKey);

		const privateKey = fs.readFileSync('server.key', 'utf8');

		console.log(privateKey);

		this.serverKeys.rsaPrivateSigningKey = privateKey;
		this.serverKeys.rsaPublicSigningKey = publicKey;

		console.log(`📝 RSA Signing Key Size: ${CONFIG.RSA_KEY_SIZE} bits`);
	}

	setupMiddleware() {
		this.app.use(bodyParser.json());
		this.app.use(express.static('public'));
		this.app.use(cors({
			origin: CONFIG.CORS_ORIGIN,
			methods: ['GET', 'POST'],
			allowedHeaders: ['Content-Type']
		}));

		// Request logging
		this.app.use((req, _, next) => {
			console.log(`* ${req.method} ${req.path} - ${new Date().toISOString()}`);
			next();
		});
	}

	setupRoutes() {
		// Get RSA public key for client key exchange
		this.app.get('/api/publickey', (_, res) => {
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
				const result = this.processClient(req.body);

				res.json({
					success: true,
					serverSignedJWS: result.jws,
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
		this.app.get('/health', (_, res) => {
			res.json({
				status: 'healthy',
				timestamp: new Date().toISOString(),
				version: '1.0.0'
			});
		});
	}

	processClient(clientInfo) {
		console.log('🔍 Received client info...');

		// Step 1: Verify client signature
		this.verifyClientSignature(clientInfo.pubkey, clientInfo.consent, clientInfo.signature)

		// Step 2: Create server-signed JWS
		const signedJWS = this.createSignedJWS(clientInfo);
		console.log('📝 JWS created');

		console.log(signedJWS)

		return {
			jws: signedJWS
		};
	}

	createSignedJWS(clientInfo) {
		const headers = {
			typ: "JWT",
			alg: "PS256", // from JWA (RSASSA-PSS using SHA-256 and MGF1 with SHA-256)
		};

		// Encode header and payload
		// const encodedHeader = this.base64UrlEncode(JSON.stringify(headers));
		const encodedPayload = this.base64UrlEncode(JSON.stringify(clientInfo.consent));

		// Sign with server private key
		const signature = this.base64UrlEncode(this.signData(clientInfo.consent));

		const jws = {
			payload: encodedPayload,
			signatures: [
				{
					header: headers,
					signature: clientInfo.signature
				},
				{
					header: headers,
					signature: signature
				}
			]
		};
		return JSON.stringify(jws);
	}

	verifyClientSignature(pubkey, consent, signature) {
		try {
			const verify = crypto.createVerify('SHA256');

			const serializedData = JSON.stringify(consent);
			verify.update(serializedData);
			verify.end();

			return verify.verify(
				{
					key: pubkey,
					padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
				},
				signature
			);
		} catch (error) {
			console.error('Error verifying client signature:', error);
			return false;
		}
	}

	signData(consent) {
		const sign = crypto.createSign('SHA256');

		const serializedData = JSON.stringify(consent);

		sign.update(serializedData);
		sign.end();

		return sign.sign({
			key: this.serverKeys.rsaPrivateSigningKey,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: 32 // falhava aqui
		});
	}

	base64UrlEncode(data) {
		const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
		return buffer.toString('base64')
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	}

	base64UrlDecode(str) {
		str += '='.repeat((4 - str.length % 4) % 4);
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		return Buffer.from(str, 'base64');
	}

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

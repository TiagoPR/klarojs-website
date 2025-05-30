// Server-side implementation for consent cryptographic flow
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();

// Import crypto utilities
const cryptoUtils = require('./crypto-utils');

// Server keys and parameters storage
let serverKeys = {
	dhParams: null,
	dhPrivateKey: null,
	dhPublicKey: null,
	rsaPrivateSigningKey: null,
	rsaPublicSigningKey: null
};

// Initialize server keys
function initializeServerKeys() {
	console.log('Initializing server keys...');

	// Generate DH parameters
	const dhGroup = crypto.getDiffieHellman('modp14'); // Using predefined group

	// Generate DH key pair
	dhGroup.generateKeys();

	// Generate RSA key pair for signing
	const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem'
		}
	});

	// Store keys and parameters
	serverKeys = {
		dhParams: dhGroup,
		dhPrivateKey: dhGroup.getPrivateKey(),
		dhPublicKey: dhGroup.getPublicKey(),
		rsaPrivateSigningKey: privateKey,
		rsaPublicSigningKey: publicKey
	};

	console.log('Server keys initialized');
}

// Get DH parameters and public key for client
function getDHParametersForClient() {
	return {
		prime: serverKeys.dhParams.getPrime().toString('hex'),
		generator: serverKeys.dhParams.getGenerator().toString('hex'),
		publicKey: serverKeys.dhPublicKey.toString('hex')
	};
}

// Handle client consent package
function processClientConsent(clientPackage) {
	console.log('Processing client consent package...');

	// Extract client data
	const encryptedConsent = clientPackage.encryptedConsent;
	const clientPublicKey = Buffer.from(clientPackage.clientPublicKey, 'hex');
	const clientSignature = clientPackage.clientSignature;
	const clientPublicSigningKey = clientPackage.clientPublicSigningKey;

	// Compute shared secret
	//const sharedSecret = crypto.diffieHellman({
	//	privateKey: serverKeys.dhPrivateKey,
	//	publicKey: clientPublicKey,
	//	prime: serverKeys.dhParams.getPrime(),
	//	generator: serverKeys.dhParams.getGenerator()
	//});
	//
	const sharedSecret = serverKeys.dhParams.computeSecret(clientPublicKey);

	// Derive symmetric key
	const symmetricKey = cryptoUtils.generateSymmetricKey(sharedSecret);
	console.log('Server symmetric key:', symmetricKey.toString('hex'));

	// Prepare data for signature verification
	const dataToVerify = encryptedConsent.iv + encryptedConsent.ciphertext + encryptedConsent.tag;

	// Verify client signature
	const signatureValid = cryptoUtils.verifySignature(
		clientPublicSigningKey,
		dataToVerify,
		clientSignature
	);

	console.log('Client signature valid:', signatureValid);

	if (!signatureValid) {
		throw new Error('Invalid client signature');
	}

	// Decrypt consent to verify server can see it
	try {
		const decryptedConsent = cryptoUtils.decryptConsent(symmetricKey, encryptedConsent);
		console.log('Decrypted consent:', decryptedConsent);

		// Prepare data for server signature
		const dataToSign = encryptedConsent.ciphertext + encryptedConsent.iv + encryptedConsent.tag;

		// Sign the consent data
		const serverSignature = cryptoUtils.signData(serverKeys.rsaPrivateSigningKey, dataToSign);

		return {
			symmetricKey: symmetricKey.toString('hex'),
			serverSignature: serverSignature
		};
	} catch (error) {
		console.error('Error decrypting consent:', error);
		throw new Error('Failed to decrypt consent');
	}
}

// Initialize server
initializeServerKeys();

// Set up Express middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Allow requests from extensions and local clients
app.use(cors({
	origin: '*', // or restrict to your extension ID (see note below)
	methods: ['GET', 'POST'],
	allowedHeaders: ['Content-Type']
}));

// Endpoint to get DH parameters
app.get('/api/dhparams', (req, res) => {
	res.json(getDHParametersForClient());
});

// Endpoint to process consent
app.post('/api/consent', (req, res) => {
	try {
		const result = processClientConsent(req.body);
		res.json({
			success: true,
			serverSignature: result.serverSignature
		});
	} catch (error) {
		console.error('Error processing consent:', error);
		res.status(400).json({
			success: false,
			error: error.message
		});
	}
});

// Endpoint for simple consent (fallback when extension is not present)
app.post('/api/consent-simple', (req, res) => {
	console.log('Simple consent received:', req.body);
	res.json({
		success: true,
		message: 'Consent received without cryptographic verification'
	});
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server listening on port ${PORT}`);
});

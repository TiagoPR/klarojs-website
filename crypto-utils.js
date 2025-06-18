// Common cryptographic utilities for both server and client
const crypto = require('crypto');

// Generate a random symmetric key (32 bytes for AES-256)
function generateRandomSymmetricKey() {
	return crypto.randomBytes(32);
}

// Generate a symmetric key from a shared secret using HKDF
function generateSymmetricKey(sharedSecret) {
	// HKDF implementation for key derivation
	const salt = null; // No salt needed as in the Python example
	const info = Buffer.from('cifragem de consentimento', 'utf8');

	// Extract phase - create a pseudorandom key
	let prk;
	if (salt) {
		const hmac = crypto.createHmac('sha256', salt);
		hmac.update(sharedSecret);
		prk = hmac.digest();
	} else {
		const hmac = crypto.createHmac('sha256', Buffer.alloc(32).fill(0));
		hmac.update(sharedSecret);
		prk = hmac.digest();
	}

	// Expand phase - expand the pseudorandom key to desired length
	const hmac = crypto.createHmac('sha256', prk);
	hmac.update(info);
	hmac.update(Buffer.from([1]));
	return hmac.digest().slice(0, 32); // 32 bytes = 256 bits
}

// Encrypt symmetric key with RSA public key
function encryptSymmetricKey(publicKey, symmetricKey) {
	return crypto.publicEncrypt({
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: 'sha256'
	}, symmetricKey);
}

// Decrypt symmetric key with RSA private key
function decryptSymmetricKey(privateKey, encryptedSymmetricKey) {
	return crypto.privateDecrypt({
		key: privateKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: 'sha256'
	}, encryptedSymmetricKey);
}

// Encrypt consent data using AES-GCM with the symmetric key
function encryptConsent(symmetricKey, consentData) {
	// Generate random IV (12 bytes as in Python example)
	const iv = crypto.randomBytes(12);

	// Create cipher
	const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

	// Convert consent data to JSON string and then to bytes
	const consentBytes = Buffer.from(JSON.stringify(consentData), 'utf8');

	// Encrypt
	const encryptedContent = Buffer.concat([
		cipher.update(consentBytes),
		cipher.final()
	]);

	// Get authentication tag
	const authTag = cipher.getAuthTag();

	return {
		ciphertext: encryptedContent.toString('hex'),
		iv: iv.toString('hex'),
		tag: authTag.toString('hex')
	};
}

// Decrypt consent data
function decryptConsent(symmetricKey, encryptedConsent) {
	// Convert hex strings back to buffers
	const ciphertext = Buffer.from(encryptedConsent.ciphertext, 'hex');
	const iv = Buffer.from(encryptedConsent.iv, 'hex');
	const authTag = Buffer.from(encryptedConsent.tag, 'hex');

	if (symmetricKey.length !== 32) throw new Error('Invalid symmetric key length');
	if (iv.length !== 12) throw new Error('Invalid IV length');
	if (authTag.length !== 16) throw new Error('Invalid authentication tag length');

	// Create decipher
	const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
	decipher.setAuthTag(authTag);

	// Decrypt
	const decryptedBytes = Buffer.concat([
		decipher.update(ciphertext),
		decipher.final()
	]);

	// Convert back to JSON
	return JSON.parse(decryptedBytes.toString('utf8'));
}

// Sign data with RSA-PSS
function signData(privateKey, data) {
	const sign = crypto.createSign('SHA256');
	sign.update(data);
	sign.end();

	const signature = sign.sign({
		key: privateKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
		saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
	});

	return signature.toString('hex');
}

// Verify signature
function verifySignature(publicKey, data, signature) {
	const verify = crypto.createVerify('SHA256');
	verify.update(data);
	verify.end();

	return verify.verify(
		{
			key: publicKey,
			padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
			saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
		},
		Buffer.from(signature, 'hex')
	);
}

// Export functions if in Node.js environment
if (typeof module !== 'undefined' && module.exports) {
	module.exports = {
		generateRandomSymmetricKey,
		generateSymmetricKey,
		encryptSymmetricKey,
		decryptSymmetricKey,
		encryptConsent,
		decryptConsent,
		signData,
		verifySignature
	};
}

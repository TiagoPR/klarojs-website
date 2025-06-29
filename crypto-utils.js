// Common cryptographic utilities for both server and client
const crypto = require('crypto');

// Sign data with RSA-PSS
function signData(privateKey, data) {
	const sign = crypto.createSign('SHA256');
	sign.update(data);
	sign.end();

	const signature = sign.sign({
		key: privateKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
		saltLength: 32
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
		signData,
		verifySignature
	};
}

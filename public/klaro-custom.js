console.log('klaro:', window.klaro);
let manager = klaro.getManager();
console.log('manager:', manager);

// Add crypto support check
const hasCryptoSupport = window.crypto && window.crypto.subtle;
console.log('WebCrypto API supported:', hasCryptoSupport);

// Track consent processing to prevent duplicates
let consentProcessing = false;
let lastConsentState = null;

// Set up custom event for consent updates
const consentUpdatedEvent = new CustomEvent('consentUpdated', {
	bubbles: true,
	cancelable: true
});

// Function to check if consent state has actually changed meaningfully
function hasConsentChanged(newState) {
	if (!lastConsentState) return true;

	// Compare confirmed status and consent objects
	if (newState.confirmed !== lastConsentState.confirmed) return true;

	// Deep compare consent objects
	const newConsents = JSON.stringify(newState.consents);
	const oldConsents = JSON.stringify(lastConsentState.consents);

	return newConsents !== oldConsents;
}

document.addEventListener('DOMContentLoaded', () => {
	const manager = window.klaro.getManager();

	manager.watch({
		update(state) {
			console.log('Consent updated:', state.consents);

			// Only process if confirmed and consent actually changed
			if (state.confirmed && !consentProcessing && hasConsentChanged(state)) {
				console.log('User confirmed consent.');
				consentProcessing = true;

				// Create consent data object
				const consentData = {
					consents: state.consents,
					confirmed: true,
					timestamp: new Date().toISOString()
				};

				// Store consent data in global variable for the extension to access
				window.klaroConsentData = consentData;
				lastConsentState = { ...state };

				// Dispatch custom event to notify extension
				document.dispatchEvent(consentUpdatedEvent);

				// Wait a bit to see if extension handles it
				setTimeout(() => {
					if (!window.consentHandledByExtension) {
						console.log('Extension not handling consent, using simple server endpoint');
						// Simple non-crypto fallback for users without the extension
						fetch('/api/consent-simple', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify(consentData)
						})
							.then(response => response.json())
							.then(data => {
								console.log('Server consent response:', data);
								consentProcessing = false;
							})
							.catch(error => {
								console.error('Error sending consent to server:', error);
								consentProcessing = false;
							});
					} else {
						consentProcessing = false;
					}
				}, 1000);
			}
		}
	});
});

// Function to check if our extension is present
function checkForExtension() {
	console.log('Checking for extension...');

	// Create a custom event that the extension can listen for
	const checkEvent = new CustomEvent('checkConsentExtension', {
		detail: { id: 'cch-extension-check' }
	});

	// Listen for a response
	const handleExtensionResponse = function(e) {
		console.log('Extension detected:', e.detail);
		window.consentHandledByExtension = true;
	};

	window.addEventListener('consentExtensionPresent', handleExtensionResponse, { once: true });

	// Dispatch the check event
	document.dispatchEvent(checkEvent);

	// If no response after 1000ms, assume extension is not present
	setTimeout(() => {
		if (!window.consentHandledByExtension) {
			console.log('Extension not detected, using server-side only consent flow');
			window.removeEventListener('consentExtensionPresent', handleExtensionResponse);
		}
	}, 1000);
}

// Run extension check after a small delay to ensure everything is loaded
setTimeout(checkForExtension, 500);

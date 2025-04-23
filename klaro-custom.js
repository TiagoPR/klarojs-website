console.log('klaro:', window.klaro);
let manager = klaro.getManager();

console.log('manager:', manager);

document.addEventListener('DOMContentLoaded', () => {
	const manager = window.klaro.getManager();

	manager.watch({
		update(state) {
			// TODO: ? Right now event changing the modal sliders its treated as confirmed consent when user already has given consent
			console.log('Consent updated:', state.consents);
			if (state.confirmed) {
				console.log('User confirmed consent.');
				// Rest of the logic
			}
		}
	});
});

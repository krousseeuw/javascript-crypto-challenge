const _sodium = require('libsodium-wrappers');

module.exports = async (key) => {
    await _sodium.ready

    if(!key) {
        throw 'no key'
    }

    return Object.freeze({
        decrypt: (ciphertext, nonce) => {
            return _sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
        }
    })
};


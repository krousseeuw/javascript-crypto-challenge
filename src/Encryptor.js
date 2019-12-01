const _sodium = require('libsodium-wrappers');

module.exports = async (key) => {
    await _sodium.ready

    if(!key) {
        throw 'no key Encryptor'
    }

    return Object.freeze({
        encrypt: (msg) => {
            nonce = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES);
            ciphertext = _sodium.crypto_secretbox_easy(msg, nonce, key);

            return {nonce: nonce, ciphertext: ciphertext};
        }
    })
};


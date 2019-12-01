const _sodium = require('libsodium-wrappers');

module.exports = async () => {
    await _sodium.ready;

    keypair = _sodium.crypto_sign_keypair();

    return Object.freeze({
        verifyingKey: keypair.publicKey,
        sign: (msg) => {
            return _sodium.crypto_sign(msg, keypair.privateKey)
        }         
    })
};
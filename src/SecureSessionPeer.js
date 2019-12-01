const _sodium = require('libsodium-wrappers');
const Decryptor = require('./Decryptor');
const Encryptor = require('./Encryptor');
const EventEmitter = require('events')


module.exports = async (peer) => {
    await _sodium.ready;
    
    var keypair = _sodium.crypto_kx_keypair();
    
    const publicKey = keypair.publicKey;
    const secretKey = keypair.privateKey;    

    sharedKey = _sodium.crypto_kx_server_session_keys(publicKey, secretKey, peer.publicKey);

    rx = sharedKey.sharedRx;
    tx = sharedKey.sharedTx;    

    decryptor = await Decryptor(publicKey);
    encryptor = await Encryptor(publicKey);

    res = _sodium.crypto_secretstream_xchacha20poly1305_init_push(publicKey);
    [state_out, header] = [res.state, res.header];

    otherPeer = {
        signature: null
    };
   
    return Object.freeze({
        publicKey: publicKey,
        encrypt: (msg) => {
            return encryptor.encrypt(msg);
        },
        decrypt: (ciphertext, nonce) => {
            return decryptor.decrypt(ciphertext, nonce);
        },
        send: (msg) => {
            _sodium.crypto_secretstream_xchacha20poly1305_push(state_out,
                _sodium.from_string(msg), null,
                _sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        },
        receive: () => {
            let state_in = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, publicKey);
            let r1 = _sodium.crypto_secretstream_xchacha20poly1305_pull(state_in);
            let [m1, tag1] = [_sodium.to_string(r1.message), r1.tag];

            return m1;
        },
        getCipher: (msg) => {
            _sodium.crypto_secretstream_xchacha20poly1305_push(state_out,
                _sodium.from_string(msg), null,
                _sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }        
    });
};
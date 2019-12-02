const _sodium = require('libsodium-wrappers');
const Decryptor = require('./Decryptor');
const Encryptor = require('./Encryptor');

_server = null;

// Server
module.exports = async(peer) => {
    await _sodium.ready;
    
    _instance = {
        encryptor: null,
        decryptor: null,
        receivedMessage: null,
        clientKey: null
    }

    var keypair = _sodium.crypto_kx_keypair();       

    isClient = false;

    const publicKey = keypair.publicKey;
    const privateKey = keypair.privateKey;

    if(peer){
        clientKeys = _sodium.crypto_kx_client_session_keys(publicKey, privateKey, peer.publicKey);    
        _instance.decryptor = await Decryptor(publicKey);
        _instance.encryptor = await Encryptor(publicKey);
        await peer.createServer(publicKey);    
    }
    
    
    return Object.freeze({
        publicKey: publicKey,
        createServer: async(clientKey) => {
            serverkeys = _sodium.crypto_kx_server_session_keys(publicKey, privateKey, clientKey);
            _instance.decryptor = await Decryptor(clientKey);
            _instance.encryptor = await Encryptor(clientKey);
        },
        encrypt: (msg) => {
            return _instance.encryptor.encrypt(msg);
        },
        decrypt: (ciphertext, nonce) => {            
            return _instance.decryptor.decrypt(ciphertext, nonce);
        },
        // There is probably a much better way to do this
        send: (msg) => {
            if(isClient){
                peer._instance.receivedMessage = _instance.encryptor.encrypt(msg);
            } else {
                _instance.receivedMessage = _instance.encryptor.encrypt(msg);
            }
        },
        receive: () => {
            let receivedCiphertext;
            let receivedNonce;
            if(isClient){
                receivedCiphertext = peer._instance.receivedMessage.ciphertext;
                receivedNonce = peer._instance.receivedMessage.nonce;
            } else {
                receivedCiphertext = _instance.receivedMessage.ciphertext;
                receivedNonce = _instance.receivedMessage.nonce;
            }

            return _instance.decryptor.decrypt(receivedCiphertext, receivedNonce);
        }

    });
}
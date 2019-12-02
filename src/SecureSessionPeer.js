const _sodium = require('libsodium-wrappers');
const Decryptor = require('./Decryptor');
const Encryptor = require('./Encryptor');

// Server
module.exports = async(peer) => {
    await _sodium.ready;

    var keypair = _sodium.crypto_kx_keypair();       

    const publicKey = keypair.publicKey;
    const privateKey = keypair.privateKey;    
    var encryptor;
    var decryptor;

    if(peer){    
        clientKeys = _sodium.crypto_kx_client_session_keys(publicKey, privateKey, peer.publicKey);
        decryptor = await Decryptor(peer.publicKey);
        encryptor = await Encryptor(peer.publicKey);
        
    } else {
        //serverKeys = _sodium.crypto_kx_server_session_keys(publicKey, privateKey);
        decryptor = await Decryptor(publicKey);
        encryptor = await Encryptor(publicKey);        
    } 
    
    
    return Object.freeze({
        publicKey: publicKey,
        encrypt: (msg) => {
            return encryptor.encrypt(msg);
        },
        decrypt: (ciphertext, nonce) => {            
            return decryptor.decrypt(ciphertext, nonce);
        },

    });
}
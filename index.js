const { keccak256 } = require("ethereum-cryptography/keccak");
const { utf8ToBytes } = require("ethereum-cryptography/utils");
const secp = require("ethereum-cryptography/secp256k1");

const PRIVATE_KEY = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";

/* hash the message */
function hashMessage(message) {
    return keccak256(utf8ToBytes(message))
}

hashMessage(message)

/* Sign a message using a private key */
function signMessage(msg) {
    const messageHash = hashMessage(msg)
    return secp.sign(messageHash, PRIVATE_KEY, { recovered: true })
}

/* Given a message, signature and recoveryBit, this find the public key and return it */
function recoverKey(message, signature, recoveryBit) {
    const messageHash = hashMessage(message)
    return secp.recoverPublicKey(messageHash, signature, recoveryBit)
}

/* Get the Ethereum address from the public key */
function getAddress(publicKey) {
    return keccak256(publicKey.slice(1)).slice(-20)
}

// Step 1 : Hash the message
// Step 2 : Sign the message
// Step 3 : Recover the Key
// Step 4 : Key to Address
const crypto = require('crypto');


// Provisioning can be done offline (preferred) or online.
// Below we provide provisioning logic and helper functions that help explain the handled values.


// Provisioning should run on a dedicated server to limit damage in case of a compromise.
const ProvisioningServerState = { // ---------------------------------------------------------------------

    // private key that signs JWT tokens
    // should only exist on provisioning server
    provSigningKeyPriv: "-----BEGIN PRIVATE KEY-----\n"+ 
                        "MC4CAQAwBQYDK2VwBCIEIApQWYwy9PK2xXX6X3iwPl48KqeXYn9juhtTqQDQqsRu\n"+
                        "-----END PRIVATE KEY-----",
  
    // KeyID stored in JWT claim: "k"
    provSigningKeyID: "aC7",
    
    // public key is not needed by provisioning server, it's needed by edge function, 
    // provSigningKeyPub: "-----BEGIN PUBLIC KEY-----\n"+
    //                    "MCowBQYDK2VwAyEA+lBGpE5ifG9y1hC0004mk892AGgFdHk2/sphvRFOzaQ=\n"+
    //                    "-----END PUBLIC KEY-----\n",

    backendDerivationKey: "jfGed&l9$6*%rf5_", // known by edge and origin
    provisioningMaskKey: '8ra69A_~8Q7g0hRI', // known by client and provisioning origin 
};


// client data
const ProvisioningClientData = {
    clientId: "kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA",
    clientType: "esp32/B7",
}

/**
 * Demo helper that simulates a successful /provision response.
 *
 * Notes:
 *   - clientAuthSecret = HMAC-SHA256(backendDerivationKey, clientId)   (32 bytes)
 *   - maskKey          = SHA-256(provisioningMaskKey)                  (32 bytes)
 *   - maskedSecret     = clientAuthSecret XOR maskKey                  (32 bytes)
 *
 * The client reconstructs MaskKey from the embedded provisioningMaskKey,
 * XORs to recover ClientAuthSecret, and stores it permanently.
 */
async function provisioningTest() {
    // generate JWT
    const jwt = await generateSignedJwt(ProvisioningClientData.clientId, ProvisioningClientData.clientType);

    // generate clientAuthSecret (32 bytes) and maskedClientAuthSecret (32 bytes)
    const clientAuthSecret = crypto
        .createHmac("sha256", ProvisioningServerState.backendDerivationKey)
        .update(ProvisioningClientData.clientId)
        .digest(); // HMAC-SHA256
    const maskKey = crypto
        .createHash("sha256")
        .update(ProvisioningServerState.provisioningMaskKey)
        .digest(); // SHA-256
    const maskedClientAuthSecret = xorBuffers(clientAuthSecret,maskKey);
    const maskedClientAuthSecretBase64url = toBase64url(maskedClientAuthSecret);

    console.log(`For DeviceID: ${ProvisioningClientData.clientId}:\n    JWT: ${jwt},\n    MaskedClientAuthSecret: ${maskedClientAuthSecretBase64url}`);
    return jwt;
}

/**
 * Generates a signed JWT for a client.
 *
 * Claims (compact, as in paper):
 *   d: ClientId  (base64url public key / ClientID)
 *   k: KeyID     (which provisioning public key to use for verification at edge/origin)
 *   c: ClientType
 *   i: issuance timestamp (seconds)
 *
 * Security note:
 *   - Only provisioning server holds provSigningKeyPriv.
 *   - Edge function holds the corresponding public key(s) to verify the JWT signature.
 */
async function generateSignedJwt(clientId, clientType) {
    if (! isValidBase64url(clientId))
        throw new Error('Invalid ClientID');

    const serverTimestampSec = Math.floor(Date.now() / 1000);

    // jose is ESM; dynamic import keeps this file runnable in CommonJS
    const { SignJWT, importPKCS8 } = await import('jose'); 
    const privateKey = await importPKCS8(ProvisioningServerState.provSigningKeyPriv, 'EdDSA');
    const jwt = await new SignJWT({
            d: clientId,
            k: ProvisioningServerState.provSigningKeyID,
            c: clientType,
            i: serverTimestampSec,
        })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .sign(privateKey);

    return jwt;
}


function testEd25519Keys() { // basic insight into Ed25519 keys

    // to generate keys ed25519 key pair:
    //   openssl genpkey -algorithm ED25519 -out ed25519-private.pem
    //   openssl pkey -in ed25519-private.pem -pubout -out ed25519-public.pem

    //PUBLIC hex key decoded from PEM format:
    //   (first 12 bytes will always be 0x302a300506032b6570032100, last 32 bytes are key)
    //  DER-encoded SubjectPublicKeyInfo (SPKI) structure for an Ed25519 public key, as defined in RFC 8410
    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //    algorithm         AlgorithmIdentifier,
    //    subjectPublicKey  BIT STRING
    //  }
    //  30 2a     → 30: Outer SEQUENCE (constructed), 2a: length = 42 bytes, everything inside is SubjectPublicKeyInfo
    //    30 05   → SEQUENCE, length = 5 bytes
    //      06    → OBJECT IDENTIFIER
    //      03    → length = 3 bytes
    //      2b 65 70 → OID value = 1.3.101.112, means: Ed25519,
    //    03 21 00 → 03: BIT STRING, 21: length(33 bytes), 00: unused bits = 0 (Required by DER for BIT STRINGs)
    //      90bbd6a0ae0431c23660136d27b8d2789d8ab80e5695f21d215460daff7182d0 → 32 byte public key

    //PRIVATE hex key decoded from PEM format
    //  (first 16 bytes will always be 0x302e020100300506032b657004220420, last 32 bytes are key)
    // DER-encoded PKCS#8 Ed25519 private key, per RFC 8410.
    // PrivateKeyInfo ::= SEQUENCE {
    //    version                   INTEGER,
    //    privateKeyAlgorithm       AlgorithmIdentifier,
    //    privateKey                OCTET STRING
    //  }
    // 30 2e       → 30: SEQUENCE, 2e: length (46 bytes), everything inside is PrivateKeyInfo
    //   02 01 00  → 02:INTEGER, 01:length(1), 00:value(0)
    //   30 05     → algorithm, same as in public key
    //     06 03 2b 65 70 
    //   04 22     → 04:OCTET STRING, 22: length(34 bytes)
    //     04 20   → 04:OCTET STRING, 20: length(32 bytes)
    //       96bde65bc6c6e15f93cc253e50d3cbc926588bcfff6a8786903d08c9de21bcc4 → 32 byte private key

    extractRawEd25519Keys(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJa95lvGxuFfk8wlPlDTy8kmWIvP/2qHhpA9CMneIbzE\n-----END PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAkLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA=\n-----END PUBLIC KEY-----"
    );
}

/**
 * Utility: extract raw Ed25519 keys from PEM formats.
 *
 * Note:
 *   - Public key PEM → type: 'spki'
 *   - Private key PEM → type: 'pkcs8'
 */
function extractRawEd25519Keys(pemPriv, pemPub) {

    // Load private key
    const privateKey = crypto.createPrivateKey({ key: pemPriv, format: 'pem', type: 'pkcs8'}); // load from PEM
    // Export raw private key (32 bytes)
    //const rawPrivateKey = privateKey.export({ format: 'der', type: 'pkcs8' }).slice(-32);
    // Base64url output
    //const base64urlPriv = toBase64url(rawPrivateKey);
    //console.log('Raw private key (base64url):', base64urlPriv);

    // Load public key
    const publicKey = crypto.createPublicKey({ key: pemPub, format: 'pem', type: 'spki'}); // load from PEM
    // or derive public key from private:
    //const publicKey = crypto.createPublicKey(privateKey);
    // Export raw public key (32 bytes)
    const rawPublicKey = publicKey.export({ format: 'der', type: 'spki'}).slice(-32);
    // Hex output
    //console.log('Raw public key (hex):', rawPublicKey.toString('hex'));
    // Base64url output
    const base64urlPub = toBase64url(rawPublicKey);
    console.log('Raw public key (base64url):', base64urlPub);

    return base64urlPub;
}

/**
 * XOR two same-length buffers.
 * Used to mask/unmask 32-byte ClientAuthSecret during provisioning.
 */
function xorBuffers(bufA, bufB) {
    if (bufA.length !== bufB.length)
        throw new Error("Buffers must be the same length for XOR.");
    const out = Buffer.alloc(bufA.length);
    for (let i = 0; i < bufA.length; i++)
        out[i] = bufA[i] ^ bufB[i];
    return out;
}

/**
 * Base64url encoding without padding (RFC 4648).
 * Note: "no padding" is the base64url default in this design.
 */
function toBase64url(buffer) {
    return Buffer.from(buffer)
        .toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Minimal base64url character validation.
 */
function isValidBase64url(str) {
    return (typeof str === 'string' && /^[A-Za-z0-9_-]+$/.test(str));
}


//testEd25519Keys();
provisioningTest();

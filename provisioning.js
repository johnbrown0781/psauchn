const crypto = require('crypto');

const clientId = "kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA"; 
const clientType = "esp32/B7";

// provisioning should run on dedicated server, to limit damage in case of compromise
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

};

async function provisioningTest() {
    const jwt = await generateSignedJwt(clientId, clientType);
    console.log(`JWT for ${clientId}:\t` + jwt);
    return jwt;
}

async function generateSignedJwt(clientId, clientType) {
    if (! isValidBase64url(clientId))
        throw new Error('Invalid ClientID');

    const serverTimestampSec = Math.floor(Date.now() / 1000);

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


function testEc25519Keys() { // basic insight into Ec25519 keys

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
    //   30 05     → algo, same as in public key
    //     06 03 2b 65 70 
    //   04 22     → 04:OCTET STRING, 22: length(34 bytes)
    //     04 20   → 04:OCTET STRING, 20: length(32 bytes)
    //       96bde65bc6c6e15f93cc253e50d3cbc926588bcfff6a8786903d08c9de21bcc4 → 32 byte private key

    extractRawEc25519Keys(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJa95lvGxuFfk8wlPlDTy8kmWIvP/2qHhpA9CMneIbzE\n-----END PRIVATE KEY-----",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAkLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA=\n-----END PUBLIC KEY-----"
    );
}

function extractRawEc25519Keys(pemPriv, pemPub) {
    // note: Public key PEM → type: 'spki'
    //       Private key PEM → type: 'pkcs8'

    // Load private key
    const privateKey = crypto.createPrivateKey({ key: pemPriv, format: 'pem', type: 'pkcs8'}); // load from pem
    // Export raw private key (32 bytes)
    //const rawPrivateKey = privateKey.export({ format: 'der', type: 'pkcs8' }).slice(-32);
    // Base64url output
    //const base64urlPriv = toBase64url(rawPrivateKey);
    //console.log('Raw private key (base64url):', base64urlPriv);

    // Load public key
    const publicKey = crypto.createPublicKey({ key: pemPub, format: 'pem', type: 'spki'}); // load from pem
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

function toBase64url(buffer) {
    return Buffer.from(buffer)
        .toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function isValidBase64url(str) {
    return (typeof str === 'string' && /^[A-Za-z0-9_-]+$/.test(str));
}


testEc25519Keys();
provisioningTest();

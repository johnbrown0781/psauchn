const https = require('https');
const crypto = require('crypto');

const ClientState = { // ----------------------------------------------------------------------------------------

    // Ed25519 private key in PKCS#8 DER, base64 encoded (32-byte Ed25519 seed wrapped in PKCS#8 structure).
    // This is used only for generating per-request signatures over AuthHash.
    privateKeyDerBase64: "MC4CAQAwBQYDK2VwBCIEIJa95lvGxuFfk8wlPlDTy8kmWIvP/2qHhpA9CMneIbzE",

    // Provisioned long-lived identity token (JWS compact form). Payload includes:
    //   d = ClientID (public key, base64url)
    //   k = KeyID (provisioning signing key identifier)
    //   c = ClientType
    //   i = IssuedAt (iat)    
    clientJwt:
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9" +
        ".eyJkIjoia0x2V29LNEVNY0kyWUJOdEo3alNlSjJLdUE1V2xmSWRJVlJnMnY5eGd0QSIsImsiOiJhQzciLCJjIjoiZXNwMzIvQjciLCJpIjoxNzcwMDkxMTI1fQ" +
        ".602RoknC7X5UQAISyVLfa7ofOA6L2xAaifs4xUdaU17CK77_ae0mAzDi62cvh8ztPCQij14pIOdNIgraEm1TAQ",

    // Convenience copy of JWT payload claim "d" (ClientID / public key, base64url).
    jwtPayloadClientId: "kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA", // identical to JWT payload claim "d", extracted here for convenience

    // Per-client secret issued during provisioning (base64url, no padding).
    // Used as the keyed component in AuthHash so that TLS MITM cannot modify requests undetected
    //   unless they also have this secret (or BackendDerivationKey on the server side).
    clientAuthSecret: "yJgxHUHg0yXC59esBJCVGg-ck_TyvVNmSxISSvG8gO8",

    // Embedded client-side provisioning masking key.
    // Used only to unmask (recover) ClientAuthSecret from the provisioning response.
    provisioningMaskKey: '8ra69A_~8Q7g0hRI',    
};

async function clientRequestSend() {

    // Request data
    const method = 'POST';
    const host = 'w1.edge-test.workers.dev'; // TODO change to your deployed worker host
    const path = '/test?a=b';                // TODO change to your deployed worker path
    const postData = JSON.stringify({ key: 'value' });

    // AuthHash
    const bodyBytes = new TextEncoder().encode(postData ?? ""); // use "" for GET
    const bodyHashRaw = await crypto.subtle.digest("SHA-256", bodyBytes);
    const authHeaderPrefixRaw_33Bytes = await getAuthenticationHeaderPrefixRaw(
        ClientState.clientJwt,                        // JWT
        method.toUpperCase(),                         // method (uppercase)
        uint8ArrayToHex(new Uint8Array(bodyHashRaw)), // hex(SHA-256(body))
        host.toLowerCase() + path                     // host/pathWithQuery
    );

    // Signature is computed over the 33-byte prefix: AuthHash(32) || TimeByte(1).
    // Edge/origin can verify Signature using the ClientID public key from the JWT ("d").    
    const signatureRaw_64Bytes = await signMessageEd25519(ClientState.privateKeyDerBase64, authHeaderPrefixRaw_33Bytes);

    // Authentication Header: base64url(AuthHash || TimeByte) || '~' || JWT || '~' || Signature
    //const clientJwtToSendWhenTestingShortJwtFormat = ".{`d`:`kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA`,`k`:`aC7`,`c`:`esp32/B7`,`i`:1770091125}.602RoknC7X5UQAISyVLfa7ofOA6L2xAaifs4xUdaU17CK77_ae0mAzDi62cvh8ztPCQij14pIOdNIgraEm1TAQ";
    const authenticationHeader = `${toBase64url(authHeaderPrefixRaw_33Bytes)}~${ClientState.clientJwt}~${toBase64url(signatureRaw_64Bytes)}`;
    console.log("Authentication Header: " + authenticationHeader);

    // Send request
    sendRequest(
        method,
        host, 
        path, 
        postData, 
        authenticationHeader,
    );
}

// AuthHash prefix builder: returns raw bytes [AuthHash (32 bytes) || TimeByte (1 byte)].
//
// Notes:
// - All fields are ASCII strings, '\n' delimited.
// - URL must not contain '\r' or '\n'.
// - TimeByte is the least-significant byte of Timestamp (Timestamp & 0xFF).
async function getAuthenticationHeaderPrefixRaw(jwt, method, bodyHash, url) {
    const serverTimestampSec = Math.floor(Date.now() / 1000);
    const timeByte = serverTimestampSec % 256;
    if (/[\r\n]/.test(url))
        throw new Error("Invalid URL");

    // AuthHash = SHA-256( JWT || "\n" || ClientAuthSecret || "\n" || Timestamp || "\n" || Method || "\n" || BodyHash || "\n" || URL || "\n" )
    const stringToHash = `${jwt}\n${ClientState.clientAuthSecret}\n${String(serverTimestampSec)}\n` +
                         `${method}\n${bodyHash}\n${url}\n`;
    //console.log(`--- Generating AuthHash from: ---\n${stringToHash}\n---\n`);

    const authHash = crypto
        .createHash("sha256")
        .update(stringToHash)
        .digest();
           
    const prefixRaw = Buffer.concat([authHash, Buffer.from([timeByte])]);
    return prefixRaw;
}

// Signs raw bytes using Ed25519 private key (PKCS#8 DER base64).
// Returns signature as Uint8Array (64 bytes).
async function signMessageEd25519(derBase64, rawDataToSign) {
    const pkcs8Der = new Uint8Array(Buffer.from(derBase64, "base64"));
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        pkcs8Der,
        { name: "Ed25519" },
        false,
        ["sign"]
    );    

    const signatureBuffer = await crypto.subtle.sign('Ed25519', privateKey, rawDataToSign);
    return new Uint8Array(signatureBuffer);
}


function sendRequest(method, hostname, path, postData, authenticationHeader) {
    const options = {
        hostname,
        port: 443,
        path,
        method,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "content-length": Buffer.byteLength(postData),            
            'unattended-client-auth': authenticationHeader
        }        
    };

    const req = https.request(options, res => {
        let data = '';
        res.on('data', chunk => {
            data += chunk;
        });
        res.on('end', () => {
            console.log("Status:", res.statusCode);
            // console.log("Headers:", res.headers);
            console.log("Body:", data.slice(0, 300));
            try {
                console.log('JSON response:', JSON.parse(data));
            } catch (e) {
                // non-JSON response
            }
        });
    });

    req.on('error', error => {
        console.error('Error making request:', error);
    });

    req.write(postData);
    req.end();
}

function uint8ArrayToHex(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++)
        s += u8[i].toString(16).padStart(2, "0");
    return s;
}

function toBase64url(buffer) {
    return Buffer.from(buffer)
        .toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlToUint8Array(base64url) {
    if (typeof base64url !== 'string' || !base64url.length)
        throw new Error("Invalid base64url input");
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
        base64 += "=";
    return new Uint8Array(Buffer.from(base64, "base64"));
}

function xorBuffers(bufA, bufB) {
    if (bufA.length !== bufB.length)
        throw new Error("Buffers must be the same length for XOR");
    const out = Buffer.alloc(bufA.length);
    for (let i = 0; i < bufA.length; i++)
        out[i] = bufA[i] ^ bufB[i];
    return out;
}

// Provisioning helper: recovers ClientAuthSecret from masked server response.
//     maskedClientAuthSecret = ClientAuthSecret XOR MaskKey
//     MaskKey = SHA-256(ProvisioningMaskKey)
function extractMaskedClientAuthSecretBase64(maskedClientAuthSecretBase64) {
    const maskKey = crypto.createHash("sha256").update(ClientState.provisioningMaskKey).digest(); // SHA-256
    const maskedClientAuthSecret = base64urlToUint8Array(maskedClientAuthSecretBase64);
    const extractedClientAuthSecret = xorBuffers(maskedClientAuthSecret,maskKey);
    console.log(`extracted ClientAuthSecret(base64url): ${toBase64url(extractedClientAuthSecret)}`);
}

// "at2JvC2FeQElhI04ZuA1pcKv4Uh41xhIp8BwKzLd20E" is the masked provisioning-server response for ClientID "kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA"
extractMaskedClientAuthSecretBase64("at2JvC2FeQElhI04ZuA1pcKv4Uh41xhIp8BwKzLd20E");

// ----------------------------------------------------------------------

clientRequestSend();
// evalRun();



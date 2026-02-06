const https = require('https');
const crypto = require('crypto');

const ClientState = { // ----------------------------------------------------------------------------------------

    privateKeyDerBase64: "MC4CAQAwBQYDK2VwBCIEIJa95lvGxuFfk8wlPlDTy8kmWIvP/2qHhpA9CMneIbzE",
    clientJwt:
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9" +
        ".eyJkIjoia0x2V29LNEVNY0kyWUJOdEo3alNlSjJLdUE1V2xmSWRJVlJnMnY5eGd0QSIsImsiOiJhQzciLCJjIjoiZXNwMzIvQjciLCJpIjoxNzcwMDkxMTI1fQ" +
        ".602RoknC7X5UQAISyVLfa7ofOA6L2xAaifs4xUdaU17CK77_ae0mAzDi62cvh8ztPCQij14pIOdNIgraEm1TAQ",

    jwtPayloadClientId: "kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA", // identical to JWT payload claim "d", here for convenience

    edgeSalt: '8ra69A_~8Q7g0hRI',
};

async function clientRequestSend() {

    // Request data
    const method = 'POST';
    const host = 'w1.edge-test.workers.dev'; // TODO change to your deployed worker host
    const path = '/test?a=b';                // TODO change to your deployed worker path
    const postData = JSON.stringify({ key: 'value' });

    // AuthHash and Signature
    const bodyHashRaw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(postData ?? ""));
    const authHeaderPrefixRaw_33Bytes = await getAuthenticationHeaderPrefixRaw(
        ClientState.clientJwt,                        // JWT
        method.toUpperCase(),                         // method
        uint8ArrayToHex(new Uint8Array(bodyHashRaw)), // hex(SHA-256(body))
        host.toLowerCase() + path                     // host/pathWithQuery
    );
    const signatureRaw_64Bytes = await signMessageEd25519(ClientState.privateKeyDerBase64, authHeaderPrefixRaw_33Bytes);

    // Authentication Header: base64url(AuthHash + TimeByte) + '~' + JWT + '~' + Signature
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

async function getAuthenticationHeaderPrefixRaw(jwt, method, bodyHash, url) {

    const serverTimestampSec = Math.floor(Date.now() / 1000);
    const timeByte = serverTimestampSec % 256;
    // AuthHash = SHA-256(JWT ∥ "\n" ∥ EdgeSalt ∥ "\n" ∥ Timestamp ∥ "\n" ∥ Method ∥ "\n" ∥ BodyHash ∥ "\n" ∥ URL)
    const stringToHash = `${jwt}\n${ClientState.edgeSalt}\n${String(serverTimestampSec)}\n` +
                         `${method}\n${bodyHash}\n${url}`;
    console.log(`--- Generating AuthHash from: ---\n${stringToHash}\n---\n`);

    const authHash = crypto
        .createHash("sha256")
        .update(stringToHash)
        .digest();
           
    const prefixRaw = Buffer.concat([authHash, Buffer.from([timeByte])]);
    return prefixRaw;
}

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
            } catch (e) {}
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


// ------------------------

clientRequestSend();

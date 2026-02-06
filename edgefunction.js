


// requests can have authentication provided in request header, or as request url parameter
const REQUEST_HEADER = "unattended-client-auth";
const REQUEST_PARAM_KEY = "uca";

// -------------------------------------------------------------------------------------------------
const EdgeState = {

    timeByteToleranceSec: 60, // allow timestamps that are +-60 seconds

    signingKeyMap: new Map([
        ['aC7', 'MCowBQYDK2VwAyEA+lBGpE5ifG9y1hC0004mk892AGgFdHk2/sphvRFOzaQ='],
        ['aC8', 'MCowBQYDK2VwAyEApEQ1ZqJjM1sAAX9VcFV5xWMpSaEg/n/D37f89SQPZg4='],
        //...
    ]),

    revokedKeyMessageMap: new Map([
        ['aB5', 'Security issue. Please contact support.'],
        //...
    ]),

    blockedClientIds: new Set([
        'yvpjgYDtivylj8bCvUOBCBg5oWngnBbDkcGPcqHZtkA',
        //...
    ]),

    extremelyLimitedClientTypes: new Set([
        'atmega3',
        'atmega4',
        //...
    ]),

    authEdgeSalt: '8ra69A_~8Q7g0hRI',

    skippedUrl: '/provision', // allow provisioning requests

};

const UserFacingMessage = {
    MISSING_AUTH: "Invalid request, missing authentication.",
    MALFORMED_AUTH: "Malformed authentication header.",
    INVALID_JWT_FORMAT: "Invalid JWT format.",
    MALFORMED_JWT: "Malformed JWT.",
    INVALID_JWT_HEADER: "Invalid JWT header.",
    INVALID_JWT_PAYLOAD: "Invalid JWT payload.",
    INVALID_JWT_SIGNATURE: "Invalid JWT signature.",
    MISSING_SIGNATURE: "Missing signature.",
    BLOCKED_CLIENT: "Access Denied. Please contact support.",
    INVALID_TIMEBYTE: "Invalid timestamp.",
    INVALID_PREFIX_FORMAT: "Invalid prefix format.",
    INVALID_PREFIX_LENGTH: "Invalid prefix length.",
    INVALID_PREFIX_VALUE: "Invalid prefix value.",
    INVALID_CLIENT_SIGNATURE: "Invalid signature.",
}

// attach function that verifies authentication header
addEventListener("fetch", event => event.respondWith(verifyAuthenticationHeader(event.request)));

async function verifyAuthenticationHeader(request) {

    // Note: We avoided low-level speed optimizations in order to keep code clean and easily portable.

    // Before Edge Function runs, two limits are enforced by WAF:
    // 1) rate-limit per IP
    // 2) rate-limit per DeviceID
    //     To enforce rate-limit per DeviceID, using WAF static rules, enforce rate-limit per JWT's payload.
    //         Extract JWT's payload from Authentication Header using regex: ^[^~]+~[^.]+\.([^\.]+)\.[^~]+
    //             details: ^[^~]+~ — the freshness part, [^.]+ — JWT header, \. — literal dot
    //                      ([^\.]+) — capture group #1: the payload (middle part),  \. — literal dot, [^~]+ — JWT signature, etc.

    try {

        const url = new URL(request.url);

        if (url.pathname === EdgeState.skippedUrl)
            return fetch(request); // forward request to backend

        // get Authentication from HTTP header, or from URL parameter.
        const authHeader = request.headers.get(REQUEST_HEADER)?.trim() || 
                           url.searchParams.get(REQUEST_PARAM_KEY);
        if (!authHeader)
            throw new Error(UserFacingMessage.MISSING_AUTH);

        const authHeaderParts = authHeader.split('~');
        if (authHeaderParts.length < 2 || authHeaderParts.length > 3)
            throw new Error(UserFacingMessage.MALFORMED_AUTH);

        let [authPrefix, jwt, signatureIfAny] = authHeaderParts;

        if (! isValidBase64url(authPrefix)) 
            throw new Error(UserFacingMessage.INVALID_PREFIX_FORMAT);

        jwt = fixShortJwt(jwt);
        if (! isValidJwtFormat(jwt))
            throw new Error(UserFacingMessage.MALFORMED_JWT);

        const jwtPayload = JSON.parse(decodeBase64urlToString(jwt.split(".")[1]));
        const clientId = jwtPayload.d;
        const clientType = jwtPayload.c;
        const keyId = jwtPayload.k;

        if (typeof clientId !== "string" || !clientId.length
            || typeof clientType !== "string" || !clientType.length
            || typeof keyId !== "string" || !keyId.length)
            throw new Error(UserFacingMessage.INVALID_JWT_PAYLOAD);

        const isHighlyConstrainedClient = EdgeState.extremelyLimitedClientTypes.has(clientType);
        if (! isHighlyConstrainedClient && ! signatureIfAny)
            throw new Error(UserFacingMessage.MISSING_SIGNATURE);

        if (EdgeState.blockedClientIds.has(clientId))
            throw new Error(UserFacingMessage.BLOCKED_CLIENT);

        // Decode the 33-byte binary prefix
        const authPrefixRaw_33Bytes = decodeBase64urlToUint8Array(authPrefix);
        if (authPrefixRaw_33Bytes.length !== 33)
            throw new Error(UserFacingMessage.INVALID_PREFIX_LENGTH);
        const authHash = authPrefixRaw_33Bytes.slice(0, 32);
        const timeByte = authPrefixRaw_33Bytes[32];

        // Reconstruct candidate timestamps
        const now = Math.floor(Date.now() / 1000);
        const candidateTimestamps = [now, now - 256, now + 256]
            .map(base => base - (base % 256) + timeByte)
            .filter(timestamp => Math.abs(timestamp - now) < EdgeState.timeByteToleranceSec);
        if (candidateTimestamps.length == 0)
            throw new Error(UserFacingMessage.INVALID_TIMEBYTE);

        // Find timestamp whose hash matches
        let match = false;
        for (const timestamp of candidateTimestamps) {
            const computed = await computeAuthHash(jwt, request.clone(), timestamp); // clone() is required to avoid reading body twice
            if (isEqualBytes(computed, authHash)) {
                match = true;
                break;
            }
        }
        if (!match) // hash or timestamp mismatch
            throw new Error(UserFacingMessage.INVALID_PREFIX_VALUE);

        // Load JWT public key
        const pubJwtSigningKey = EdgeState.signingKeyMap.get(keyId);
        if (! pubJwtSigningKey) {
            const message = EdgeState.revokedKeyMessageMap.get(keyId);
            if (message)
                throw new Error(message);
            throw new Error(UserFacingMessage.INVALID_JWT_PAYLOAD);
        }

        // Verify JWT signature
        const pubKey = await importEd25519PublicKey(pubJwtSigningKey);
        const validJwtSignature = await verifyJwtSignature(jwt, pubKey);
        if (!validJwtSignature)
            throw new Error(UserFacingMessage.INVALID_JWT_SIGNATURE);

        // Verify client's signature
        if (signatureIfAny) {
            const validClientSignature = await verifyEd25519(clientId, signatureIfAny, authPrefixRaw_33Bytes);
            if (!validClientSignature)
                throw new Error(UserFacingMessage.INVALID_CLIENT_SIGNATURE);
        }

        //return new Response("OK", { status: 200 }); // useful for testing

        // Everything OK — forward request to backend
        // Note: accessing this worker on w1.edge-test.workers.dev (and not on your domain) will result with response 404, since w1.edge-test.workers.dev 
        //   is test URL that doesn't have origin set behind it. In that case 404 can be interpreted as edge validation was successful.
        return fetch(request);

    } catch (err) {
        // Catch errors (invalid format, decode issues, etc.)
        const now = Math.floor(Date.now() / 1000);
        const responseBody = { time: now }; // Always return JSON 'time' so device can update it's internal clock
        if (err?.message)
            responseBody.message = err.message;
        return new Response(
          JSON.stringify(responseBody),
          {
            status: 403,
            headers: { 'content-type': 'application/json' },
          }
        );
    }
}

function fixShortJwt(jwt) {
    // handle short JWT form
    if (jwt.startsWith(".{`")) {
        //Note: clients that prefer to use shorter URLs (including highly constrained clients that can't compute signature)
        //      may send shorter version of JWT (JWT header skipped, and JWT payload in unencoded form with " replaced by ` ).
        
        // JWT payload we use is shorter in unencoded form, but to use it efficiently we need to avoid URL characters that would be encoded into %XX.
        //   To make it shorter JWT will not have first part (always the same), and second part will be unencoded, with '"' replaced with '`'.
        //   For this, provisioning server needs to not sign JWTs with following: ',  %, ., ~, and space, inside JWTs payload.
        //   Short JWT might looks like this:  .{`d`:`kL2R-DeviceID-v9xgA`,`k`:`abcd`,`c`:`efgh`}.602R-JWT-signature-OrE1

        const jwtPayload = JSON.parse(decodeBase64urlToString(jwt.split(".")[1]));
        if ( /['"%\.~ ]/.test(jwtPayload) ) // short JWT payload must not contains ', ", %, ., ~, or space.
            throw new Error(UserFacingMessage.MALFORMED_JWT);

        // reconstruct valid JWT
        jwt = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.' + toBase64url(jwtPayload.replace(/`/g, '"')) + '.' + jwt.split(".")[2];

        // Clients with buffers limited to 256 char will want to:
        //     (i) skip signature, (ii) skip JWT's header (always: eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9),
        //     (iii) skip JWT's "i" claim, and (iv) transmit unencoded JWT payload
    }
    return jwt;
}

async function computeAuthHash(jwt, request, timestampSec) {
    const salt = EdgeState.authEdgeSalt;
    const url = new URL(request.url);
    const urlPathWithQuery = url.pathname + url.search; // TODO remove last 'uca' argument
    const urlForHash = url.host.toLowerCase() + urlPathWithQuery;

    const bodyBuf = new TextDecoder("utf-8").decode(await request.arrayBuffer()); // as text
    const bodyHashRaw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bodyBuf));
    const bodyHash = uint8ArrayToHex(new Uint8Array(bodyHashRaw));

    // AuthHash = SHA-256(JWT ∥ "\n" ∥ EdgeSalt ∥ "\n" ∥ Timestamp ∥ "\n" ∥ Method ∥ "\n" ∥ BodyHash ∥ "\n" ∥ URL)
    const stringToHash = `${jwt}\n${salt}\n${String(timestampSec)}\n` +
                         `${request.method.toUpperCase()}\n${bodyHash}\n${urlForHash}`;

    const hash = new Uint8Array(await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(stringToHash)
    ));
    return hash;
}

// Import Ed25519 public key for WebCrypto.verify
async function importEd25519PublicKey(base64PubKey) {
    const rawPubKey = Uint8Array.from(atob(base64PubKey), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        'spki',
        rawPubKey.buffer,
        { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' },
        true,
        ['verify']
    );
}

async function verifyEd25519(clientId, signature, dataBytes) {
    const clientPublicKeyRaw = decodeBase64urlToUint8Array(clientId);
    const publicKey = await crypto.subtle.importKey(
        "raw",
        clientPublicKeyRaw,
        { name: "Ed25519" },
        false,
        ["verify"]
    );
    const signatureBytes = decodeBase64urlToUint8Array(signature);
    return crypto.subtle.verify(
        'Ed25519',
        publicKey,
        signatureBytes,
        dataBytes
    );
}


// Splits JWT into header, payload, signature; and verifies signature.
async function verifyJwtSignature(token, key) {
    // Split JWT into parts
    const [header64, payload64, signature64] = token.split(".");
    if (!header64 || !payload64 || !signature64)
        throw new Error(UserFacingMessage.MALFORMED_JWT);
    let header;
    try {
        // Decode and parse header
        header = JSON.parse(decodeBase64urlToString(header64));
    } catch (e) {
        throw new Error(UserFacingMessage.INVALID_JWT_HEADER);
    }
    // Validate header fields
    if (header.alg !== "EdDSA" || header.typ !== "JWT")
        throw new Error(UserFacingMessage.INVALID_JWT_HEADER);

    // Prepare the signature and data
    const data = new TextEncoder().encode(`${header64}.${payload64}`);
    const signature = decodeBase64urlToUint8Array(signature64);

    // Verify signature using WebCrypto
    const valid = await crypto.subtle.verify(
        { name: 'NODE-ED25519' },
        key,
        signature,
        data
    );
    return valid;
}

function isEqualBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i]; // side-channel resistant
    return diff === 0;
}

function uint8ArrayToHex(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++)
        s += u8[i].toString(16).padStart(2, "0");
    return s;
}

// Decode base64url to Uint8Array
function decodeBase64urlToUint8Array(base64url) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
        base64 += "=";
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// Decode base64url to string
function decodeBase64urlToString(base64url) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
        base64 += "=";
    return atob(base64); 
}

function toBase64url(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const binary = String.fromCharCode(...bytes);
    return btoa(binary)
        .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function isValidJwtFormat(jwt) {
    // this prevents tricks like adding '=' at the end of base64url encoding, etc.
    if (typeof jwt !== 'string')
        return false;
    const parts = jwt.split('.');
    if (parts.length !== 3)
        return false;
    return parts.every(part => isValidBase64url(part));
}

function isValidBase64url(str) {
    return (typeof str === 'string' && /^[A-Za-z0-9_-]*$/.test(str)); // yes, *, not +
}

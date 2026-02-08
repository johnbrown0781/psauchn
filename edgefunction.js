// Requests can provide authentication in an HTTP header or as a URL parameter.
const REQUEST_HEADER = "unattended-client-auth";
const REQUEST_PARAM_KEY = "uca";

// -------------------------------------------------------------------------------------------------
const EdgeState = {

    timeByteToleranceSec: 60, // Allow timestamps that are +-60 seconds

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

    highlyConstrainedClientTypes: new Set([
        'atmega3',
        'atmega4',
        //...
    ]),

    backendDerivationKey: "jfGed&l9$6*%rf5_",

    skippedUrl: '/provision', // Allow provisioning requests

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

// Attach our function that verifies authentication header.
addEventListener("fetch", event => event.respondWith(verifyAuthenticationHeader(event.request)));

/**
 * Edge entry point: validates the authentication header and either:
 *   - forwards the request to the origin (fetch(request)), or
 *   - rejects it with a user-facing JSON response.
 * Note:
 *   - Cloudflare Workers run on the Web Crypto API, not Node.js crypto.
 *   - We avoid micro-optimizations here to keep the verifier clean and portable.* 
 */
async function verifyAuthenticationHeader(request) {

    // Before the edge function runs, two limits are enforced by the WAF:
    // 1) rate-limit per IP
    // 2) rate-limit per ClientID
    //     To enforce rate limits per ClientID using static WAF rules, rate-limit on the JWT payload.
    //         Extract JWT's payload from Authentication Header using regex: ^[^~]+~[^.]+\.([^\.]+)\.[^~]+
    //             Details: ^[^~]+~ — the freshness part, [^.]+ — JWT header, \. — literal dot
    //                      ([^\.]+) — capture group #1: the payload (middle part),  \. — literal dot, [^~]+ — JWT signature, etc.

    try {

        const url = new URL(request.url);

        if (url.pathname === EdgeState.skippedUrl)
            return fetch(request); // forward request to backend

        // Get Authentication from HTTP header, or from URL parameter.
        const authHeader = request.headers.get(REQUEST_HEADER)?.trim() || 
                           url.searchParams.get(REQUEST_PARAM_KEY);
        if (!authHeader)
            throw new Error(UserFacingMessage.MISSING_AUTH);

        // Authentication header format:
        //   base64url(AuthHash||TimeByte) ~ JWT ~ Signature
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

        // Some clients cannot compute Ed25519 signatures (e.g., very small MCUs).
        // For those, only the keyed AuthHash is required.
        const isHighlyConstrainedClient = EdgeState.highlyConstrainedClientTypes.has(clientType);
        if (! isHighlyConstrainedClient && ! signatureIfAny)
            throw new Error(UserFacingMessage.MISSING_SIGNATURE);

        // Block misbehaving or abusive clients
        if (EdgeState.blockedClientIds.has(clientId))
            throw new Error(UserFacingMessage.BLOCKED_CLIENT);

        // Decode the 33-byte binary prefix: AuthHash(32) || TimeByte(1)
        const authPrefixRaw_33Bytes = decodeBase64urlToUint8Array(authPrefix);
        if (authPrefixRaw_33Bytes.length !== 33)
            throw new Error(UserFacingMessage.INVALID_PREFIX_LENGTH);
        const authHash = authPrefixRaw_33Bytes.slice(0, 32);
        const timeByte = authPrefixRaw_33Bytes[32];

        // Reconstruct candidate timestamps consistent with TimeByte, within a small tolerance window.
        // We only need to consider near timestamps, and offsets of +-256 seconds cover wrap-around of the low byte.
        const now = Math.floor(Date.now() / 1000);
        const candidateTimestamps = [now, now - 256, now + 256]
            .map(base => base - (base % 256) + timeByte)
            .filter(timestamp => Math.abs(timestamp - now) < EdgeState.timeByteToleranceSec);
             // For small tolerance there will be just one valid candidate.
        if (candidateTimestamps.length == 0)
            throw new Error(UserFacingMessage.INVALID_TIMEBYTE);

        // Find a timestamp whose recomputed AuthHash matches the received AuthHash.
        let match = false;
        for (const timestamp of candidateTimestamps) {
            // clone() is required to avoid reading the body twice.
            const computed = await computeAuthHash(clientId, jwt, request.clone(), timestamp); // clone() is required to avoid reading the body twice
            if (isEqualBytes(computed, authHash)) {
                match = true;
                break;
            }
        }
        if (!match) // hash or timestamp mismatch
            throw new Error(UserFacingMessage.INVALID_PREFIX_VALUE);

        // Load JWT signing public key by KeyID.
        // Block if KeyID is missing, revoked, or unknown.
        const pubJwtSigningKey = EdgeState.signingKeyMap.get(keyId);
        if (! pubJwtSigningKey) {
            const message = EdgeState.revokedKeyMessageMap.get(keyId);
            if (message)
                throw new Error(message);
            throw new Error(UserFacingMessage.INVALID_JWT_PAYLOAD);
        }

        // Verify JWT signature (proves JWT was issued by the provisioning server).
        const pubKey = await importEd25519PublicKey(pubJwtSigningKey);
        const validJwtSignature = await verifyJwtSignature(jwt, pubKey);
        if (!validJwtSignature)
            throw new Error(UserFacingMessage.INVALID_JWT_SIGNATURE);

        // Verify client's per-request signature (binds AuthHash to the client private key).
        if (signatureIfAny) {
            const validClientSignature = await verifyEd25519(clientId, signatureIfAny, authPrefixRaw_33Bytes);
            if (!validClientSignature)
                throw new Error(UserFacingMessage.INVALID_CLIENT_SIGNATURE);
        }

        //return new Response("OK", { status: 200 }); // useful for testing

        // Everything OK — forward request to the backend
        // Note: accessing this worker on w1.edge-test.workers.dev (and not on your domain) will result in a 404 response, since w1.edge-test.workers.dev
        //   is a test URL that doesn't have an origin set behind it. In that case 404 can be interpreted as edge validation was successful.
        return fetch(request);

    } catch (err) {
        // Catch errors (invalid format, decode issues, etc.)
        const now = Math.floor(Date.now() / 1000);
        const responseBody = { time: now }; // Always return JSON 'time' so the client can update its internal clock
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

/**
 * Accepts an optionally-compressed JWT representation and returns a standard compact JWS string.
 * Throws a user-facing error on malformed short format.
 */
function fixShortJwt(jwt) {
    // handle short JWT form
    if (jwt.startsWith(".{`")) {
        // Note: clients that prefer to use shorter URLs (including highly constrained clients that can't compute signature)
        //       may send a shorter version of the JWT (JWT header skipped, and JWT payload in unencoded form with " replaced by ` ).
        // Short format of JWT might look like this:  .{`d`:`kL2R-ClientID-v9xgA`,`k`:`abcd`,`c`:`efgh`}.602R-JWT-signature
        
        // JWT is <header>.<payload>.<signature>
        //   - header is always "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9" since algorithm doesn't change
        //   - payload is shorter in unencoded form, but to use it efficiently we need to avoid URL characters that would be encoded into %XX.
        //       That is why the unencoded payload needs to be sent with '"' replaced by '`'.
        //       Signed payload must not contain:   '   %   .   ~   <space>.
        //   - signature is kept as is.

        const jwtPayload = jwt.split(".")[1];
        if ( /['"%\.~ ]/.test(jwtPayload) ) // short JWT payload must not contain ', ", %, ., ~, or space.
            throw new Error(UserFacingMessage.MALFORMED_JWT);
        // reconstruct valid JWT
        jwt = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.' + toBase64url(jwtPayload.replace(/`/g, '"')) + '.' + jwt.split(".")[2];
        
        // Clients with buffers limited to 256 chars will want to:
        //     (i) skip signature, (ii) skip JWT's header (iii) skip JWT's "i" claim, and (iv) transmit unencoded JWT payload

        // If more compression is needed, jwt payload should be replaced with an array of 3 base64url values: [DeviceID,KeyID,ClientType], like this:
        //   ?uca=YxVoNmLyYBHUweUKdjv1Hc6gWbWevXa5cS1fBxX4XWB3~.[kLvWoK4EMcI2YBNtJ7jSeJ2KuA5WlfIdIVRg2v9xgtA,abcd,efgh].602Rok-signature-Em1TAQ
        //   Further optimizations are possible by recompressing all base64 strings into custom encoding (base-85 or so, for ~6.4% reduction).
    }
    return jwt;
}

/**
 * Recomputes AuthHash for the received request.
 *
 * Inputs:
 *   - clientId: used to derive ClientAuthSecret via HMAC-SHA256(BackendDerivationKey, clientId)
 *   - jwt: bound into the hash (identity binding)
 *   - request: body/method/url are bound into the hash (integrity binding)
 *   - timestampSec: candidate timestamp reconstructed from TimeByte (replay window binding)
 *
 * Output:
 *   - 32-byte SHA-256 digest (Uint8Array)
 */
async function computeAuthHash(clientId, jwt, request, timestampSec) {
    const url = new URL(request.url);
    let urlPathWithQuery = url.pathname + url.search;
    // Remove the trailing authentication header from the URL if it is added as the last URL parameter.
    urlPathWithQuery = urlPathWithQuery.replace(new RegExp(`([?&])${REQUEST_PARAM_KEY}=[^&]*$`), ""); // remove trailing ?uca=... or &uca=...

    const urlForHash = url.host.toLowerCase() + urlPathWithQuery;
    if (/[\r\n]/.test(urlForHash))
        throw new Error(UserFacingMessage.INVALID_PREFIX_FORMAT);
    // Derive per-client secret (ClientAuthSecret) deterministically at the edge.
    const clientAuthSecret = toBase64url(await hmacSha256(EdgeState.backendDerivationKey, clientId));

    // Note: request.arrayBuffer() consumes the body, so pass in request.clone().
    const bodyBuf = new TextDecoder("utf-8").decode(await request.arrayBuffer()); // as text
    const bodyHashRaw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(bodyBuf));
    const bodyHash = uint8ArrayToHex(new Uint8Array(bodyHashRaw));

    // AuthHash = SHA-256( JWT || "\n" || ClientAuthSecret || "\n" || Timestamp || "\n" || Method || "\n" || BodyHash || "\n" || URL || "\n" )
    const stringToHash = `${jwt}\n${clientAuthSecret}\n${String(timestampSec)}\n` +
                         `${request.method.toUpperCase()}\n${bodyHash}\n${urlForHash}\n`;

    const hash = new Uint8Array(await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(stringToHash)
    ));
    return hash;
}

/**
 * Imports an Ed25519 public key (SPKI, base64) into WebCrypto so it can be used for signature verification.
 */
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

/**
 * Verifies an Ed25519 signature from a client.
 * clientId is the client Ed25519 public key encoded as base64url.
 * signature is base64url.
 * dataBytes is the raw bytes that were signed (here: AuthHash||TimeByte prefix).
 */
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


/**
 * Splits a JWT into header, payload, and signature, then verifies the signature.
 */
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

/**
 * Computes HMAC-SHA256(keyString, dataString) using WebCrypto and returns raw bytes (Uint8Array).
 */
async function hmacSha256(keyString, dataString) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(keyString),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        new TextEncoder().encode(dataString)
    );
    return new Uint8Array(signature);
}

/**
 * Constant-time (length-equal) byte-array comparison.
 */
function isEqualBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}

/**
 * Converts a Uint8Array to lowercase hex string.
 */
function uint8ArrayToHex(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++)
        s += u8[i].toString(16).padStart(2, "0");
    return s;
}

/**
 * Decodes base64url to Uint8Array.
 * Note: accepts both padded and unpadded base64url.
 */
function decodeBase64urlToUint8Array(base64url) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
        base64 += "=";
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

/**
 * Decodes base64url to a UTF-8 string.
 * Used for JWT header/payload JSON decoding.
 */
function decodeBase64urlToString(base64url) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4)
        base64 += "=";
    return atob(base64); 
}


/**
 * Encodes input as base64url (no padding).
 * Supported input types:
 *   - Uint8Array
 *   - ArrayBuffer
 *   - string (encoded as UTF-8 first)
 */
function toBase64url(input) {
    let bytes;
    if (input instanceof Uint8Array)
        bytes = input;
    else if (input instanceof ArrayBuffer)
        bytes = new Uint8Array(input);
    else if (typeof input === "string")
        bytes = new TextEncoder().encode(input);
    else
        throw new TypeError("Unsupported input type");
    const binary = String.fromCharCode(...bytes);
    return btoa(binary)
        .replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Syntactic JWT check:
 *   - exactly 3 dot-separated parts
 *   - each part must be base64url characters only (no padding)
 */
function isValidJwtFormat(jwt) {
    // This prevents tricks like adding '=' at the end of base64url encoding, etc.
    if (typeof jwt !== 'string')
        return false;
    const parts = jwt.split('.');
    if (parts.length !== 3)
        return false;
    return parts.every(part => isValidBase64url(part));
}

/**
 * Checks whether a string contains only base64url characters (no padding).
 */
function isValidBase64url(str) {
    return (typeof str === 'string' && /^[A-Za-z0-9_-]*$/.test(str));
}

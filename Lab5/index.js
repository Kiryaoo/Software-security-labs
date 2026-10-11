// Lab 5: extension of Lab 4 token_auth (Auth0 password grant, registration, refresh).
// JWT signature validation: RS256, Auth0 public certificate from /pem.
// Max mark: verified JWT payload -> compact JWE (dir / A256GCM) -> decryption/comparison.
'use strict';

const { randomUUID, randomBytes } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');

const envPath = path.join(__dirname, '.env');
try {
    process.loadEnvFile(envPath); // Node.js 20.12+ (recommended: Node 22)
} catch (e) {
    if (e.code !== 'ENOENT') console.warn('Could not load .env:', e.message);
}

// Convenient offline key generator: node index.js --generate-secret
// This command works even before installing npm dependencies.
if (process.argv.includes('--generate-secret')) {
    console.log(randomBytes(32).toString('base64'));
    process.exit(0);
}
const express = require('express');

const PORT = Number(process.env.PORT || 3000);
const AUTH0_DOMAIN = (process.env.AUTH0_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
const AUTH0_URL = `https://${AUTH0_DOMAIN}`;
const AUDIENCE = process.env.AUDIENCE;
const CONNECTION = process.env.CONNECTION || 'Username-Password-Authentication';
const APP_CLIENT_ID = process.env.APP_CLIENT_ID;
const M2M_ID = process.env.M2M_ID;
const M2M_SECRET = process.env.M2M_SECRET;
const REFRESH_BEFORE_SEC = Number(process.env.REFRESH_BEFORE_SEC || 300);
const DEMO_SHOW_SECRET = process.env.DEMO_SHOW_SECRET === '1';

if (!AUTH0_DOMAIN || !AUDIENCE || !APP_CLIENT_ID) {
    console.error('Set AUTH0_DOMAIN, AUDIENCE and APP_CLIENT_ID in .env');
    process.exit(1);
}

// The key belongs to the local server
if (!process.env.JWE_SECRET) {
    const created = randomBytes(32).toString('base64');
    fs.appendFileSync(envPath, `\nJWE_SECRET=${created}\n`, { encoding: 'utf8', flag: 'a' });
    process.env.JWE_SECRET = created;
    console.log('New JWE_SECRET generated and saved to .env:', created);
}

function decodeAesKey(base64) {
    if (typeof base64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error('JWE_SECRET must be standard base64');
    }
    const key = Buffer.from(base64, 'base64');
    if (key.length !== 32 || key.toString('base64') !== base64) {
        throw new Error('JWE_SECRET must be exactly 32 random bytes encoded as base64');
    }
    return key;
}

let JWE_KEY;
try {
    JWE_KEY = decodeAesKey(process.env.JWE_SECRET);
} catch (e) {
    console.error('Invalid JWE_SECRET:', e.message);
    process.exit(1);
}

const josePromise = import('jose');
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    next();
});

//  Authorization: <session-id> mechanism.
// Sessions remain in RAM to avoid saving access/refresh tokens in a plaintext JSON file.
const sessions = new Map();
app.use((req, res, next) => {
    const supplied = req.get('Authorization');
    const sessionId = supplied && sessions.has(supplied) ? supplied : randomUUID();
    if (!sessions.has(sessionId)) sessions.set(sessionId, {});
    req.sessionId = sessionId;
    req.session = sessions.get(sessionId);
    next();
});

//Auth0 helpers
async function auth0Post(pathname, body, headers = {}) {
    const isForm = pathname === '/oauth/token';
    const response = await fetch(`${AUTH0_URL}${pathname}`, {
        method: 'POST',
        headers: {
            'content-type': isForm ? 'application/x-www-form-urlencoded' : 'application/json',
            ...headers,
        },
        body: isForm ? new URLSearchParams(body).toString() : JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
}

function passwordGrant(login, password) {
    return auth0Post('/oauth/token', {
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        username: login,
        password: password,
        audience: AUDIENCE,
        scope: 'openid profile email offline_access',
        client_id: APP_CLIENT_ID,
        realm: CONNECTION,
        ...(process.env.APP_CLIENT_SECRET
            ? { client_secret: process.env.APP_CLIENT_SECRET }
            : {})
    });
}
function refreshGrant(refreshToken) {
    return auth0Post('/oauth/token', {
        grant_type: 'refresh_token', client_id: APP_CLIENT_ID,
        refresh_token: refreshToken,
    });
}
async function managementToken() {
    const r = await auth0Post('/oauth/token', {
        grant_type: 'client_credentials', audience: AUDIENCE,
        client_id: M2M_ID, client_secret: M2M_SECRET,
    });
    if (!r.ok) throw new Error(`Management API token failed (HTTP ${r.status})`);
    return r.data.access_token;
}
async function createAuth0User(login, password) {
    const mgmtToken = await managementToken();
    return auth0Post('/api/v2/users', {
        email: login, password, connection: CONNECTION,
        // Do NOT set email_verified:true for unverified registrations.
    }, { authorization: `Bearer ${mgmtToken}` });
}

// LAB 5: public key from Auth0 /pem 
let cachedPublicKey;
let publicKeyCachedAt = 0;
async function getAuth0PublicKey() {
    if (cachedPublicKey && Date.now() - publicKeyCachedAt < 60 * 60 * 1000) {
        return cachedPublicKey;
    }
    const response = await fetch(`${AUTH0_URL}/pem`);
    if (!response.ok) throw new Error(`Cannot retrieve Auth0 /pem (HTTP ${response.status})`);
    const pem = (await response.text()).trim();
    const { importX509, importSPKI } = await josePromise;
    if (pem.includes('-----BEGIN CERTIFICATE-----')) {
        cachedPublicKey = await importX509(pem, 'RS256');
    } else if (pem.includes('-----BEGIN PUBLIC KEY-----')) {
        cachedPublicKey = await importSPKI(pem, 'RS256');
    } else {
        throw new Error('Auth0 /pem returned neither an X.509 certificate nor a public key');
    }
    publicKeyCachedAt = Date.now();
    return cachedPublicKey;
}
// Verify the RSA256 signature of an Auth0 JWT. Throws on failure.
async function verifyAuth0Jwt(token, expectedAudience = AUDIENCE) {
    if (typeof token !== 'string' || token.split('.').length !== 3) {
        throw new Error('Access Token is not a JWT (three dot-separated parts expected)');
    }
    const { jwtVerify, decodeProtectedHeader } = await josePromise;
    const header = decodeProtectedHeader(token);
    if (header.alg !== 'RS256') throw new Error(`Expected RS256, received ${header.alg || 'unknown'}`);
    const result = await jwtVerify(token, await getAuth0PublicKey(), {
        issuer: `${AUTH0_URL}/`, audience: expectedAudience,
        algorithms: ['RS256'],
    });
    return { payload: result.payload, header: result.protectedHeader };
}

function saveTokens(session, response, verifiedPayload) {
    session.accessToken = response.access_token;
    if (response.refresh_token) session.refreshToken = response.refresh_token;
    if (response.id_token) session.idToken = response.id_token;
    if (!Number.isFinite(verifiedPayload.exp)) throw new Error('JWT has no exp claim');
    session.expiresAt = verifiedPayload.exp * 1000;
}
function clearAuth(session) {
    delete session.username;
    delete session.login;
    delete session.accessToken;
    delete session.refreshToken;
    delete session.idToken;
    delete session.expiresAt;
}

// Token lifetime check + refresh_token grant.
async function ensureFreshToken(req, res, next) {
    const session = req.session;
    if (!session.accessToken) return next();
    let secondsLeft = Math.floor((session.expiresAt - Date.now()) / 1000);
    req.tokenInfo = { secondsLeft, refreshed: false };
    if (secondsLeft > REFRESH_BEFORE_SEC) return next();

    if (session.refreshToken) {
        try {
            const r = await refreshGrant(session.refreshToken);
            if (r.ok) {
                // Refuse to store the newly obtained token unless its signature is valid.
                const verified = await verifyAuth0Jwt(r.data.access_token);
                saveTokens(session, r.data, verified.payload);
                req.tokenInfo = {
                    secondsLeft: Math.floor((session.expiresAt - Date.now()) / 1000),
                    refreshed: true,
                };
                return next();
            }
            console.warn('Refresh rejected:', r.status, r.data.error);
        } catch (e) {
            console.warn('Refresh failed:', e.message);
        }
    }
    if (secondsLeft <= 0) {
        clearAuth(session);
        return res.status(401).json({ error: 'Token expired and refresh failed' });
    }
    next();
}
async function requireVerifiedSession(req, res, next) {
    if (!req.session.accessToken) return res.status(401).json({ error: 'Login required' });
    try {
        req.verifiedJwt = await verifyAuth0Jwt(req.session.accessToken);
        next();
    } catch (e) {
        clearAuth(req.session);
        res.status(401).json({ error: `JWT verification failed: ${e.message}` });
    }
}

app.get('/', ensureFreshToken, async (req, res) => {
    if (!req.session.accessToken) return res.sendFile(path.join(__dirname, 'index.html'));
    try {
        const jwt = await verifyAuth0Jwt(req.session.accessToken);
        res.json({
            username: req.session.username,
            accessToken: req.session.accessToken,
            refreshTokenAvailable: Boolean(req.session.refreshToken),
            tokenExpiresInSeconds: Math.max(0, Math.floor((req.session.expiresAt - Date.now()) / 1000)),
            tokenRefreshed: Boolean(req.tokenInfo?.refreshed),
            signatureValid: true,
            publicKeyUrl: `${AUTH0_URL}/pem`,
            algorithm: jwt.header.alg,
            payload: jwt.payload,
            demoCanShowSecret: DEMO_SHOW_SECRET,
        });
    } catch (e) {
        clearAuth(req.session);
        res.status(401).json({ error: `JWT verification failed: ${e.message}` });
    }
});
app.get('/logout', (req, res) => {
    sessions.delete(req.sessionId);
    res.redirect('/');
});
app.post('/api/login', async (req, res) => {
    const { login, password } = req.body || {};
    if (!login || !password) return res.status(400).json({ error: 'Email and password required' });
    try {
        const r = await passwordGrant(login, password);
        if (!r.ok) {
    console.error('Auth0 login failed:', {
        status: r.status,
        error: r.data.error,
        description: r.data.error_description
    });

    return res.status(r.status).json({
        error: r.data.error_description ||
               r.data.message ||
               'Invalid username and/or password'
    });
}
        const access = await verifyAuth0Jwt(r.data.access_token);
        let username = login;
        if (r.data.id_token) {
            try {
                const id = await verifyAuth0Jwt(r.data.id_token, APP_CLIENT_ID);
                username = id.payload.email || id.payload.nickname || login;
            } catch (e) {
                // Access JWT was verified above. Never trust claims from an unverified ID token.
                console.warn('ID token not verified; displaying the submitted login:', e.message);
            }
        }
        saveTokens(req.session, r.data, access.payload);
        req.session.username = username;
        req.session.login = login;
        res.json({ token: req.sessionId });
    } catch (e) {
        console.error('Login failed:', e.message);
        res.status(502).json({ error: `Auth0/JWT error: ${e.message}` });
    }
});
app.post('/api/register', async (req, res) => {
    const { login, password } = req.body || {};
    if (!login || !password) return res.status(400).json({ error: 'Email and password required' });
    if (!M2M_ID || !M2M_SECRET) return res.status(503).json({ error: 'M2M configuration missing in .env' });
    try {
        const r = await createAuth0User(login, password);
        if (!r.ok) return res.status(r.status).json({ error: r.data.message || 'Register failed' });
        res.status(201).json({ user_id: r.data.user_id, email: r.data.email });
    } catch (e) {
        console.error('Registration failed:', e.message);
        res.status(502).json({ error: 'Could not register user via Auth0' });
    }
});

//LAB 5 routes 
app.get('/api/lab5/verify', ensureFreshToken, requireVerifiedSession, (req, res) => {
    res.json({ valid: true, algorithm: req.verifiedJwt.header.alg,
        issuer: req.verifiedJwt.payload.iss, audience: req.verifiedJwt.payload.aud,
        payload: req.verifiedJwt.payload });
});

app.post('/api/lab5/encrypt', ensureFreshToken, requireVerifiedSession, async (req, res) => {
    try {
        const { CompactEncrypt } = await josePromise;
        const payload = req.verifiedJwt.payload; // VERIFIED JWT payload, not an untrusted decode
        const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
        const jwe = await new CompactEncrypt(plaintext)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'JWE', cty: 'application/json' })
            .encrypt(JWE_KEY);
        res.json({ jwe, originalPayload: payload, algorithm: 'dir / A256GCM' });
    } catch (e) {
        res.status(500).json({ error: `Encryption failed: ${e.message}` });
    }
});

app.post('/api/lab5/decrypt', ensureFreshToken, requireVerifiedSession, async (req, res) => {
    const { jwe, demoKey } = req.body || {};
    if (typeof jwe !== 'string' || jwe.length < 10 || jwe.length > 30000) {
        return res.status(400).json({ error: 'Provide a compact JWE string' });
    }
    try {
        // Supplying a key is optional; for a lab demo only. Never save input keys.
        const key = demoKey ? decodeAesKey(demoKey) : JWE_KEY;
        const { compactDecrypt } = await josePromise;
        const { plaintext, protectedHeader } = await compactDecrypt(jwe, key, {
            keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'],
        });
        const decryptedPayload = JSON.parse(Buffer.from(plaintext).toString('utf8'));
        const matchesOriginal = isDeepStrictEqual(decryptedPayload, req.verifiedJwt.payload);
        res.json({ success: true, protectedHeader, decryptedPayload, matchesOriginal });
    } catch (e) {
        res.status(400).json({ success: false,
            error: 'JWE decryption failed (wrong secret, damaged JWE, or invalid payload)' });
    }
});

app.post('/api/lab5/tamper-test', ensureFreshToken, requireVerifiedSession, async (req, res) => {
    const parts = req.session.accessToken.split('.');

    const originalPayload = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString('utf8')
    );

    const payload = {
        ...originalPayload,
        lab5_modified: originalPayload.lab5_modified !== true
    };

    const changed = [
        parts[0],
        Buffer.from(JSON.stringify(payload)).toString('base64url'),
        parts[2]
    ].join('.');

    //Data for displaying the modified JWT in the browser.
    const details = {
        modifiedToken: changed,
        modifiedPayload: payload,
        signatureUnchanged: true,
        change: {
            claim: 'lab5_modified',
            before: originalPayload.lab5_modified ?? null,
            after: payload.lab5_modified
        }
    };

    try {
        await verifyAuth0Jwt(changed);

        res.status(500).json({
            ...details,
            rejected: false,
            valid: true,
            error: 'Unexpectedly accepted changed JWT'
        });
    } catch (e) {
        // A failed signature verification is expected.
        if (e.code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
            return res.status(502).json({
                ...details,
                rejected: false,
                error: e.message || 'Could not complete the negative test',
                errorCode: e.code || 'NEGATIVE_TEST_ERROR'
            });
        }

        res.json({
            ...details,
            rejected: true,
            valid: false,
            reason: 'Modified payload invalidates the original RS256 signature',
            error: e.message,
            errorCode: e.code
        });
    }
});

// Only an opt-in LOCAL demonstration may display the AES secret.
app.get('/api/lab5/demo-secret', ensureFreshToken, requireVerifiedSession, (req, res) => {
    const local = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
    if (!DEMO_SHOW_SECRET || !local) {
        return res.status(403).json({ error: 'Enable DEMO_SHOW_SECRET=1 for a localhost-only demo' });
    }
    res.json({ secret: process.env.JWE_SECRET });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log(`Lab 5 running at http://localhost:${PORT}`);
    console.log('Auth0 RS256 public key:', `${AUTH0_URL}/pem`);
    console.log('JWE_SECRET loaded from .env; demo display:', DEMO_SHOW_SECRET ? 'ON' : 'OFF');
});

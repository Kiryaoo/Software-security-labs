const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const path = require('node:path');
const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');

function readConfig() {
    try {
        process.loadEnvFile(path.join(__dirname, '.env'));
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    }

    for (const name of ['AUTH0_DOMAIN', 'APP_CLIENT_ID']) {
        if (!process.env[name] || /YOUR_|REPLACE_WITH_/.test(process.env[name])) {
            throw new Error(`Fill ${name} in Lab6/.env (see .env.example)`);
        }
    }

    const domain = process.env.AUTH0_DOMAIN.trim();
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        throw new Error('AUTH0_DOMAIN must be a hostname without https:// or a path');
    }

    const port = Number(process.env.PORT || 3000);
    const refreshBefore = Number(process.env.REFRESH_BEFORE_SEC || 300);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !Number.isFinite(refreshBefore) || refreshBefore < 0) {
        throw new Error('Check PORT and REFRESH_BEFORE_SEC');
    }

    const baseUrl = new URL(process.env.BASE_URL || `http://localhost:${port}`);
    const redirectUri = new URL(process.env.REDIRECT_URI || `${baseUrl.origin}/callback`);
    if (!['http:', 'https:'].includes(baseUrl.protocol) ||
        redirectUri.origin !== baseUrl.origin || redirectUri.pathname !== '/callback' ||
        redirectUri.search || redirectUri.hash || baseUrl.pathname !== '/' || baseUrl.search || baseUrl.hash) {
        throw new Error('BASE_URL must be an origin; REDIRECT_URI must be BASE_URL + /callback');
    }

    const sessionSecret = process.env.SESSION_SECRET || randomBytes(32).toString('hex');
    if (sessionSecret.length < 32 || /REPLACE_WITH_/.test(sessionSecret)) {
        throw new Error('SESSION_SECRET, if provided, must contain at least 32 random characters');
    }

    return {
        auth0Url: `https://${domain}`,
        clientId: process.env.APP_CLIENT_ID,
        clientSecret: process.env.APP_CLIENT_SECRET || undefined,
        sessionSecret,
        audience: process.env.AUDIENCE || '',
        baseUrl: baseUrl.origin,
        redirectUri: redirectUri.href,
        port,
        refreshBefore,
    };
}

const random = () => randomBytes(32).toString('base64url');
const sessionSaves = new Map();
function persist(req) {
    const sessionId = req.sessionID;
    const previous = sessionSaves.get(sessionId) || Promise.resolve();
    let current;
    current = previous.catch(() => undefined).then(() => new Promise((resolve, reject) => {
        req.session.save(error => error ? reject(error) : resolve());
    })).finally(() => {
        if (sessionSaves.get(sessionId) === current) sessionSaves.delete(sessionId);
    });
    sessionSaves.set(sessionId, current);
    return current;
}
const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
const destroy = (req) => new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));

function equal(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const left = Buffer.from(a);
    const right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
}

async function createApp(config) {
    const { createRemoteJWKSet, jwtVerify } = await import('jose');
    const jwks = createRemoteJWKSet(new URL(`${config.auth0Url}/.well-known/jwks.json`));
    const refreshes = new Map();
    const app = express();

    app.disable('x-powered-by');
    app.use(express.urlencoded({ extended: false, limit: '10kb' }));
    app.use((req, res, next) => {
        res.set({
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff',
        });
        next();
    });

    app.use(session({
        name: 'lab6.sid',
        secret: config.sessionSecret,
        store: new FileStore({
            path: path.join(__dirname, 'sessions'),
            ttl: 8 * 60 * 60,
            retries: 0,
        }),
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: config.baseUrl.startsWith('https://'),
            maxAge: 8 * 60 * 60 * 1000,
        },
    }));

    async function tokenGrant(parameters) {
        const body = { ...parameters, client_id: config.clientId };
        if (config.clientSecret) body.client_secret = config.clientSecret;

        const response = await fetch(`${config.auth0Url}/oauth/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(body),
            signal: AbortSignal.timeout(15000),
        });

        const data = await response.json();
        if (!response.ok) {
            console.warn(`Auth0 token endpoint: HTTP ${response.status}, ${data.error || 'request_failed'}`);
            throw new Error('Auth0 could not issue a token. Check the application settings and try signing in again.');
        }

        if (typeof data.access_token !== 'string' || !data.access_token ||
            typeof data.expires_in !== 'number' || data.expires_in <= 0 ||
            data.token_type?.toLowerCase() !== 'bearer') {
            throw new Error('Auth0 returned an incomplete token response');
        }

        return data;
    }

    async function verifyIdentity(idToken, nonce, expectedSub) {
        if (typeof idToken !== 'string') throw new Error('Auth0 did not return an ID token');

        const { payload } = await jwtVerify(idToken, jwks, {
            algorithms: ['RS256'],
            issuer: `${config.auth0Url}/`,
            audience: config.clientId,
            requiredClaims: ['iss', 'aud', 'exp', 'iat', 'sub'],
            clockTolerance: 5,
        });

        if ((Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== config.clientId) ||
            (payload.azp !== undefined && payload.azp !== config.clientId)) {
            throw new Error('Unexpected authorized party in ID token');
        }

        if (nonce !== undefined && !equal(payload.nonce, nonce)) throw new Error('Invalid ID token nonce');
        if (typeof payload.sub !== 'string' || !payload.sub || (expectedSub && payload.sub !== expectedSub)) {
            throw new Error('Unexpected ID token subject');
        }

        return payload;
    }

    function saveTokens(currentSession, tokens) {
        currentSession.accessToken = tokens.access_token;
        if (tokens.refresh_token) currentSession.refreshToken = tokens.refresh_token;
        currentSession.expiresAt = Date.now() + tokens.expires_in * 1000;
    }

    async function startLogin(req, res) {
        await regenerate(req);
        const state = random();
        const nonce = random();
        const verifier = random();
        req.session.oauth = { state, nonce, verifier, createdAt: Date.now() };
        await persist(req);

        const authorizeUrl = new URL(`${config.auth0Url}/authorize`);
        authorizeUrl.search = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            response_type: 'code',
            response_mode: 'query',
            scope: 'openid profile email offline_access',
            state,
            nonce,
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256',
        }).toString();

        if (config.audience) authorizeUrl.searchParams.set('audience', config.audience);
        if (req.path === '/register') authorizeUrl.searchParams.set('screen_hint', 'signup');
        res.redirect(authorizeUrl.href);
    }

    app.get('/login', startLogin);
    app.get('/register', startLogin);

    app.get('/callback', async (req, res) => {
        const transaction = req.session.oauth;
        if (!transaction || !equal(req.query.state, transaction.state) ||
            Date.now() - transaction.createdAt > 10 * 60 * 1000) {
            return res.status(400).type('text').send('Invalid or expired state. Open /login to sign in again.');
        }

        delete req.session.oauth;
        await persist(req);

        if (req.query.error) {
            return res.status(400).type('text').send('Sign-in was cancelled or denied by Auth0. Open /login to try again.');
        }

        if (typeof req.query.code !== 'string' || !req.query.code) {
            return res.status(400).type('text').send('Missing authorization code. Open /login to try again.');
        }

        const tokens = await tokenGrant({
            grant_type: 'authorization_code',
            code: req.query.code,
            redirect_uri: config.redirectUri,
            code_verifier: transaction.verifier,
        });

        const claims = await verifyIdentity(tokens.id_token, transaction.nonce);
        await regenerate(req);
        req.session.user = {
            sub: claims.sub,
            email: claims.email,
            name: claims.name || claims.nickname || claims.email || claims.sub,
        };
        req.session.csrf = random();
        saveTokens(req.session, tokens);
        await persist(req);

        console.log('Authorization Code Flow completed: ID token verified, user session created.');
        res.redirect('/');
    });

    async function ensureFreshToken(req, res, next) {
        const current = req.session;
        if (!current.user || !current.accessToken) return res.status(401).json({ error: 'Login required', login: '/login' });

        let secondsLeft = Math.floor((current.expiresAt - Date.now()) / 1000);
        let refreshed = false;
        if (secondsLeft <= config.refreshBefore && current.refreshToken) {
            try {
                let pending = refreshes.get(req.sessionID);
                if (!pending) {
                    pending = (async () => {
                        const tokens = await tokenGrant({ grant_type: 'refresh_token', refresh_token: current.refreshToken });
                        if (tokens.id_token) await verifyIdentity(tokens.id_token, undefined, current.user.sub);
                        return tokens;
                    })();
                    refreshes.set(req.sessionID, pending);
                }

                const tokens = await pending;
                saveTokens(current, tokens);
                await persist(req);
                refreshed = true;
            } catch {
                console.warn('Token refresh failed; checking the existing token lifetime.');
            } finally {
                refreshes.delete(req.sessionID);
            }

            secondsLeft = Math.floor((current.expiresAt - Date.now()) / 1000);
        }

        if (secondsLeft <= 0) {
            await destroy(req);
            res.clearCookie('lab6.sid', { path: '/' });
            return res.status(401).json({ error: 'Token expired. Sign in again.', login: '/login' });
        }

        req.tokenInfo = { secondsLeft, refreshed };
        next();
    }

    app.get('/', (req, res) => {
        if (!req.session.user) return res.redirect('/login');
        res.sendFile(path.join(__dirname, 'index.html'));
    });

    app.get('/api/session', ensureFreshToken, (req, res) => res.json({
        username: req.session.user.email || req.session.user.name,
        user: req.session.user,
        grantType: 'authorization_code',
        idTokenVerified: true,
        accessToken: req.session.accessToken,
        refreshTokenAvailable: Boolean(req.session.refreshToken),
        tokenExpiresInSeconds: req.tokenInfo.secondsLeft,
        tokenRefreshed: req.tokenInfo.refreshed,
        csrfToken: req.session.csrf,
    }));

    app.post('/logout', async (req, res) => {
        if (!req.session.user || !equal(req.body?.csrf, req.session.csrf)) {
            return res.status(403).type('text').send('Invalid logout request');
        }

        await destroy(req);
        res.clearCookie('lab6.sid', { path: '/' });

        const logoutUrl = new URL(`${config.auth0Url}/v2/logout`);
        logoutUrl.search = new URLSearchParams({ client_id: config.clientId, returnTo: `${config.baseUrl}/` });
        res.redirect(logoutUrl.href);
    });

    app.use((error, req, res, next) => {
        console.error(`Request failed: ${error.code || error.name || 'Error'}`);
        if (res.headersSent) return next(error);
        res.status(502).type('text').send('Authentication service request failed. Check Auth0 settings, then open /login to try again.');
    });

    return app;
}

if (require.main === module) {
    (async () => {
        const config = readConfig();
        const app = await createApp(config);
        app.listen(config.port, () => console.log(`Lab 6: ${config.baseUrl}`));
    })().catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    });
}

module.exports = { createApp, readConfig };

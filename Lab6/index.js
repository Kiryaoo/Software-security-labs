// Lab 

const express = require('express');
const session = require('express-session');
const path = require('node:path');
const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');

function readConfig() {
    try { process.loadEnvFile(path.join(__dirname, '.env')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    for (const name of ['AUTH0_DOMAIN', 'APP_CLIENT_ID']) {
        if (!process.env[name] || /YOUR_|REPLACE_WITH_/.test(process.env[name])) {
            throw new Error(`Fill ${name} in .env`);
        }
    }
    const domain = process.env.AUTH0_DOMAIN.trim();
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) throw new Error('AUTH0_DOMAIN must be a hostname');
    const port = Number(process.env.PORT || 3000);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
    const baseUrl = new URL(process.env.BASE_URL || `http://localhost:${port}`);
    const redirectUri = new URL(process.env.REDIRECT_URI || `${baseUrl.origin}/callback`);
    if (!['http:', 'https:'].includes(baseUrl.protocol) || baseUrl.pathname !== '/' || baseUrl.search || baseUrl.hash ||
        redirectUri.origin !== baseUrl.origin || redirectUri.pathname !== '/callback' || redirectUri.search || redirectUri.hash) {
        throw new Error('Use BASE_URL as an origin and REDIRECT_URI as BASE_URL + /callback');
    }
    const sessionSecret = process.env.SESSION_SECRET || randomBytes(32).toString('hex');
    if (sessionSecret.length < 32 || /REPLACE_WITH_/.test(sessionSecret)) throw new Error('Invalid SESSION_SECRET');
    return {
        auth0Url: `https://${domain}`,
        clientId: process.env.APP_CLIENT_ID,
        audience: process.env.AUDIENCE || '',
        baseUrl: baseUrl.origin,
        redirectUri: redirectUri.href,
        port,
        sessionSecret,
    };
}

const random = () => randomBytes(32).toString('base64url');
const persist = req => new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
const regenerate = req => new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
function equal(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const left = Buffer.from(a), right = Buffer.from(b);
    return left.length === right.length && timingSafeEqual(left, right);
}

function createApp(config) {
    const app = express();
    app.disable('x-powered-by');
    app.use((req, res, next) => {
        res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' });
        next();
    });
    app.use(session({
        name: 'lab6.basic.sid',
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, sameSite: 'lax', secure: config.baseUrl.startsWith('https://'), maxAge: 60 * 60 * 1000 },
    }));

    app.get('/', (req, res) => res.redirect('/login'));

    app.get('/login', async (req, res) => {
        await regenerate(req);
        const state = random();
        const verifier = random();
        req.session.oauth = { state, createdAt: Date.now() };
        await persist(req);
        const authorizeUrl = new URL(`${config.auth0Url}/authorize`);
        authorizeUrl.search = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            response_type: 'code',
            response_mode: 'query',
            scope: 'openid profile email',
            state,
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256',
        }).toString();
        if (config.audience) authorizeUrl.searchParams.set('audience', config.audience);
        res.redirect(authorizeUrl.href);
    });

    app.get('/callback', async (req, res) => {
        const transaction = req.session.oauth;
        if (!transaction || !equal(req.query.state, transaction.state) || Date.now() - transaction.createdAt > 10 * 60 * 1000) {
            return res.status(400).type('text').send('Invalid or expired state. Open /login to try again.');
        }
        delete req.session.oauth;
        await persist(req);
        if (req.query.error) return res.status(400).type('text').send('Auth0 sign-in was cancelled or denied. Open /login to try again.');
        if (typeof req.query.code !== 'string' || !req.query.code) {
            return res.status(400).type('text').send('Missing authorization code. Open /login to try again.');
        }
  
        res.type('text').send('Callback');
    });
    app.use((error, req, res, next) => {
        console.error(`Request failed: ${error.code || error.name || 'Error'}`);
        if (res.headersSent) return next(error);
        res.status(500).type('text').send('Request failed. Open /login to try again.');
    });
    return app;
}

if (require.main === module) {
    try {
        const config = readConfig();
        createApp(config).listen(config.port, () => console.log(`Lab 6 basic: ${config.baseUrl}`));
    } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { createApp, readConfig };

// Lab 4: token_auth + Auth0 (password grant), user registration, token lifetime check with refresh
const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

try {
    process.loadEnvFile(); // loads .env 
} catch (e) {
    console.log('.env file not found, using process environment');
}

const port = 3000;

const AUTH0_URL = `https://${process.env.AUTH0_DOMAIN}`;
const AUDIENCE = process.env.AUDIENCE;
const CONNECTION = 'Username-Password-Authentication';
const APP_CLIENT_ID = process.env.APP_CLIENT_ID; // login application
const M2M_ID = process.env.M2M_ID; // M2M application, used only to create users
const M2M_SECRET = process.env.M2M_SECRET;
// Refresh the token if less than this many seconds are left
const REFRESH_BEFORE_SEC = Number(process.env.REFRESH_BEFORE_SEC || 300);

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

// ---------- Auth0 helpers ----------
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
        grant_type: 'password',
        username: login,
        password,
        audience: AUDIENCE,
        scope: 'openid profile email offline_access',
        client_id: APP_CLIENT_ID,
    });
}

function refreshGrant(refreshToken) {
    return auth0Post('/oauth/token', {
        grant_type: 'refresh_token',
        client_id: APP_CLIENT_ID,
        refresh_token: refreshToken,
    });
}

app.get('/', ensureFreshToken, (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            accessToken: req.session.accessToken,
            refreshTokenAvailable: Boolean(req.session.refreshToken),
            tokenExpiresInSeconds: req.tokenInfo && req.tokenInfo.secondsLeft,
            tokenRefreshed: req.tokenInfo && req.tokenInfo.refreshed,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    try {
        const r = await passwordGrant(login, password);
        if (!r.ok) {
            return res.status(401).send();
        }

        saveTokens(req.session, r.data);
        if (!r.data.refresh_token) {
            console.warn(
                'Auth0 did not return a refresh token. Enable Allow Offline Access for the API, ' +
                'enable the Password grant for the application, and request offline_access.'
            );
        }
        const claims = decodeJwt(r.data.id_token);
        req.session.username = claims.email || claims.nickname || login;
        req.session.login = login;

        return res.json({ token: req.sessionId });
    } catch (e) {
        console.log(e.message);
        return res.status(500).send();
    }
});

// Additional feature: create a user in Auth0 via Management API
app.post('/api/register', async (req, res) => {
    const { login, password } = req.body;

    try {
        const r = await createAuth0User(login, password);
        /*
        const registrationRequest = await auth0Post('/api/v2/users', {
            email: login,
            password,
            connection: CONNECTION,
            email_verified: true,
        }, { authorization: `Bearer ${mgmtToken}` });

        */
        if (!r.ok) {
            return res.status(r.status).json({ error: r.data.message || 'register failed' });
        }
        return res.status(201).json({ user_id: r.data.user_id, email: r.data.email });
    } catch (e) {
        console.log(e.message);
        return res.status(500).json({ error: 'register failed' });
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

// Max score task
// User creation through Auth0 Management API
async function managementToken() {
    const r = await auth0Post('/oauth/token', {
        grant_type: 'client_credentials',
        audience: AUDIENCE,
        client_id: M2M_ID,
        client_secret: M2M_SECRET,
    });
    if (!r.ok) throw new Error(`management token: ${r.status} ${JSON.stringify(r.data)}`);
    return r.data.access_token;
}

async function createAuth0User(login, password) {
    const mgmtToken = await managementToken();
    return auth0Post('/api/v2/users', {
        email: login,
        password,
        connection: CONNECTION,
        email_verified: true,
    }, {
        authorization: `Bearer ${mgmtToken}`,
    });
}

// Signature is not verified here (added in Lab 5)
function decodeJwt(token) {
    try {
        return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    } catch (e) {
        return {};
    }
}

function saveTokens(session, tokens) {
    session.accessToken = tokens.access_token;
    if (tokens.refresh_token) {
        session.refreshToken = tokens.refresh_token; // new value only if rotation is enabled
    }
    if (tokens.id_token) {
        session.idToken = tokens.id_token;
    }
    session.expiresAt = Date.now() + Number(tokens.expires_in || 0) * 1000;
}

// Token lifetime check and automatic refresh through refresh_token grant
async function ensureFreshToken(req, res, next) {
    const session = req.session;
    if (!session.accessToken) {
        return next();
    }

    const secondsLeft = Math.floor((session.expiresAt - Date.now()) / 1000);
    req.tokenInfo = { secondsLeft, refreshed: false };

    if (secondsLeft > REFRESH_BEFORE_SEC) {
        return next();
    }

    console.log(`Token expires in ${secondsLeft}s, refreshing`);
    if (session.refreshToken) {
        try {
            const r = await refreshGrant(session.refreshToken);
            if (r.ok) {
                saveTokens(session, r.data);
                req.tokenInfo = {
                    secondsLeft: Math.floor((session.expiresAt - Date.now()) / 1000),
                    refreshed: true,
                };
                return next();
            }
            console.log('Refresh failed:', r.status, r.data);
        } catch (e) {
            console.log('Refresh error:', e.message);
        }
    }

    // Refresh failed and the token is already expired: end the session
    if (secondsLeft <= 0) {
        delete session.username;
        delete session.accessToken;
        delete session.refreshToken;
        delete session.expiresAt;
        return res.status(401).json({ error: 'token expired' });
    }
    next();
}

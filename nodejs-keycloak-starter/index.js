/**
 * @file index.js
 * @description
 * Node.js starter application implementing the OpenID Connect
 * Authorization Code Flow with Keycloak.
 *
 * Flow:
 * 1. Redirects users to Keycloak for authentication.
 * 2. Receives the authorization code callback.
 * 3. Exchanges the code for access and identity tokens.
 * 4. Can be extended to store the authenticated user in the session.
 *
 * Configuration:
 * - Keycloak realm and server URL
 * - Client ID and client secret
 * - OAuth2 redirect URI
 *
 * Routes:
 * - GET /login    Redirects the user to Keycloak for authentication.
 * - GET /callback Exchanges the authorization code for tokens.
 */
const express = require('express');
const axios = require('axios');
const session = require('express-session');
const app = express();

const APP_PORT = 3000;
let SAVE_SESSION = true;

const config = {
    clientId: 'client-id',
    clientSecret: 'client-secret',
    realm: 'master',
    authServerUrl: 'http://localhost:8080',
    redirectUri: 'http://localhost:3000/callback',
    postLogoutRedirectUri: 'http://localhost:3000/'
};

// Session configuration
app.use(
    session({
        secret: 'replace-with-a-strong-session-secret',
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false, // Set to true when using HTTPS
            maxAge: 60 * 60 * 1000
        }
    })
);

// Home route
app.get('/', (req, res) => {
    if (!req.session.user) {
        return res.send(`
            <h1>Keycloak Login</h1>
            <a href="/login">Login with Keycloak</a>
        `);
    }

    res.send(`
        <h1>Welcome, ${req.session.user.preferred_username || 'User'}</h1>
        <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
        <a href="/logout">Logout</a>
    `);
});

// Route to initiate login
app.get('/login', (req, res) => {
    const authUrl = `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/auth` +
        `?client_id=${config.clientId}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
        `&scope=openid`;


    res.redirect(authUrl); // Redirect to Keycloak for login
});

// Callback route to handle Keycloak's redirect after authentication
app.get('/callback', async (req, res) => {
    const authCode = req.query.code;

    if (!authCode) {
        return res.status(400).send('Authorization code is missing');
    }

    try {
        // Exchange authorization code for tokens
        const tokenResponse = await axios.post(
            `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: config.clientId,
                client_secret: config.clientSecret,
                code: authCode,
                redirect_uri: config.redirectUri
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );


        if (SAVE_SESSION) {
            const tokens = tokenResponse.data;

            // Retrieve the authenticated user's information
            const userResponse = await axios.get(
                `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/userinfo`,
                {
                    headers: {
                        Authorization: `Bearer ${tokens.access_token}`
                    }
                }
            );

            // Store user and tokens in the session
            req.session.user = userResponse.data;
            req.session.accessToken = tokens.access_token;
            req.session.refreshToken = tokens.refresh_token;
            req.session.idToken = tokens.id_token;

            res.redirect('/');

        } else {

            // Token response (contains access_token, refresh_token, etc.)
            res.json(tokenResponse.data);

        }

    } catch (error) {
        console.error('Token exchange failed:', error);
        res.status(500).send('Token exchange failed');
    }
});

// Logout from the application and Keycloak
app.get('/logout', (req, res) => {
    const idToken = req.session.idToken;

    req.session.destroy((error) => {
        if (error) {
            return res.status(500).send('Logout failed');
        }

        let logoutUrl =
            `${config.authServerUrl}/realms/${config.realm}` +
            `/protocol/openid-connect/logout` +
            `?post_logout_redirect_uri=${encodeURIComponent(
                config.postLogoutRedirectUri
            )}` +
            `&client_id=${encodeURIComponent(config.clientId)}`;

        if (idToken) {
            logoutUrl += `&id_token_hint=${encodeURIComponent(idToken)}`;
        }

        res.redirect(logoutUrl);
    });
});

app.listen(APP_PORT, () => {
    console.log(`Server running at http://localhost:${APP_PORT}`);
});
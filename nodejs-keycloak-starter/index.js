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
const app = express();

const APP_PORT = 3000;

const config = {
    clientId: 'client-secret',                                       
    clientSecret: 'client-secret',
    realm: 'master',                        
    authServerUrl: 'http://localhost:8080',  
    redirectUri: 'http://localhost:3000/callback'
};

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

        // Token response (contains access_token, refresh_token, etc.)
        res.json(tokenResponse.data);
    } catch (error) {
        console.error('Token exchange failed:', error);
        res.status(500).send('Token exchange failed');
    }
});

app.listen(APP_PORT, () => {
    console.log(`Server running at http://localhost:${APP_PORT}`);
});
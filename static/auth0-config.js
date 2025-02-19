const config = {
    clientId: 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5',
    redirectUri: window.location.origin + '/oauth2/callback',
    scope: 'openid profile email offline_access',
    audience: 'https://dev-lk0vcub54idn0l5c.us.auth0.com/api/v2/',
    responseType: 'token id_token',
    tokenType: 'JWT',
};

export { config };

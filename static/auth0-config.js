const config = {
    clientId: 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5',
    redirectUri: window.location.origin + '/oauth2/callback',
    scope: 'openid profile email offline_access',
    audience: 'https://calorie-gpt.onrender.com',
    responseType: 'token id_token',
    tokenType: 'JWT',
};

export { config };

const config = {
    clientId: 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5',
    redirectUri: window.location.origin + '/oauth2/callback',
    scope: 'openid profile email',
    audience: 'https://calorie-gpt-api',
    responseType: 'code',
};

export { config };

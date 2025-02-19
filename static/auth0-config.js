const AUTH0_DOMAIN = 'dev-lk0vcub54idn0l5c.us.auth0.com';
const AUTH0_CLIENT_ID = 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5';  
const AUTH0_AUDIENCE = 'https://calorie-gpt-api';

const config = {
    clientId: AUTH0_CLIENT_ID,
    redirectUri: window.location.origin + '/oauth2/callback',
    scope: 'openid profile email',
    audience: AUTH0_AUDIENCE,
    responseType: 'code',
    domain: AUTH0_DOMAIN,
};

export { config };

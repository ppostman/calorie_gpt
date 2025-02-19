const AUTH0_DOMAIN = 'dev-lk0vcub54idn0l5c.us.auth0.com';
const AUTH0_CLIENT_ID = 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5';  
const AUTH0_AUDIENCE = 'https://calorie-gpt-api';

const AUTH0_CONFIG = {
    clientId: AUTH0_CLIENT_ID,
    domain: AUTH0_DOMAIN,
    redirectUri: window.location.origin,
    audience: AUTH0_AUDIENCE,
    scope: 'openid profile email offline_access',
    responseType: 'code',
    cacheLocation: 'localstorage'
};

window.AUTH0_CONFIG = AUTH0_CONFIG;

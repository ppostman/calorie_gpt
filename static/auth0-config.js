const AUTH0_DOMAIN = 'dev-lk0vcub54idn0l5c.us.auth0.com';
const AUTH0_CLIENT_ID = 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5';  
const AUTH0_AUDIENCE = 'https://calorie-gpt-api';

const AUTH0_CONFIG = {
    domain: AUTH0_DOMAIN,
    clientId: AUTH0_CLIENT_ID,
    authorizationParams: {
        redirect_uri: window.location.origin,
        audience: AUTH0_AUDIENCE,
        scope: 'openid profile email offline_access'
    },
    cacheLocation: 'localstorage',
    useRefreshTokens: true
};

window.AUTH0_CONFIG = AUTH0_CONFIG;

const auth0Config = {
    domain: 'dev-lk0vcub54idn0l5c.us.auth0.com', // e.g., 'your-tenant.auth0.com'
    clientId: 'xiSSGNYciPG0CAyHQYf4nAbA0D7OS1T5',
    authorizationParams: {
        redirect_uri: window.location.origin,
        audience: 'https://dev-lk0vcub54idn0l5c.us.auth0.com/api/v2/', // This should match your API identifier in Auth0
        scope: 'openid profile email offline_access'
    },
    cacheLocation: 'localstorage',
    useRefreshTokens: true
};

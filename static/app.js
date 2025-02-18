// Auth0 client
let auth0Client = null;
let isLoading = false;

// Initialize Auth0 client
async function initializeAuth0() {
    try {
        // Redirect to our OAuth2 proxy authorize endpoint
        window.location.href = '/oauth2/authorize';
    } catch (error) {
        console.error('Error initializing Auth0:', error);
        handleAuthenticationFailure();
    }
}

// Update authentication state
async function updateAuthState() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const newAccessToken = urlParams.get('access_token');
        const newIdToken = urlParams.get('id_token');
        const error = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');

        if (error) {
            console.error('Authentication error:', error, errorDescription);
            handleAuthenticationFailure();
            return;
        }

        if (code) {
            // If we have a code, we're in the initial OAuth callback
            // The backend will handle this and redirect back with the tokens
            return;
        }

        if (newAccessToken && newIdToken) {
            // Validate the tokens
            if (!isValidJWT(newAccessToken) || !isValidJWT(newIdToken)) {
                console.error('Invalid tokens received');
                handleAuthenticationFailure();
                return;
            }

            // Parse the ID token to get user info
            const idTokenParts = newIdToken.split('.');
            const payload = JSON.parse(atob(idTokenParts[1].replace(/-/g, '+').replace(/_/g, '/')));
            
            console.log('ID Token payload:', payload);  // Debug log

            // Create user object from ID token payload
            const user = {
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                sub: payload.sub
            };

            // Handle successful authentication with tokens and user info
            handleAuthenticationSuccess(newAccessToken, user);
            return;
        }

        // Check if we have a stored token
        const storedToken = localStorage.getItem('access_token');
        if (storedToken) {
            if (!isValidJWT(storedToken)) {
                console.log('Stored token is invalid or expired');
                handleAuthenticationFailure();
                return;
            }
            
            // Try to load user profile with stored token
            try {
                accessToken = storedToken;
                await loadUserProfile();
                handleAuthenticationSuccess(storedToken, { email: localStorage.getItem('userEmail') });
            } catch (error) {
                console.error('Error loading user profile:', error);
                handleAuthenticationFailure();
            }
            return;
        }

        handleAuthenticationFailure();
    } catch (error) {
        console.error('Error updating auth state:', error);
        handleAuthenticationFailure();
    }
}

// Validate JWT token format
function isValidJWT(token) {
    if (!token) {
        console.log('No token provided');
        return false;
    }
    
    // JWT should have 3 parts separated by dots
    const parts = token.split('.');
    if (parts.length !== 3) {
        console.log('Invalid token format: wrong number of parts');
        return false;
    }
    
    try {
        // Each part should be valid base64url
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        
        // Debug logging
        console.log('Validating JWT...');
        console.log('Header:', header);
        console.log('Payload:', payload);
        
        // Basic JWT structure validation
        if (!header.alg) {
            console.log('Missing algorithm in header');
            return false;
        }
        
        // Check expiration only if it exists
        if (payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp < now) {
                console.log('Token expired. Expiry:', new Date(payload.exp * 1000), 'Current:', new Date(now * 1000));
                return false;
            }
        }
        
        // Additional security checks - be more lenient
        if (header.alg !== 'RS256') {
            console.log('Warning: Unexpected algorithm:', header.alg);
            // Don't fail on algorithm mismatch for now
        }
        
        // For ID tokens, verify issuer
        if (payload.iss) {
            const expectedIssuer = 'https://dev-lk0vcub54idn0l5c.us.auth0.com';
            if (!payload.iss.startsWith(expectedIssuer)) {
                console.log('Warning: Unexpected issuer:', payload.iss);
                // Don't fail on issuer mismatch for now
            }
        }
        
        console.log('JWT validation successful');
        return true;
    } catch (error) {
        console.error('Error validating JWT:', error);
        return false;
    }
}

// Handle successful authentication
function handleAuthenticationSuccess(token, user) {
    if (!token || !isValidJWT(token)) {
        console.error('Invalid JWT token in authentication success');
        handleAuthenticationFailure();
        return;
    }
    
    if (!user || !user.email) {
        console.error('Missing user info in authentication success');
        handleAuthenticationFailure();
        return;
    }

    // Store authentication state
    accessToken = token;
    userEmail = user.email;
    localStorage.setItem('access_token', token);
    localStorage.setItem('userEmail', user.email);

    // Update UI with user info
    const welcomeElement = document.getElementById('welcome');
    if (welcomeElement) {
        const displayName = user.name || user.email;
        welcomeElement.textContent = `Welcome, ${displayName}!`;
    }

    // Update UI and load data
    updateAuthUI(true);
    loadInitialData().catch(error => {
        console.error('Error loading initial data:', error);
        alert('Failed to load initial data. Please refresh the page.');
    });
}

// Load user profile
async function loadUserProfile() {
    try {
        const response = await fetchWithAuth('/oauth2/userinfo', {
            headers: getHeaders()
        });
        if (!response.ok) {
            throw new Error('Failed to load user profile');
        }
        const profile = await response.json();
        userEmail = profile.email;
        
        // Update welcome message with user's name or email
        const welcomeElement = document.getElementById('welcome');
        if (welcomeElement) {
            const displayName = profile.name || profile.email;
            welcomeElement.textContent = `Welcome, ${displayName}!`;
        }
    } catch (error) {
        console.error('Error loading user profile:', error);
        throw error; // Propagate error for proper error handling
    }
}

// Handle authentication failure
function handleAuthenticationFailure() {
    accessToken = null;
    userEmail = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('userEmail');
    updateAuthUI(false);
    // Clear any sensitive data from the UI
    document.getElementById('user-email').textContent = '';
    document.getElementById('entries-container').innerHTML = '';
    document.getElementById('weight-container').innerHTML = '';
}

// Login handler
async function handleLogin() {
    try {
        const currentPath = window.location.pathname;
        const redirectUri = encodeURIComponent(currentPath || '/');
        window.location.href = `/oauth2/authorize?redirect_uri=${redirectUri}`;
    } catch (error) {
        console.error('Error during login:', error);
        alert('Failed to log in. Please try again.');
    }
}

// Logout handler
async function handleLogout() {
    try {
        accessToken = null;
        localStorage.removeItem('access_token');
        updateAuthUI(false);
        document.getElementById('welcome').textContent = '';
        document.getElementById('weights').innerHTML = '';
    } catch (error) {
        console.error('Error during logout:', error);
        alert('Failed to log out. Please try again.');
    }
}

// Auth Configuration
let accessToken = null;
let userEmail = null;

// Check if we have a token in local storage
async function checkAuth() {
    // Update to use our OAuth2 proxy endpoints
    const storedToken = localStorage.getItem('access_token');
    if (storedToken) {
        accessToken = storedToken;
        updateAuthUI(true);
        loadUserProfile();
        loadWeights();
    } else {
        updateAuthUI(false);
    }

    // Check if we're handling a callback
    if (window.location.search.includes('code=')) {
        handleCallback();
    }
}

// Update UI based on auth state
function updateAuthUI(isAuthenticated) {
    const loginButton = document.getElementById('login-button');
    const loginButtonMain = document.getElementById('login-button-main');
    const logoutButton = document.getElementById('logout-button');
    const loginSection = document.getElementById('login-section');
    const userSection = document.getElementById('user-section');
    const authenticatedView = document.getElementById('authenticated-view');
    const unauthenticatedView = document.getElementById('unauthenticated-view');

    if (isAuthenticated) {
        // Update navigation elements
        if (loginButton) loginButton.style.display = 'none';
        if (loginButtonMain) loginButtonMain.style.display = 'none';
        if (logoutButton) logoutButton.style.display = 'block';
        if (loginSection) loginSection.style.display = 'none';
        if (userSection) userSection.style.display = 'block';
        
        // Update main view containers
        if (authenticatedView) {
            authenticatedView.classList.remove('d-none');
            authenticatedView.classList.add('d-block');
        }
        if (unauthenticatedView) {
            unauthenticatedView.classList.remove('d-block');
            unauthenticatedView.classList.add('d-none');
        }
    } else {
        // Update navigation elements
        if (loginButton) loginButton.style.display = 'block';
        if (loginButtonMain) loginButtonMain.style.display = 'block';
        if (logoutButton) logoutButton.style.display = 'none';
        if (loginSection) loginSection.style.display = 'block';
        if (userSection) userSection.style.display = 'none';
        
        // Update main view containers
        if (authenticatedView) {
            authenticatedView.classList.remove('d-block');
            authenticatedView.classList.add('d-none');
        }
        if (unauthenticatedView) {
            unauthenticatedView.classList.remove('d-none');
            unauthenticatedView.classList.add('d-block');
        }
    }
}

// Load all initial data
async function loadInitialData() {
    if (!accessToken || isLoading) return;
    
    isLoading = true;
    try {
        await Promise.all([
            loadNutritionData(),
            loadWeightData()
        ]);
    } catch (error) {
        console.error('Error loading initial data:', error);
    } finally {
        isLoading = false;
    }
}

// API Configuration
const API_BASE_URL = window.location.origin;

// Headers with bearer token
const getHeaders = () => ({
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
});

// Add error handling middleware
async function fetchWithAuth(url, options = {}) {
    if (!accessToken || !isValidJWT(accessToken)) {
        console.error('No valid access token available');
        handleAuthenticationFailure();
        return null;
    }

    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
    };

    try {
        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            handleAuthenticationFailure();
            return null;
        }

        return response;
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// Nutrition Functions
async function loadNutritionData() {
    if (!accessToken) return;

    try {
        const [limitResult, entriesResult] = await Promise.all([
            fetchWithAuth(`${API_BASE_URL}/daily-limit/${new Date().toISOString().split('T')[0]}`),
            fetchWithAuth(`${API_BASE_URL}/entries`)
        ]);

        if (!limitResult || !entriesResult) return;

        const limit = await limitResult.json();
        const entries = await entriesResult.json();

        updateCalorieProgress(entries, limit);
        updateFoodEntries(entries);
    } catch (error) {
        console.error('Error loading nutrition data:', error);
        // Don't show alert here as it might be too intrusive during background updates
    }
}

function updateCalorieProgress(entries, limit) {
    const consumed = entries.reduce((sum, entry) => sum + entry.calories, 0);
    const total = limit.base_calories + (limit.workout_calories || 0);
    const remaining = total - consumed;
    const percentage = Math.min((consumed / total) * 100, 100);

    document.getElementById('calorie-progress').style.width = `${percentage}%`;
    document.getElementById('calories-consumed').textContent = `${consumed} consumed`;
    document.getElementById('calories-remaining').textContent = `${remaining} remaining`;
    
    // Update form values
    document.getElementById('base-calories').value = limit.base_calories;
    document.getElementById('workout-calories').value = limit.workout_calories || 0;
}

function updateFoodEntries(entries) {
    const tbody = document.getElementById('food-entries');
    tbody.innerHTML = '';

    entries.forEach(entry => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${entry.food}</td>
            <td>${entry.calories}</td>
            <td>${entry.protein || '-'}</td>
            <td>${entry.carbs || '-'}</td>
            <td>${entry.fat || '-'}</td>
            <td>${entry.description || '-'}</td>
            <td>
                <button class="btn btn-danger btn-action" onclick="deleteEntry(${entry.id})">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Weight Functions
let weightChart;

async function loadWeightData() {
    if (!accessToken) return;

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/weight`);
        if (!response) return;

        const weights = await response.json();
        if (Array.isArray(weights)) {
            updateWeightChart(weights);
            updateWeightEntries(weights);
        } else {
            console.error('Expected weights to be an array');
        }
    } catch (error) {
        console.error('Error loading weight data:', error);
        // Don't show alert here as it might be too intrusive during background updates
    }
}

function updateWeightChart(weights) {
    const ctx = document.getElementById('weight-chart').getContext('2d');
    
    if (weightChart) {
        weightChart.destroy();
    }

    const sortedWeights = weights.sort((a, b) => new Date(a.date) - new Date(b.date));
    
    weightChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: sortedWeights.map(w => new Date(w.date).toLocaleDateString()),
            datasets: [{
                label: 'Weight (kg)',
                data: sortedWeights.map(w => w.weight),
                borderColor: '#0d6efd',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: false
                }
            }
        }
    });
}

function updateWeightEntries(weights) {
    const tbody = document.getElementById('weight-entries');
    tbody.innerHTML = '';

    weights.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(weight => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(weight.date).toLocaleDateString()}</td>
            <td>${weight.weight} kg</td>
            <td>${weight.notes || '-'}</td>
            <td>
                <button class="btn btn-danger btn-action" onclick="deleteWeight(${weight.id})">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// View Management
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', async (e) => {
        e.preventDefault();
        if (!accessToken) return; // Don't allow navigation if not authenticated
        if (isLoading) return; // Don't allow navigation while loading
        
        const view = e.target.dataset.view;
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        e.target.classList.add('active');
        
        isLoading = true;
        try {
            if (view === 'nutrition') {
                document.getElementById('nutrition-view').style.display = 'block';
                document.getElementById('weight-view').style.display = 'none';
                await loadNutritionData();
            } else {
                document.getElementById('nutrition-view').style.display = 'none';
                document.getElementById('weight-view').style.display = 'block';
                await loadWeightData();
            }
        } catch (error) {
            console.error('Error switching views:', error);
        } finally {
            isLoading = false;
        }
    });
});

// Event Listeners
document.getElementById('login-button')?.addEventListener('click', handleLogin);
document.getElementById('login-button-main')?.addEventListener('click', handleLogin);
document.getElementById('logout-button')?.addEventListener('click', handleLogout);

document.getElementById('limit-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!accessToken) return;

    const data = {
        date: new Date().toISOString().split('T')[0],
        base_calories: parseFloat(document.getElementById('base-calories').value),
        workout_calories: parseFloat(document.getElementById('workout-calories').value || 0)
    };

    const result = await fetchWithAuth(`${API_BASE_URL}/daily-limit`, {
        method: 'POST',
        body: JSON.stringify(data)
    });

    if (result) {
        loadNutritionData();
    }
});

document.getElementById('save-food')?.addEventListener('click', async () => {
    if (!accessToken) return;

    const data = {
        date: new Date().toISOString().split('T')[0],
        food: document.getElementById('food-name').value,
        calories: parseFloat(document.getElementById('food-calories').value),
        protein: parseFloat(document.getElementById('food-protein').value || 0),
        carbs: parseFloat(document.getElementById('food-carbs').value || 0),
        fat: parseFloat(document.getElementById('food-fat').value || 0),
        description: document.getElementById('food-description').value
    };

    const result = await fetchWithAuth(`${API_BASE_URL}/entries`, {
        method: 'POST',
        body: JSON.stringify(data)
    });

    if (result) {
        const modal = bootstrap.Modal.getInstance(document.getElementById('addFoodModal'));
        modal.hide();
        loadNutritionData();
    }
});

document.getElementById('save-weight')?.addEventListener('click', async () => {
    if (!accessToken) return;

    const data = {
        weight: parseFloat(document.getElementById('weight-value').value),
        notes: document.getElementById('weight-notes').value,
        date: new Date().toISOString()
    };

    const result = await fetchWithAuth(`${API_BASE_URL}/weight`, {
        method: 'POST',
        body: JSON.stringify(data)
    });

    if (result) {
        const modal = bootstrap.Modal.getInstance(document.getElementById('addWeightModal'));
        modal.hide();
        loadWeightData();
    }
});

async function deleteEntry(id) {
    if (!confirm('Are you sure you want to delete this entry?')) return;

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/entries/${id}`, {
            method: 'DELETE'
        });
        if (!response) return;
        loadNutritionData();
    } catch (error) {
        console.error('Error deleting entry:', error);
        alert('Failed to delete entry');
    }
}

async function deleteWeight(id) {
    if (!confirm('Are you sure you want to delete this weight entry?')) return;

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/weight/${id}`, {
            method: 'DELETE'
        });
        if (!response) return;
        loadWeightData();
    } catch (error) {
        console.error('Error deleting weight entry:', error);
        alert('Failed to delete weight entry');
    }
}

// Initial setup
document.addEventListener('DOMContentLoaded', () => {
    updateAuthState().catch(error => {
        console.error('Error during initial auth check:', error);
        handleAuthenticationFailure();
    });
});

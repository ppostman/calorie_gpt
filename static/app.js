// Auth0 client
let auth0Client = null;
let isLoading = false;

// Initialize Auth0 client
async function initializeAuth0() {
    try {
        // Update to use our OAuth2 proxy endpoints
        const response = await fetch('/oauth2/authorize');
        const data = await response.json();
        window.location.href = data.auth_url;
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
        const state = urlParams.get('state');

        if (code) {
            try {
                const response = await fetch(`/oauth2/callback?code=${code}&state=${state}`);
                const data = await response.json();
                
                if (data.access_token) {
                    accessToken = data.access_token;
                    localStorage.setItem('access_token', accessToken);
                    window.history.replaceState({}, document.title, '/');
                    updateAuthUI(true);
                    loadUserProfile();
                    loadWeights();
                }
            } catch (error) {
                console.error('Token exchange failed:', error);
                handleAuthenticationFailure();
            }
        }
    } catch (error) {
        console.error('Error updating auth state:', error);
        handleAuthenticationFailure();
    }
}

// Handle successful authentication
function handleAuthenticationSuccess(token, user) {
    accessToken = token;
    userEmail = user.email;
    localStorage.setItem('accessToken', token);
    localStorage.setItem('userEmail', user.email);
    updateAuthUI();
    loadInitialData();
}

// Handle authentication failure
function handleAuthenticationFailure() {
    accessToken = null;
    userEmail = null;
    localStorage.removeItem('accessToken');
    localStorage.removeItem('userEmail');
    updateAuthUI();
}

// Login handler
async function handleLogin() {
    try {
        const response = await fetch('/oauth2/authorize');
        const data = await response.json();
        window.location.href = data.auth_url;
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
    const authButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');
    const authSection = document.getElementById('auth-section');
    const unauthSection = document.getElementById('unauth-section');

    if (isAuthenticated) {
        authButton.style.display = 'none';
        logoutButton.style.display = 'block';
        authSection.style.display = 'block';
        unauthSection.style.display = 'none';
    } else {
        authButton.style.display = 'block';
        logoutButton.style.display = 'none';
        authSection.style.display = 'none';
        unauthSection.style.display = 'block';
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
    if (!accessToken) {
        updateAuthUI();
        return null;
    }

    try {
        // Try to refresh the token before making the request
        await updateAuthState();

        const response = await fetch(url, {
            ...options,
            headers: getHeaders(),
        });
        
        if (response.status === 401) {
            // Token might be expired, try to refresh
            try {
                await updateAuthState();
                // Retry the request with the new token
                const retryResponse = await fetch(url, {
                    ...options,
                    headers: getHeaders(),
                });
                if (retryResponse.status === 401) {
                    // If still unauthorized after refresh, logout
                    handleLogout();
                    return null;
                }
                const text = await retryResponse.text();
                return { json: JSON.parse(text), response: retryResponse };
            } catch (error) {
                console.error('Token refresh failed:', error);
                handleLogout();
                return null;
            }
        }

        const text = await response.text();
        try {
            return { json: JSON.parse(text), response };
        } catch (e) {
            console.error('JSON parse error:', e);
            console.error('Response text:', text);
            return null;
        }
    } catch (error) {
        console.error('API request failed:', error);
        alert('Failed to connect to the server. Please try again.');
        return null;
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

        const limit = limitResult.json;
        const entries = entriesResult.json;

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

        const weights = response.json;
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

// Initial auth check and data load
checkAuth();

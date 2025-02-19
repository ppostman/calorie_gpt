// Auth0 configuration
let auth0 = null;
let isAuthenticated = false;
let accessToken = null;
let userProfile = null;

// Initialize Auth0 client
async function initializeAuth0() {
    auth0 = await createAuth0Client({
        domain: AUTH0_DOMAIN,
        client_id: AUTH0_CLIENT_ID,
        audience: AUTH0_AUDIENCE,
        redirect_uri: window.location.origin
    });

    try {
        // Check for authentication callback
        if (window.location.search.includes("code=")) {
            await auth0.handleRedirectCallback();
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (err) {
        console.error("Error handling redirect:", err);
    }

    isAuthenticated = await auth0.isAuthenticated();
    updateUI();

    if (isAuthenticated) {
        accessToken = await auth0.getTokenSilently();
        userProfile = await auth0.getUser();
        await loadInitialData();
    }
}

// Update UI based on authentication state
async function updateUI() {
    const isAuthenticated = await auth0.isAuthenticated();
    
    document.getElementById("authenticated-view").classList.toggle("d-none", !isAuthenticated);
    document.getElementById("unauthenticated-view").classList.toggle("d-none", isAuthenticated);
    document.getElementById("login-section").classList.toggle("d-none", isAuthenticated);
    document.getElementById("user-section").classList.toggle("d-none", !isAuthenticated);

    if (isAuthenticated && userProfile) {
        document.getElementById("welcome").textContent = `Welcome, ${userProfile.name}!`;
    }
}

// Login
async function login() {
    try {
        await auth0.loginWithRedirect({
            redirect_uri: window.location.origin,
            scope: 'openid profile email offline_access'
        });
    } catch (err) {
        console.error("Error during login:", err);
    }
}

// Logout
async function logout() {
    try {
        await auth0.logout({
            returnTo: window.location.origin
        });
    } catch (err) {
        console.error("Error during logout:", err);
    }
}

// API calls helper with authentication
async function fetchWithAuth(url, options = {}) {
    try {
        if (!accessToken) {
            throw new Error('No access token available');
        }

        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            // Token might be expired, try to refresh
            accessToken = await auth0.getTokenSilently();
            headers.Authorization = `Bearer ${accessToken}`;
            return await fetch(url, { ...options, headers });
        }

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

// Load initial data
async function loadInitialData() {
    if (!isAuthenticated) return;
    
    try {
        await Promise.all([
            loadNutritionData(),
            loadWeightData()
        ]);
    } catch (error) {
        console.error('Error loading initial data:', error);
    }
}

// Nutrition data functions
async function loadNutritionData() {
    try {
        const today = new Date().toISOString().split('T')[0];
        const [entries, limit] = await Promise.all([
            fetchWithAuth(`${window.location.origin}/entries/${today}`),
            fetchWithAuth(`${window.location.origin}/daily-limit/${today}`)
        ]);

        updateCalorieProgress(entries, limit);
        updateFoodEntries(entries);
    } catch (error) {
        console.error('Error loading nutrition data:', error);
    }
}

// Update calorie progress display
function updateCalorieProgress(entries, limitResponse) {
    const totalCalories = entries.reduce((sum, entry) => sum + entry.calories, 0);
    const limit = limitResponse.limit?.limit || 0;
    const percentage = limit ? (totalCalories / limit) * 100 : 0;

    const progressBar = document.getElementById('calorie-progress');
    progressBar.style.width = `${Math.min(percentage, 100)}%`;
    progressBar.classList.toggle('bg-danger', percentage > 100);
    
    document.getElementById('calories-consumed').textContent = `${Math.round(totalCalories)} consumed`;
    document.getElementById('calories-remaining').textContent = limit ? 
        `${Math.round(limit - totalCalories)} remaining` :
        'No limit set';
}

// Update food entries table
function updateFoodEntries(entries) {
    const tbody = document.querySelector('#food-entries tbody');
    tbody.innerHTML = entries.map(entry => `
        <tr>
            <td>${entry.name}</td>
            <td>${entry.calories}</td>
            <td>${entry.protein || '-'}</td>
            <td>${entry.carbs || '-'}</td>
            <td>${entry.fat || '-'}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="deleteEntry('${entry.id}')">Delete</button>
            </td>
        </tr>
    `).join('');
}

// Weight data functions
async function loadWeightData() {
    try {
        const weights = await fetchWithAuth(`${window.location.origin}/weights`);
        updateWeightChart(weights);
        updateWeightEntries(weights);
    } catch (error) {
        console.error('Error loading weight data:', error);
    }
}

// Event Listeners
document.getElementById('login-button').addEventListener('click', login);
document.getElementById('login-button-main').addEventListener('click', login);
document.getElementById('logout-button').addEventListener('click', logout);

// Form submissions
document.getElementById('limit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const limit = {
        limit: parseFloat(document.getElementById('base-calories').value)
    };

    try {
        const today = new Date().toISOString().split('T')[0];
        await fetchWithAuth(`${window.location.origin}/daily-limit/${today}`, {
            method: 'POST',
            body: JSON.stringify(limit)
        });
        await loadNutritionData();
    } catch (error) {
        console.error('Error setting daily limit:', error);
    }
});

document.getElementById('food-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const entry = {
        name: document.getElementById('food-name').value,
        calories: parseFloat(document.getElementById('food-calories').value),
        protein: parseFloat(document.getElementById('food-protein').value) || null,
        carbs: parseFloat(document.getElementById('food-carbs').value) || null,
        fat: parseFloat(document.getElementById('food-fat').value) || null
    };

    try {
        await fetchWithAuth(`${window.location.origin}/entries`, {
            method: 'POST',
            body: JSON.stringify(entry)
        });
        await loadNutritionData();
        bootstrap.Modal.getInstance(document.getElementById('addFoodModal')).hide();
        e.target.reset();
    } catch (error) {
        console.error('Error adding food entry:', error);
    }
});

document.getElementById('weight-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const weight = {
        weight: parseFloat(document.getElementById('weight-value').value)
    };

    try {
        await fetchWithAuth(`${window.location.origin}/weights`, {
            method: 'POST',
            body: JSON.stringify(weight)
        });
        await loadWeightData();
        e.target.reset();
    } catch (error) {
        console.error('Error adding weight entry:', error);
    }
});

// Delete functions
async function deleteEntry(id) {
    try {
        await fetchWithAuth(`${window.location.origin}/entries/${id}`, {
            method: 'DELETE'
        });
        await loadNutritionData();
    } catch (error) {
        console.error('Error deleting entry:', error);
    }
}

async function deleteWeight(id) {
    try {
        await fetchWithAuth(`${window.location.origin}/weights/${id}`, {
            method: 'DELETE'
        });
        await loadWeightData();
    } catch (error) {
        console.error('Error deleting weight:', error);
    }
}

// Initialize the application
window.addEventListener('load', initializeAuth0);

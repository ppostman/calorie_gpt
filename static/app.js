// Authentication state
let isAuthenticated = false;
let accessToken = null;
let userProfile = null;

// Initialize authentication state
async function initializeAuth() {
    try {
        // Check if we have a valid token in localStorage
        accessToken = localStorage.getItem('access_token');
        if (accessToken) {
            // Validate token and get user info
            const user = await fetchUserInfo();
            if (user) {
                isAuthenticated = true;
                userProfile = user;
                await loadInitialData();
            } else {
                // Token is invalid, clear it
                logout();
            }
        }
        
        // Check for authentication callback
        if (window.location.search.includes("code=")) {
            await handleAuthCallback();
        }

        await updateUI();
    } catch (err) {
        console.error("Error initializing auth:", err);
        showError("Failed to initialize authentication. Please try again later.");
    }
}

// Handle authentication callback
async function handleAuthCallback() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        
        // Exchange code for tokens
        const response = await fetch('/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ code, state })
        });

        if (!response.ok) {
            throw new Error('Failed to exchange code for token');
        }

        const data = await response.json();
        
        // Store tokens
        localStorage.setItem('access_token', data.access_token);
        accessToken = data.access_token;
        
        // Get user info
        userProfile = await fetchUserInfo();
        isAuthenticated = true;

        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
        
        await loadInitialData();
    } catch (err) {
        console.error('Auth callback error:', err);
        showError('Authentication failed. Please try again.');
    }
}

// Fetch user info
async function fetchUserInfo() {
    try {
        const response = await fetch('/oauth2/userinfo', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch user info');
        }

        return await response.json();
    } catch (err) {
        console.error('Error fetching user info:', err);
        return null;
    }
}

// Login
async function login() {
    try {
        console.log('Starting login process...');
        const state = generateState();
        localStorage.setItem('oauth_state', state);
        
        const params = new URLSearchParams({
            client_id: window.AUTH0_CONFIG.clientId,
            redirect_uri: `${window.location.origin}/oauth2/callback`,
            response_type: 'code',
            scope: 'openid profile email',
            audience: window.AUTH0_CONFIG.audience,
            state: state
        });

        window.location.href = `/oauth2/authorize?${params.toString()}`;
    } catch (err) {
        console.error('Login error:', err);
        showError('Failed to start login process. Please try again.');
    }
}

// Logout
async function logout() {
    try {
        console.log('Starting logout process...');
        localStorage.removeItem('access_token');
        localStorage.removeItem('oauth_state');
        accessToken = null;
        userProfile = null;
        isAuthenticated = false;
        
        await updateUI();
        
        // Redirect to home
        window.location.href = '/';
    } catch (err) {
        console.error('Logout error:', err);
        showError('Failed to logout. Please try again.');
    }
}

// Generate random state
function generateState() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Update UI based on authentication state
async function updateUI() {
    try {
        document.getElementById("authenticated-view").classList.toggle("d-none", !isAuthenticated);
        document.getElementById("unauthenticated-view").classList.toggle("d-none", isAuthenticated);
        document.getElementById("login-section").classList.toggle("d-none", isAuthenticated);
        document.getElementById("user-section").classList.toggle("d-none", !isAuthenticated);

        if (isAuthenticated && userProfile) {
            document.getElementById("welcome").textContent = `Welcome, ${userProfile.name || userProfile.email}!`;
        }
    } catch (err) {
        console.error("Error updating UI:", err);
    }
}

// API calls helper with authentication
async function fetchWithAuth(url, options = {}) {
    try {
        if (!accessToken) {
            throw new Error('No access token available');
        }

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            // Token expired or invalid
            logout();
            throw new Error('Session expired. Please login again.');
        }

        return await response.json();
    } catch (err) {
        console.error('API call error:', err);
        throw err;
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
    const weightValue = parseFloat(document.getElementById('weight-value').value);
    
    if (!weightValue || weightValue <= 0) {
        showError("Please enter a valid weight value greater than 0");
        return;
    }

    const weight = {
        value: weightValue,
        date: new Date().toISOString()
    };

    try {
        const response = await fetchWithAuth(`${window.location.origin}/weights`, {
            method: 'POST',
            body: JSON.stringify(weight)
        });

        if (response.error) {
            throw new Error(response.error);
        }

        await loadWeightData();
        e.target.reset();

        // Show success message
        const successDiv = document.createElement('div');
        successDiv.className = 'alert alert-success alert-dismissible fade show';
        successDiv.innerHTML = `
            Weight entry added successfully!
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        document.body.insertBefore(successDiv, document.body.firstChild);
    } catch (error) {
        console.error('Error adding weight entry:', error);
        showError(error.message || "Failed to add weight entry. Please try again.");
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

// Handle AI response and execute API call
async function handleAIResponse(response) {
    try {
        const aiResponse = JSON.parse(response);
        
        // Display AI message to user
        addMessage('assistant', aiResponse.Message);
        
        // Make the API call using the provided URL, method, and payload
        const apiResponse = await fetchWithAuth(aiResponse.URL, {
            method: aiResponse.Method,
            body: JSON.stringify(aiResponse.Payload)
        });
        
        // Reload nutrition data after successful API call
        if (apiResponse) {
            await Promise.all([loadDailyCalories(), loadEntries()]);
        }
        
        return true;
    } catch (err) {
        console.error('Error handling AI response:', err);
        addMessage('assistant', 'Sorry, I encountered an error processing your request.');
        return false;
    }
}

// Initialize the application
window.addEventListener('load', () => {
    if (!window.AUTH0_CONFIG) {
        showError('Failed to load authentication configuration. Please refresh the page.');
        return;
    }
    initializeAuth();
});

// Show error message to user
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger alert-dismissible fade show';
    errorDiv.role = 'alert';
    errorDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    document.body.insertBefore(errorDiv, document.body.firstChild);
}

// Handle chat form submission
document.getElementById('chat-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message) return;

    // Clear input
    input.value = '';

    // Add user message to chat
    addMessage('user', message);

    try {
        // Show typing indicator
        const typingIndicator = document.createElement('div');
        typingIndicator.className = 'typing-indicator';
        typingIndicator.textContent = 'AI is typing...';
        document.getElementById('chat-messages').appendChild(typingIndicator);

        // Make API call
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                messages: [{
                    role: 'user',
                    content: message
                }]
            })
        });

        // Remove typing indicator
        typingIndicator.remove();

        if (!response.ok) {
            throw new Error('Failed to get AI response');
        }

        const data = await response.json();
        if (data.content) {
            // Try to handle as JSON response first
            const success = await handleAIResponse(data.content);
            if (!success) {
                // If not a valid JSON response, display as regular message
                addMessage('assistant', data.content);
            }
        }
    } catch (err) {
        console.error('Chat error:', err);
        addMessage('assistant', 'Sorry, I encountered an error. Please try again.');
    }
});

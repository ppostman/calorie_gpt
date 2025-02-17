// API Configuration
let API_KEY = localStorage.getItem('apiKey');

function promptForApiKey() {
    const key = prompt('Please enter your API key. If you need one, please check the documentation:');
    if (!key) {
        alert('API key is required to use this application.');
        return promptForApiKey();
    }
    localStorage.setItem('apiKey', key);
    API_KEY = key;
    return key;
}

if (!API_KEY) {
    API_KEY = promptForApiKey();
}

const API_BASE_URL = window.location.origin + '/api';
const getHeaders = () => ({
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
});

// Add function to update API key
function updateApiKey() {
    const newKey = promptForApiKey();
    if (newKey) {
        location.reload();
    }
}

// Add error handling middleware
async function fetchWithAuth(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: getHeaders(),
        });
        
        if (response.status === 401) {
            alert('Invalid API key. Please enter a valid key.');
            updateApiKey();
            return null;
        }

        // Log raw response for debugging
        const text = await response.text();
        console.log('Raw response:', text);
        
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

// View Management
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const view = e.target.dataset.view;
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        e.target.classList.add('active');
        
        if (view === 'nutrition') {
            document.getElementById('nutrition-view').style.display = 'block';
            document.getElementById('weight-view').style.display = 'none';
            loadNutritionData();
        } else {
            document.getElementById('nutrition-view').style.display = 'none';
            document.getElementById('weight-view').style.display = 'block';
            loadWeightData();
        }
    });
});

// Nutrition Functions
async function loadNutritionData() {
    try {
        const [limitResult, entriesResult] = await Promise.all([
            fetchWithAuth(`${API_BASE_URL}/daily-limits/${new Date().toISOString().split('T')[0]}`),
            fetchWithAuth(`${API_BASE_URL}/entries`)
        ]);

        if (!limitResult || !entriesResult) return;

        const limit = limitResult.json;
        const entries = entriesResult.json;

        updateCalorieProgress(entries, limit);
        updateFoodEntries(entries);
    } catch (error) {
        console.error('Error loading nutrition data:', error);
        alert('Failed to load nutrition data. Please try again.');
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
    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/weights`);
        if (!response) return;

        const weights = response.json;
        updateWeightChart(weights);
        updateWeightEntries(weights);
    } catch (error) {
        console.error('Error loading weight data:', error);
        alert('Failed to load weight data. Please try again.');
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

// Event Listeners
document.getElementById('limit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {
        base_calories: parseInt(document.getElementById('base-calories').value),
        workout_calories: parseInt(document.getElementById('workout-calories').value) || 0
    };

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/daily-limits`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (!response) return;
        loadNutritionData();
    } catch (error) {
        console.error('Error setting daily limit:', error);
        alert('Failed to set daily limit');
    }
});

document.getElementById('save-food').addEventListener('click', async () => {
    const data = {
        name: document.getElementById('food-name').value,
        calories: parseInt(document.getElementById('food-calories').value),
        protein: parseInt(document.getElementById('food-protein').value) || null,
        carbs: parseInt(document.getElementById('food-carbs').value) || null,
        fat: parseInt(document.getElementById('food-fat').value) || null,
        description: document.getElementById('food-description').value
    };

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/entries`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (!response) return;
        bootstrap.Modal.getInstance(document.getElementById('addFoodModal')).hide();
        document.getElementById('food-form').reset();
        loadNutritionData();
    } catch (error) {
        console.error('Error adding food entry:', error);
        alert('Failed to add food entry');
    }
});

document.getElementById('save-weight').addEventListener('click', async () => {
    const data = {
        weight: parseFloat(document.getElementById('weight-value').value),
        notes: document.getElementById('weight-notes').value,
        date: new Date().toISOString()
    };

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/weights`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
        if (!response) return;
        bootstrap.Modal.getInstance(document.getElementById('addWeightModal')).hide();
        document.getElementById('weight-form').reset();
        loadWeightData();
    } catch (error) {
        console.error('Error adding weight entry:', error);
        alert('Failed to add weight entry');
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
        const response = await fetchWithAuth(`${API_BASE_URL}/weights/${id}`, {
            method: 'DELETE'
        });
        if (!response) return;
        loadWeightData();
    } catch (error) {
        console.error('Error deleting weight entry:', error);
        alert('Failed to delete weight entry');
    }
}

// Initial load
loadNutritionData();

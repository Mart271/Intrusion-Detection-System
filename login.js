// ==================== CONFIGURATION ====================

const API_BASE = 'http://localhost:5000/api';
const MAX_ATTEMPTS = 3;

// ==================== STATE ====================

let failedAttempts = 0;

// ==================== LOGIN HANDLER ====================

async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('loginBtn');
    const btnText = document.getElementById('btnText');
    const btnLoading = document.getElementById('btnLoading');
    const errorMsg = document.getElementById('errorMessage');
    const successMsg = document.getElementById('successMessage');

    // Hide messages
    errorMsg.classList.remove('show');
    successMsg.classList.remove('show');

    // Disable button and show loading
    loginBtn.disabled = true;
    btnText.style.display = 'none';
    btnLoading.style.display = 'inline-block';

    try {
        // Call IDS backend API
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // ==================== SUCCESS ====================
            failedAttempts = 0;
            updateAttemptBadge();
            
            successMsg.textContent = '✅ Login successful! Redirecting to dashboard...';
            successMsg.classList.add('show');

            console.log(`✅ LOGIN SUCCESSFUL - User: ${username} - Time: ${new Date().toLocaleString()}`);

            setTimeout(() => {
                showDashboard(username);
            }, 1500);

        } else {
            // ==================== FAILURE ====================
            failedAttempts++;
            updateAttemptBadge();

            let errorText = data.message;

            // Format error message with emoji based on reason
            if (data.message.includes('locked')) {
                errorText = '🔒 ' + data.message;
            } else if (data.message.includes('blocked')) {
                errorText = '🚫 ' + data.message;
            } else if (data.message.includes('Invalid')) {
                errorText = '❌ ' + data.message;
            } else {
                errorText = '⚠️ ' + data.message;
            }

            errorMsg.textContent = errorText;
            errorMsg.classList.add('show');

            // Clear password field for security
            document.getElementById('password').value = '';

            console.log(`❌ LOGIN FAILED - User: ${username} - Reason: ${data.message} - Failed Attempts: ${failedAttempts}`);
        }

    } catch (error) {
        // ==================== CONNECTION ERROR ====================
        errorMsg.textContent = '❌ Connection error: ' + error.message;
        errorMsg.classList.add('show');
        failedAttempts++;
        updateAttemptBadge();

        console.error('Connection Error:', error);
    } finally {
        // Re-enable button
        loginBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
    }
}

// ==================== ATTEMPT BADGE UPDATER ====================

function updateAttemptBadge() {
    const badge = document.getElementById('attemptBadge');
    badge.textContent = `${failedAttempts}/${MAX_ATTEMPTS}`;
    
    // Remove all classes
    badge.classList.remove('warning', 'danger');
    
    // Add appropriate class
    if (failedAttempts >= 2) {
        badge.classList.add('warning');
    }
    if (failedAttempts >= MAX_ATTEMPTS) {
        badge.classList.add('danger');
    }
}

// ==================== DASHBOARD DISPLAY ====================

function showDashboard(username) {
    document.getElementById('loginContainer').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('loggedUser').textContent = username;

    console.log(`📊 Dashboard loaded for user: ${username}`);
}

// ==================== LOGOUT ====================

function logout() {
    console.log('👋 User logged out');
    
    // Hide dashboard and show login
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('loginContainer').style.display = 'flex';
    
    // Reset form
    document.getElementById('loginForm').reset();
    document.getElementById('errorMessage').classList.remove('show');
    document.getElementById('successMessage').classList.remove('show');
    
    // Reset counters
    failedAttempts = 0;
    updateAttemptBadge();

    // Focus on username field
    document.getElementById('username').focus();
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🔐 SecureBank Login System Initialized');
    console.log('📡 Backend API: ' + API_BASE);
    
    // Set initial attempt badge
    updateAttemptBadge();
    
    // Focus on username field
    document.getElementById('username').focus();
});
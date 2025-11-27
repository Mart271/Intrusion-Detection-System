// Auto-detect API base URL
const API_BASE = (() => {
    if (window.location.protocol === 'https:' || window.location.hostname !== 'localhost') {
        return '/api';
    }
    return 'http://127.0.0.1:5000/api';
})();

let loginAttempts = 0;

// Session Manager
class SessionManager {
    static setSession(token, role, username) {
        sessionStorage.setItem('sessionToken', token);
        sessionStorage.setItem('userRole', role);
        sessionStorage.setItem('username', username);
    }
    
    static getToken() {
        return sessionStorage.getItem('sessionToken');
    }
    
    static getRole() {
        return sessionStorage.getItem('userRole');
    }
    
    static getUsername() {
        return sessionStorage.getItem('username');
    }
    
    static clearSession() {
        sessionStorage.removeItem('sessionToken');
        sessionStorage.removeItem('userRole');
        sessionStorage.removeItem('username');
    }
    
    static isLoggedIn() {
        return !!this.getToken();
    }
}

// API Client
class APIClient {
    static getHeaders() {
        const headers = { 'Content-Type': 'application/json' };
        const token = SessionManager.getToken();
        if (token) {
            headers['X-Session-Token'] = token;
        }
        return headers;
    }
    
    static async post(endpoint, data) {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify(data)
        });
        return { response: res, data: await res.json() };
    }
}

async function handleLogin(e) {
    // CRITICAL: Prevent form submission
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');
    const loginButton = document.getElementById('loginButton');
    
    if (loginButton.disabled) return;
    
    loginAttempts++;
    document.getElementById('attemptCount').textContent = loginAttempts;
    
    loginButton.disabled = true;
    loginButton.textContent = 'Signing In...';
    
    try {
        const { response, data } = await APIClient.post('/login', { username, password });
        
        if (response.status === 429) {
            errorMessage.style.display = 'block';
            successMessage.style.display = 'none';
            errorMessage.innerHTML = `<strong>Too Many Attempts!</strong><br>${data.message || 'Please wait before trying again.'}`;
            shakeForm();
            showRateLimitCountdown(loginButton, 60);
            // Clear password only
            console.log('Rate limited, clearing password...');
            console.log('Password value BEFORE clear:', passwordInput.value);
            setTimeout(() => {
                passwordInput.value = '';
                console.log('Password value AFTER clear:', passwordInput.value);
            }, 100);
            return;
        }
        
        if (response.ok && data.success) {
            SessionManager.setSession(data.session_token, data.role, data.username);
            
            errorMessage.style.display = 'none';
            successMessage.style.display = 'block';
            successMessage.textContent = data.message || 'Login successful! Redirecting...';
            
            if (data.must_change_password) {
                successMessage.textContent = 'Password change required. Redirecting...';
                setTimeout(() => {
                    window.location.href = 'change-password.html';
                }, 1500);
                return;
            }
            
            setTimeout(() => {
                redirectBasedOnRole(data.role);
            }, 1500);
            
        } else {
            // Failed login - show error
            successMessage.style.display = 'none';
            errorMessage.style.display = 'block';
            
            if (response.status === 403) {
                errorMessage.innerHTML = `<strong>Access Denied!</strong><br>${data.message}`;
            } else {
                errorMessage.textContent = data.message || 'Invalid username or password';
            }
            
            shakeForm();
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
            
            // CLEAR PASSWORD ONLY - KEEP USERNAME
            console.log('About to clear password...');
            console.log('Password value BEFORE clear:', passwordInput.value);
            setTimeout(() => {
                passwordInput.value = '';
                console.log('Password value AFTER clear:', passwordInput.value);
                passwordInput.focus();
            }, 100);
        }
        
    } catch (error) {
        console.error('Login error:', error);
        errorMessage.style.display = 'block';
        successMessage.style.display = 'none';
        errorMessage.textContent = 'Connection error. Please check if server is running.';
        shakeForm();
        loginButton.disabled = false;
        loginButton.textContent = 'Sign In';
        
        // CLEAR PASSWORD ONLY - KEEP USERNAME
        console.log('Error occurred, clearing password...');
        console.log('Password value BEFORE clear:', passwordInput.value);
        setTimeout(() => {
            passwordInput.value = '';
            console.log('Password value AFTER clear:', passwordInput.value);
            passwordInput.focus();
        }, 100);
    }
}

function redirectBasedOnRole(role) {
    switch (role) {
        case 'admin':
            window.location.href = 'admin.html';
            break;
        case 'analyst':
            window.location.href = 'analyst.html';
            break;
        default:
            document.getElementById('loginContainer').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            document.getElementById('loggedUser').textContent = SessionManager.getUsername();
    }
}

function shakeForm() {
    const loginForm = document.querySelector('.login-form');
    if (loginForm) {
        loginForm.style.animation = 'shake 0.5s';
        setTimeout(() => loginForm.style.animation = '', 500);
    }
}

function showRateLimitCountdown(btn, seconds) {
    btn.disabled = true;
    btn.style.opacity = '0.5';
    const errorMessage = document.getElementById('errorMessage');
    
    const countdown = setInterval(() => {
        btn.textContent = `Wait ${seconds}s`;
        errorMessage.innerHTML = `<strong>Too Many Attempts!</strong><br>Please wait ${seconds} seconds before trying again.`;
        seconds--;
        
        if (seconds < 0) {
            clearInterval(countdown);
            btn.disabled = false;
            btn.textContent = 'Sign In';
            btn.style.opacity = '1';
            errorMessage.style.display = 'none';
        }
    }, 1000);
}

async function logout() {
    try {
        await APIClient.post('/logout', {});
    } catch (e) {
        console.error('Logout error:', e);
    }
    
    SessionManager.clearSession();
    loginAttempts = 0;
    
    document.getElementById('loginContainer').style.display = 'flex';
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('attemptCount').textContent = '0';
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Page loaded, initializing...');
    
    if (SessionManager.isLoggedIn()) {
        const role = SessionManager.getRole();
        if (role === 'admin' || role === 'analyst') {
            redirectBasedOnRole(role);
            return;
        }
    }
    
    // Attach form submit handler
    const loginForm = document.getElementById('loginForm');
    console.log('Login form found:', loginForm);
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            console.log('Form submitted!');
            e.preventDefault();
            e.stopPropagation();
            handleLogin(e);
            return false;
        });
    } else {
        console.error('Login form not found!');
    }
});
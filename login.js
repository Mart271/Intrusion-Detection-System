const API_BASE = 'http://127.0.0.1:5000/api';
let loginAttempts = 0;

// Session Manager Class
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

// API Client Class
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
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');
    const loginButton = document.querySelector('.login-btn');
    
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
            return;
        }
        
        if (response.ok && data.success) {
            // Store session
            SessionManager.setSession(data.session_token, data.role, data.username);
            
            errorMessage.style.display = 'none';
            successMessage.style.display = 'block';
            successMessage.textContent = data.message || 'Login successful! Redirecting...';
            
            // Check password change requirement
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
            
        } else if (response.status === 403) {
            successMessage.style.display = 'none';
            errorMessage.style.display = 'block';
            errorMessage.innerHTML = `<strong>Access Denied!</strong><br>${data.message}`;
            shakeForm();
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
            
        } else {
            successMessage.style.display = 'none';
            errorMessage.style.display = 'block';
            errorMessage.textContent = data.message || 'Invalid username or password';
            shakeForm();
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
        }
        
    } catch (error) {
        console.error('Login error:', error);
        errorMessage.style.display = 'block';
        successMessage.style.display = 'none';
        errorMessage.textContent = 'Connection error. Please check if server is running.';
        shakeForm();
        loginButton.disabled = false;
        loginButton.textContent = 'Sign In';
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
    
    const countdown = setInterval(() => {
        btn.textContent = `Wait ${seconds}s`;
        seconds--;
        
        if (seconds < 0) {
            clearInterval(countdown);
            btn.disabled = false;
            btn.textContent = 'Sign In';
            btn.style.opacity = '1';
            document.getElementById('errorMessage').style.display = 'none';
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

// Check if already logged in on page load
document.addEventListener('DOMContentLoaded', function() {
    if (SessionManager.isLoggedIn()) {
        const role = SessionManager.getRole();
        if (role === 'admin' || role === 'analyst') {
            redirectBasedOnRole(role);
            return;
        }
    }
    
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleLogin(e);
            return false;
        });
    }
});
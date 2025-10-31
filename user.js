const API_BASE = 'http://localhost:5000/api';
const CURRENT_USER = 'testuser';

function logout() {
    alert('Logged out successfully');
    window.location.href = 'index.html';
}

async function loadUserData() {
    try {
        // Fetch login history
        const historyRes = await fetch(`${API_BASE}/dashboard/login-history?limit=10`);
        const historyData = await historyRes.json();
        
        // Fetch alerts
        const alertsRes = await fetch(`${API_BASE}/dashboard/alerts?limit=20`);
        const alertsData = await alertsRes.json();

        // Update account status
        document.getElementById('accountStatus').textContent = '✓';
        
        // Update last login info
        if (historyData.history && historyData.history.length > 0) {
            const lastLogin = historyData.history[0];
            document.getElementById('lastLogin').textContent = new Date(lastLogin.timestamp).toLocaleTimeString();
            document.getElementById('userIP').textContent = lastLogin.ip_address;
        }

        // Count user alerts
        const userAlerts = (alertsData.alerts || []).filter(a => a.username === CURRENT_USER).length;
        document.getElementById('userAlerts').textContent = userAlerts;

        // Load login history table
        loadHistory(historyData.history || []);
    } catch (error) {
        console.error('Error loading user data:', error);
    }
}

function loadHistory(history) {
    const tbody = document.getElementById('userHistory');
    
    if (history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No login history</td></tr>';
        return;
    }

    tbody.innerHTML = history.map(h => `
        <tr>
            <td>${new Date(h.timestamp).toLocaleString()}</td>
            <td>${h.ip_address}</td>
            <td>${h.location}</td>
            <td><span class="status-${h.status}">${h.status.toUpperCase()}</span></td>
        </tr>
    `).join('');
}

// Initial load
window.addEventListener('load', loadUserData);

// Auto-refresh every 5 seconds
setInterval(loadUserData, 5000);
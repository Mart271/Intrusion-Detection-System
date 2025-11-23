const API_BASE = 'http://127.0.0.1:5000/api';

let allIncidents = [];
let selectedIncidents = [];
let filterText = '';
let severityFilter = 'all';
let statusFilter = 'all';

// Session Manager
class SessionManager {
    static getToken() { return sessionStorage.getItem('sessionToken'); }
    static getRole() { return sessionStorage.getItem('userRole'); }
    static getUsername() { return sessionStorage.getItem('username'); }
    static clearSession() {
        sessionStorage.removeItem('sessionToken');
        sessionStorage.removeItem('userRole');
        sessionStorage.removeItem('username');
    }
    static isLoggedIn() { return !!this.getToken(); }
    static isAnalyst() { return ['analyst', 'admin'].includes(this.getRole()); }
}

// Notification Service
class NotificationService {
    static show(msg, type = 'info') {
        const colors = { info: '#3b82f6', success: '#10b981', error: '#ef4444', warning: '#f59e0b' };
        const notif = document.createElement('div');
        notif.style.cssText = `position:fixed;top:80px;right:20px;background:${colors[type]};color:white;padding:1rem 1.5rem;border-radius:0.5rem;box-shadow:0 4px 6px rgba(0,0,0,0.2);z-index:9999;max-width:400px;`;
        notif.textContent = msg;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 4000);
    }
}

// Input Validator
class InputValidator {
    static sanitize(str) {
        return String(str).replace(/[<>'"&]/g, c => ({'<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;','&':'&amp;'}[c]));
    }
}

// API Client with Auth
class APIClient {
    static getHeaders() {
        const headers = { 'Content-Type': 'application/json' };
        const token = SessionManager.getToken();
        if (token) headers['X-Session-Token'] = token;
        return headers;
    }
    
    static async handleResponse(res) {
        if (res.status === 401) {
            NotificationService.show('Session expired. Please login again.', 'error');
            setTimeout(() => { SessionManager.clearSession(); window.location.href = 'login.html'; }, 2000);
            throw new Error('Unauthorized');
        }
        if (res.status === 403) {
            NotificationService.show('Access denied. Insufficient privileges.', 'error');
            throw new Error('Forbidden');
        }
        return res.json();
    }
    
    static async get(endpoint) {
        const res = await fetch(`${API_BASE}${endpoint}`, { headers: this.getHeaders() });
        return this.handleResponse(res);
    }
    
    static async post(endpoint, data) {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST', headers: this.getHeaders(), body: JSON.stringify(data)
        });
        return this.handleResponse(res);
    }
}

// Auth Check
function checkAuth() {
    if (!SessionManager.isLoggedIn()) {
        window.location.href = 'login.html';
        return false;
    }
    if (!SessionManager.isAnalyst()) {
        NotificationService.show('Analyst access required', 'error');
        setTimeout(() => window.location.href = 'login.html', 2000);
        return false;
    }
    return true;
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    if (!checkAuth()) return;
    loadIncidents();
    setupEventListeners();
    setInterval(loadIncidents, 10000);
});

function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const severitySelect = document.getElementById('severityFilter');
    const statusSelect = document.getElementById('statusFilter');
    
    if (searchInput) searchInput.addEventListener('input', (e) => {
        filterText = e.target.value;
        renderIncidents();
    });
    
    if (severitySelect) severitySelect.addEventListener('change', (e) => {
        severityFilter = e.target.value;
        renderIncidents();
    });
    
    if (statusSelect) statusSelect.addEventListener('change', (e) => {
        statusFilter = e.target.value;
        renderIncidents();
    });
}

async function loadIncidents() {
    try {
        const alertsData = await APIClient.get('/dashboard/alerts?limit=100');
        
        allIncidents = (alertsData.alerts || []).map(alert => ({
            id: alert.id,
            alert_type: alert.alert_type,
            username: alert.username,
            ip_address: alert.ip_address,
            severity: alert.severity,
            timestamp: alert.timestamp,
            resolved: alert.resolved,
            // Determine status based on resolved flag and local storage for escalated/tagged
            status: getIncidentStatus(alert),
            tags: getIncidentTags(alert.id)
        }));
        
        updateStats();
        renderIncidents();
    } catch (error) {
        console.error('Error loading incidents:', error);
    }
}

// Store escalated and tagged incidents locally since backend doesn't track this separately
function getIncidentStatus(alert) {
    const localStatus = localStorage.getItem(`incident_status_${alert.id}`);
    if (localStatus) return localStatus;
    return alert.resolved ? 'archived' : 'unreviewed';
}

function setIncidentStatus(id, status) {
    localStorage.setItem(`incident_status_${id}`, status);
}

function getIncidentTags(id) {
    const tags = localStorage.getItem(`incident_tags_${id}`);
    return tags ? JSON.parse(tags) : [];
}

function setIncidentTags(id, tags) {
    localStorage.setItem(`incident_tags_${id}`, JSON.stringify(tags));
}

function updateStats() {
    const criticalUnreviewed = allIncidents.filter(i => i.severity === 'critical' && i.status === 'unreviewed').length;
    const pendingReview = allIncidents.filter(i => i.status === 'unreviewed').length;
    const escalated = allIncidents.filter(i => i.status === 'escalated').length;
    const archived = allIncidents.filter(i => i.status === 'archived').length;
    
    document.getElementById('criticalUnreviewed').textContent = criticalUnreviewed;
    document.getElementById('pendingReview').textContent = pendingReview;
    document.getElementById('escalated').textContent = escalated;
    document.getElementById('archived').textContent = archived;
}

function renderIncidents() {
    const tbody = document.getElementById('incidentsTable');
    
    const filtered = allIncidents.filter(inc => {
        const matchesText = filterText === '' || 
            inc.username.toLowerCase().includes(filterText.toLowerCase()) ||
            inc.ip_address.toLowerCase().includes(filterText.toLowerCase()) ||
            inc.alert_type.toLowerCase().includes(filterText.toLowerCase());
        const matchesSeverity = severityFilter === 'all' || inc.severity === severityFilter;
        const matchesStatus = statusFilter === 'all' || inc.status === statusFilter;
        return matchesText && matchesSeverity && matchesStatus;
    });
    
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No incidents found</td></tr>';
        document.getElementById('incidentCount').textContent = `Showing 0 of ${allIncidents.length} incidents`;
        return;
    }
    
    tbody.innerHTML = filtered.map(inc => {
        const checked = selectedIncidents.includes(inc.id) ? 'checked' : '';
        const severityClass = getSeverityClass(inc.severity);
        const statusClass = getStatusClass(inc.status);
        
        return `
            <tr>
                <td style="padding:1rem;"><input type="checkbox" ${checked} onchange="toggleSelect(${inc.id})"></td>
                <td style="padding:1rem;color:#94a3b8;font-size:0.875rem;">${new Date(inc.timestamp).toLocaleString()}</td>
                <td style="padding:1rem;"><span style="color:#f87171;">!</span> <span style="color:#e2e8f0;font-weight:500;">${InputValidator.sanitize(inc.alert_type)}</span></td>
                <td style="padding:1rem;color:#cbd5e1;">${InputValidator.sanitize(inc.username)}</td>
                <td style="padding:1rem;"><code style="background:#0f172a;padding:0.25rem 0.5rem;border-radius:0.25rem;color:#93c5fd;font-size:0.875rem;">${InputValidator.sanitize(inc.ip_address)}</code></td>
                <td style="padding:1rem;"><span class="badge ${severityClass}">${inc.severity.toUpperCase()}</span></td>
                <td style="padding:1rem;"><span class="badge ${statusClass}">${inc.status.toUpperCase()}</span></td>
                <td style="padding:1rem;">${inc.tags.map(tag => `<span style="background:#1e3a8a;color:#93c5fd;padding:0.125rem 0.5rem;border-radius:0.25rem;font-size:0.75rem;margin-right:0.25rem;">${InputValidator.sanitize(tag)}</span>`).join('')}</td>
            </tr>`;
    }).join('');
    
    document.getElementById('incidentCount').textContent = `Showing ${filtered.length} of ${allIncidents.length} incidents`;
}

function getSeverityClass(severity) {
    switch(severity) {
        case 'critical': return 'danger';
        case 'high': return 'warning';
        case 'medium': return 'warning';
        default: return 'success';
    }
}

function getStatusClass(status) {
    switch(status) {
        case 'escalated': return 'danger';
        case 'archived': return 'success';
        default: return 'warning';
    }
}

function toggleSelect(id) {
    if (selectedIncidents.includes(id)) {
        selectedIncidents = selectedIncidents.filter(i => i !== id);
    } else {
        selectedIncidents.push(id);
    }
    updateBulkActionButtons();
    renderIncidents();
}

function selectAll() {
    const checkbox = document.getElementById('selectAll');
    const filtered = allIncidents.filter(inc => {
        const matchesText = filterText === '' || 
            inc.username.toLowerCase().includes(filterText.toLowerCase()) ||
            inc.ip_address.toLowerCase().includes(filterText.toLowerCase()) ||
            inc.alert_type.toLowerCase().includes(filterText.toLowerCase());
        const matchesSeverity = severityFilter === 'all' || inc.severity === severityFilter;
        const matchesStatus = statusFilter === 'all' || inc.status === statusFilter;
        return matchesText && matchesSeverity && matchesStatus;
    });
    selectedIncidents = checkbox.checked ? filtered.map(i => i.id) : [];
    renderIncidents();
    updateBulkActionButtons();
}

function updateBulkActionButtons() {
    const count = selectedIncidents.length;
    document.getElementById('escalateBtn').textContent = `🚩 Escalate (${count})`;
    document.getElementById('archiveBtn').textContent = `📦 Archive (${count})`;
    document.getElementById('tagBtn').textContent = `🏷️ Tag (${count})`;
}

async function bulkEscalate() {
    if (selectedIncidents.length === 0) { 
        NotificationService.show('Please select at least one incident', 'warning'); 
        return; 
    }
    if (!confirm(`Escalate ${selectedIncidents.length} incident(s) to Administrator?`)) return;
    
    try {
        let successCount = 0;
        for (const id of selectedIncidents) {
            try {
                const res = await APIClient.post('/analyst/escalate-incident', { 
                    incident_id: id, 
                    analyst: SessionManager.getUsername() 
                });
                if (res.success) {
                    successCount++;
                    setIncidentStatus(id, 'escalated');
                }
            } catch (e) { 
                console.error(`Failed to escalate ${id}:`, e); 
            }
        }
        
        if (successCount > 0) {
            NotificationService.show(`Successfully escalated ${successCount} incident(s)`, 'success');
            // Update local state
            allIncidents = allIncidents.map(inc => 
                selectedIncidents.includes(inc.id) ? {...inc, status: 'escalated'} : inc
            );
            selectedIncidents = [];
            document.getElementById('selectAll').checked = false;
            renderIncidents();
            updateStats();
            updateBulkActionButtons();
        }
    } catch (error) {
        console.error('Bulk escalate error:', error);
        NotificationService.show('Error escalating incidents', 'error');
    }
}

async function bulkArchive() {
    if (selectedIncidents.length === 0) { 
        NotificationService.show('Please select at least one incident', 'warning'); 
        return; 
    }
    if (!confirm(`Archive ${selectedIncidents.length} incident(s)?`)) return;
    
    try {
        let successCount = 0;
        for (const id of selectedIncidents) {
            try {
                const res = await APIClient.post('/analyst/archive-incident', { 
                    incident_id: id, 
                    analyst: SessionManager.getUsername() 
                });
                if (res.success) {
                    successCount++;
                    setIncidentStatus(id, 'archived');
                }
            } catch (e) {
                console.error(`Failed to archive ${id}:`, e);
            }
        }
        
        if (successCount > 0) {
            NotificationService.show(`Successfully archived ${successCount} incident(s)`, 'success');
            allIncidents = allIncidents.map(inc => 
                selectedIncidents.includes(inc.id) ? {...inc, status: 'archived'} : inc
            );
            selectedIncidents = [];
            document.getElementById('selectAll').checked = false;
            renderIncidents();
            updateStats();
            updateBulkActionButtons();
        }
    } catch (error) {
        console.error('Bulk archive error:', error);
        NotificationService.show('Error archiving incidents', 'error');
    }
}

async function bulkTag() {
    if (selectedIncidents.length === 0) { 
        NotificationService.show('Please select at least one incident', 'warning'); 
        return; 
    }
    
    const tag = prompt(`Add tag to ${selectedIncidents.length} incident(s):\n\nEnter tag name (e.g., "bot-attack", "false-positive"):`);
    if (!tag || !tag.trim()) return;
    
    const cleanTag = tag.trim();
    
    try {
        let successCount = 0;
        for (const id of selectedIncidents) {
            try {
                const res = await APIClient.post('/analyst/tag-incident', { 
                    incident_id: id, 
                    tag: cleanTag,
                    analyst: SessionManager.getUsername() 
                });
                if (res.success) {
                    successCount++;
                    // Update local tags
                    const existingTags = getIncidentTags(id);
                    if (!existingTags.includes(cleanTag)) {
                        setIncidentTags(id, [...existingTags, cleanTag]);
                    }
                }
            } catch (e) {
                console.error(`Failed to tag ${id}:`, e);
            }
        }
        
        if (successCount > 0) {
            NotificationService.show(`Successfully tagged ${successCount} incident(s) with "${cleanTag}"`, 'success');
            allIncidents = allIncidents.map(inc => {
                if (selectedIncidents.includes(inc.id)) {
                    const newTags = [...new Set([...inc.tags, cleanTag])];
                    return {...inc, tags: newTags};
                }
                return inc;
            });
            selectedIncidents = [];
            document.getElementById('selectAll').checked = false;
            renderIncidents();
            updateBulkActionButtons();
        }
    } catch (error) {
        console.error('Bulk tag error:', error);
        NotificationService.show('Error tagging incidents', 'error');
    }
}

// Export functions - Generate CSV locally from current data
function exportCSV() { 
    const csvContent = generateCSV(allIncidents, ['id', 'alert_type', 'username', 'ip_address', 'timestamp', 'severity', 'status']);
    downloadCSV(csvContent, 'ids_incidents.csv');
    NotificationService.show('IDS incidents exported', 'success');
}

function exportLoginHistory() { 
    // Try to fetch login history, fallback to local generation
    APIClient.get('/dashboard/login-history?limit=1000')
        .then(data => {
            const csvContent = generateCSV(data.history || [], ['username', 'ip_address', 'timestamp', 'status', 'location']);
            downloadCSV(csvContent, 'login_history.csv');
            NotificationService.show('Login history exported', 'success');
        })
        .catch(() => {
            NotificationService.show('Unable to export login history', 'error');
        });
}

function exportForensicPackage() { 
    // Export all available data
    const csvContent = generateCSV(allIncidents, ['id', 'alert_type', 'username', 'ip_address', 'timestamp', 'severity', 'status', 'tags']);
    downloadCSV(csvContent, 'forensic_package.csv');
    NotificationService.show('Forensic package exported', 'success');
}

function exportSelected() {
    if (selectedIncidents.length === 0) { 
        NotificationService.show('Please select incidents to export', 'warning'); 
        return; 
    }
    const selectedData = allIncidents.filter(inc => selectedIncidents.includes(inc.id));
    const csvContent = generateCSV(selectedData, ['id', 'alert_type', 'username', 'ip_address', 'timestamp', 'severity', 'status', 'tags']);
    downloadCSV(csvContent, 'selected_incidents.csv');
    NotificationService.show(`Exported ${selectedIncidents.length} selected incidents`, 'success');
}

function generateCSV(data, columns) {
    if (!data || data.length === 0) return '';
    
    const header = columns.join(',');
    const rows = data.map(row => {
        return columns.map(col => {
            let val = row[col];
            if (Array.isArray(val)) val = val.join(';');
            if (val === null || val === undefined) val = '';
            // Escape quotes and wrap in quotes if contains comma
            val = String(val).replace(/"/g, '""');
            if (val.includes(',') || val.includes('"') || val.includes('\n')) {
                val = `"${val}"`;
            }
            return val;
        }).join(',');
    });
    
    return [header, ...rows].join('\n');
}

function downloadCSV(content, filename) {
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

// Alternative: Try server export first, fallback to local
async function tryServerExport(endpoint, fallbackFn, filename) {
    try {
        const res = await fetch(`${API_BASE}${endpoint}`, { 
            headers: APIClient.getHeaders() 
        });
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            return true;
        }
    } catch (e) {
        console.log('Server export failed, using fallback');
    }
    // Use fallback
    fallbackFn();
    return false;
}

// Reports - Generate locally from available data
async function generateWeeklyReport() { 
    NotificationService.show('Generating weekly report...', 'info');
    
    try {
        // Try to get from admin endpoint first (if user has admin role)
        const report = await APIClient.get('/admin/reports/weekly');
        displayReport(report);
    } catch (e) {
        // Generate locally if admin endpoint fails
        const report = generateLocalReport('weekly', 7);
        displayReport(report);
    }
}

async function generateMonthlyReport() { 
    NotificationService.show('Generating monthly report...', 'info');
    
    try {
        const report = await APIClient.get('/admin/reports/monthly');
        displayReport(report);
    } catch (e) {
        const report = generateLocalReport('monthly', 30);
        displayReport(report);
    }
}

function generateThreatReport() { 
    NotificationService.show('Generating threat intelligence report...', 'info');
    const report = generateLocalReport('threat', 30);
    report.report_type = 'Threat Intelligence';
    displayReport(report);
}

function generateIncidentReport() { 
    NotificationService.show('Generating incident response report...', 'info');
    
    const escalatedIncidents = allIncidents.filter(i => i.status === 'escalated');
    const report = {
        report_type: 'Incident Response',
        period: `Last 30 days`,
        total_escalated: escalatedIncidents.length,
        escalated_by_severity: {
            critical: escalatedIncidents.filter(i => i.severity === 'critical').length,
            high: escalatedIncidents.filter(i => i.severity === 'high').length,
            medium: escalatedIncidents.filter(i => i.severity === 'medium').length,
            low: escalatedIncidents.filter(i => i.severity === 'low').length
        },
        top_attacked_users: getTopAttackedUsers(escalatedIncidents),
        generated_at: new Date().toISOString()
    };
    displayReport(report);
}

function generateLocalReport(type, days) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    const recentIncidents = allIncidents.filter(i => new Date(i.timestamp) >= cutoffDate);
    const failedCount = recentIncidents.length;
    const resolvedCount = recentIncidents.filter(i => i.status === 'archived').length;
    
    const severityBreakdown = {
        critical: recentIncidents.filter(i => i.severity === 'critical').length,
        high: recentIncidents.filter(i => i.severity === 'high').length,
        medium: recentIncidents.filter(i => i.severity === 'medium').length,
        low: recentIncidents.filter(i => i.severity === 'low').length
    };
    
    return {
        report_type: type,
        period: `${cutoffDate.toISOString().split('T')[0]} to ${new Date().toISOString().split('T')[0]}`,
        total_logins: 'N/A (requires admin)',
        failed_logins: failedCount,
        success_rate: 'N/A',
        top_attacked_users: getTopAttackedUsers(recentIncidents),
        severity_breakdown: severityBreakdown,
        generated_at: new Date().toISOString()
    };
}

function getTopAttackedUsers(incidents) {
    const userCounts = {};
    incidents.forEach(i => {
        userCounts[i.username] = (userCounts[i.username] || 0) + 1;
    });
    return Object.entries(userCounts)
        .map(([username, count]) => ({ username, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
}

function displayReport(report) {
    document.getElementById('reportDisplay').style.display = 'block';
    
    let html = `
        <div style="color: #e2e8f0; line-height: 1.8;">
            <h3 style="color: #60a5fa; margin-bottom: 1rem; font-size: 1.5rem;">
                📊 ${(report.report_type || 'SECURITY').toUpperCase()} REPORT
            </h3>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem; border-left: 4px solid #60a5fa;">
                <p><strong style="color: #60a5fa;">Report Period:</strong> ${report.period || 'N/A'}</p>
                <p><strong style="color: #60a5fa;">Generated:</strong> ${report.generated_at ? new Date(report.generated_at).toLocaleString() : new Date().toLocaleString()}</p>
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">📈 Overview Statistics</h4>
                <p><strong>Total Login Attempts:</strong> ${report.total_logins || 0}</p>
                <p><strong>Failed/Alert Count:</strong> <span style="color: #f87171;">${report.failed_logins || 0}</span></p>
                <p><strong>Success Rate:</strong> <span style="color: #4ade80;">${report.success_rate || 'N/A'}</span></p>
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">🎯 Top Attacked Users</h4>
                ${report.top_attacked_users && report.top_attacked_users.length > 0 ? `
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${report.top_attacked_users.map(u => `
                            <li style="padding: 0.5rem; background: #0f172a; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                                <strong>${InputValidator.sanitize(u.username)}</strong>: <span style="color: #f87171;">${u.count} attacks</span>
                            </li>
                        `).join('')}
                    </ul>
                ` : '<p style="color: #94a3b8;">No attack data available</p>'}
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">⚠️ Alert Severity Breakdown</h4>
                ${report.severity_breakdown && Object.keys(report.severity_breakdown).length > 0 ? `
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${Object.entries(report.severity_breakdown).map(([severity, count]) => {
                            const colors = {critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#4ade80'};
                            return `
                                <li style="padding: 0.5rem; background: #0f172a; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                                    <strong style="text-transform: uppercase;">${severity}:</strong> 
                                    <span style="color: ${colors[severity] || '#cbd5e1'};">${count} alerts</span>
                                </li>
                            `;
                        }).join('')}
                    </ul>
                ` : '<p style="color: #94a3b8;">No alerts in this period</p>'}
            </div>
        </div>
    `;
    
    document.getElementById('reportContent').innerHTML = html;
    NotificationService.show('Report generated successfully', 'success');
    
    // Scroll to report
    document.getElementById('reportDisplay').scrollIntoView({ behavior: 'smooth' });
}

// Tab switching
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
        tab.style.display = 'none';
    });
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    
    const targetTab = document.getElementById(tabName + 'Tab');
    if (targetTab) {
        targetTab.classList.add('active');
        targetTab.style.display = 'block';
    }
    
    // Find and activate the clicked button
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
        if (btn.textContent.toLowerCase().includes(tabName.substring(0, 4))) {
            btn.classList.add('active');
        }
    });
}

function logout() {
    APIClient.post('/logout', {}).catch(() => {});
    SessionManager.clearSession();
    // Clear local incident status/tags on logout
    Object.keys(localStorage).forEach(key => {
        if (key.startsWith('incident_')) {
            localStorage.removeItem(key);
        }
    });
    window.location.href = 'login.html';
}
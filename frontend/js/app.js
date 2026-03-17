/**
 * Main Application JavaScript
 */

// State
let currentProject = null;
let currentPage = 'dashboard';

// Initialize
document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupNavigation();
    setupModals();
    setupForms();
    await loadDashboard();
    await loadToolStatus();
}

// Navigation
function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            showPage(page);
        });
    });

    document.querySelectorAll('.view-all').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            showPage(page);
        });
    });
}

function showPage(page) {
    currentPage = page;

    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Update pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`${page}-page`).classList.add('active');

    // Update title
    const titles = {
        dashboard: 'Dashboard',
        projects: 'Projects',
        scans: 'All Scans',
        vulnerabilities: 'Vulnerabilities',
        tools: 'Tools Status',
        'project-detail': currentProject?.name || 'Project'
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Load data
    if (page === 'projects') loadProjects();
    if (page === 'scans') loadAllScans();
    if (page === 'vulnerabilities') loadAllVulnerabilities();
    if (page === 'tools') loadToolStatus();
}

// Modals
function setupModals() {
    document.getElementById('new-project-btn').addEventListener('click', () => {
        openModal('new-project-modal');
    });

    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal.id);
        });
    });
}

function openModal(id) {
    document.getElementById(id).classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

// Forms
function setupForms() {
    document.getElementById('new-project-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const name = document.getElementById('project-name-input').value;
        const domain = document.getElementById('project-domain-input').value;
        const description = document.getElementById('project-desc-input').value;

        try {
            await api.createProject({ name, target_domain: domain, description });
            closeModal('new-project-modal');
            e.target.reset();
            loadDashboard();
            if (currentPage === 'projects') loadProjects();
            showNotification('Project created successfully!', 'success');
        } catch (error) {
            showNotification('Failed to create project: ' + error.message, 'error');
        }
    });
}

// Dashboard
async function loadDashboard() {
    try {
        const projects = await api.getProjects(5);

        // Update stats
        document.getElementById('total-projects').textContent = projects.total || projects.length;

        // Get aggregate stats
        let totalSubdomains = 0;
        let activeScans = 0;
        let criticalVulns = 0;

        for (const project of projects.projects || projects) {
            try {
                const stats = await api.getProjectStats(project.id);
                totalSubdomains += stats.subdomains || 0;
                activeScans += stats.scans_running || 0;
                criticalVulns += stats.critical_vulns || 0;
            } catch { }
        }

        document.getElementById('total-subdomains').textContent = totalSubdomains;
        document.getElementById('active-scans').textContent = activeScans;
        document.getElementById('critical-vulns').textContent = criticalVulns;

        // Render recent projects
        const container = document.getElementById('recent-projects');
        if ((projects.projects || projects).length === 0) {
            container.innerHTML = '<p class="empty-state">No projects yet. Create one to get started!</p>';
        } else {
            container.innerHTML = (projects.projects || projects).slice(0, 5).map(p => `
        <div class="project-card" onclick="viewProject(${p.id})">
          <div class="project-card-header">
            <h3>${escapeHtml(p.name)}</h3>
            <span class="domain-badge">${escapeHtml(p.target_domain)}</span>
          </div>
        </div>
      `).join('');
        }
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

// Projects
async function loadProjects() {
    try {
        const data = await api.getProjects();
        const projects = data.projects || data;

        const grid = document.getElementById('projects-grid');

        if (projects.length === 0) {
            grid.innerHTML = '<p class="empty-state">No projects yet. Create one to get started!</p>';
            return;
        }

        grid.innerHTML = await Promise.all(projects.map(async (p) => {
            let stats = { subdomains: 0, urls: 0, vulnerabilities: 0 };
            try { stats = await api.getProjectStats(p.id); } catch { }

            return `
        <div class="project-card" onclick="viewProject(${p.id})">
          <div class="project-card-header">
            <h3>${escapeHtml(p.name)}</h3>
            <span class="domain-badge">${escapeHtml(p.target_domain)}</span>
          </div>
          <div class="project-stats-row">
            <div class="project-stat">
              <span>${stats.subdomains || 0}</span>
              <span>Subdomains</span>
            </div>
            <div class="project-stat">
              <span>${stats.urls || 0}</span>
              <span>URLs</span>
            </div>
            <div class="project-stat">
              <span>${stats.vulnerabilities || 0}</span>
              <span>Vulns</span>
            </div>
          </div>
        </div>
      `;
        })).then(html => html.join(''));
    } catch (error) {
        console.error('Failed to load projects:', error);
    }
}

async function viewProject(projectId) {
    try {
        currentProject = await api.getProject(projectId);
        document.getElementById('project-name').textContent = currentProject.name;
        document.getElementById('project-domain').textContent = currentProject.target_domain;

        showPage('project-detail');
        setupProjectTabs();
        setupScanButtons();
        setupDeleteButton();
        loadProjectSubdomains();
    } catch (error) {
        showNotification('Failed to load project', 'error');
    }
}

function setupProjectTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');

            const tab = btn.dataset.tab;
            if (tab === 'subdomains') loadProjectSubdomains();
            if (tab === 'urls') loadProjectUrls();
            if (tab === 'vulnerabilities') loadProjectVulns();
            if (tab === 'scans') loadProjectScans();
        });
    });
}

function setupScanButtons() {
    document.querySelectorAll('.scan-type-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const scanType = btn.dataset.type;
            try {
                const scan = await api.startScan(currentProject.id, scanType);
                showNotification(`Started ${scanType} scan`, 'success');
                openScanModal(scan.id, scanType);
            } catch (error) {
                showNotification('Failed to start scan: ' + error.message, 'error');
            }
        });
    });
}

function setupDeleteButton() {
    const deleteBtn = document.getElementById('delete-project-btn');
    if (deleteBtn) {
        deleteBtn.onclick = async () => {
            if (!currentProject) return;

            const confirmed = confirm(
                `⚠️ Are you sure you want to delete "${currentProject.name}"?\n\n` +
                `This will permanently delete:\n` +
                `• All subdomains\n` +
                `• All collected URLs\n` +
                `• All vulnerabilities\n` +
                `• All scan history\n\n` +
                `This action cannot be undone!`
            );

            if (confirmed) {
                try {
                    await api.deleteProject(currentProject.id);
                    showNotification('Project deleted successfully', 'success');
                    currentProject = null;
                    showPage('projects');
                    loadDashboard();
                } catch (error) {
                    showNotification('Failed to delete project: ' + error.message, 'error');
                }
            }
        };
    }
}

async function loadProjectSubdomains(page = 1) {
    if (!currentProject) return;

    try {
        const data = await api.getSubdomains(currentProject.id, { limit: 50, offset: (page - 1) * 50 });
        const tbody = document.getElementById('subdomains-tbody');

        const items = data.items || data.subdomains || [];
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No subdomains found. Run a subdomain scan!</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(s => `
      <tr>
        <td><a href="https://${escapeHtml(s.subdomain)}" target="_blank">${escapeHtml(s.subdomain)}</a></td>
        <td>${escapeHtml(s.ip || '-')}</td>
        <td>${s.is_alive ? '<span class="status-badge status-running">Alive</span>' : '-'}</td>
        <td>${escapeHtml(s.title || '-')}</td>
        <td>${escapeHtml(s.technologies || '-')}</td>
      </tr>
    `).join('');
    } catch (error) {
        console.error('Failed to load subdomains:', error);
    }
}

async function loadProjectUrls(page = 1) {
    if (!currentProject) return;

    try {
        const data = await api.getUrls(currentProject.id, { limit: 50, offset: (page - 1) * 50 });
        const tbody = document.getElementById('urls-tbody');

        const items = data.items || data.urls || [];
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No URLs found. Run URL collection!</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(u => `
      <tr>
        <td><a href="${escapeHtml(u.url)}" target="_blank">${escapeHtml(truncate(u.url, 80))}</a></td>
        <td>${escapeHtml(u.source || '-')}</td>
        <td>${u.parameters ? u.parameters.length : 0}</td>
        <td>${escapeHtml(u.url_type || '-')}</td>
      </tr>
    `).join('');
    } catch (error) {
        console.error('Failed to load URLs:', error);
    }
}

async function loadProjectVulns() {
    if (!currentProject) return;

    try {
        const data = await api.getVulnerabilities(currentProject.id);
        const tbody = document.getElementById('vulns-tbody');

        const items = data.items || data.vulnerabilities || [];
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No vulnerabilities found. Run vulnerability scans!</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(v => `
      <tr class="${v.false_positive ? 'false-positive' : ''} ${v.verified ? 'verified' : ''}">
        <td><span class="severity-badge severity-${v.severity}">${v.severity}</span></td>
        <td>${escapeHtml(v.vuln_type)}</td>
        <td><a href="${escapeHtml(v.url)}" target="_blank">${escapeHtml(truncate(v.url, 60))}</a></td>
        <td>${escapeHtml(v.tool || '-')}</td>
        <td>
            <button class="btn btn-sm ${v.verified ? 'btn-success' : 'btn-secondary'}" 
                onclick="toggleVerify(${v.id}, ${!v.verified})">
                ${v.verified ? 'Verified' : 'Verify'}
            </button>
            <button class="btn btn-sm ${v.false_positive ? 'btn-danger' : 'btn-secondary'}" 
                onclick="toggleFalsePositive(${v.id}, ${!v.false_positive})">
                ${v.false_positive ? 'FP' : 'Mark FP'}
            </button>
            <button class="btn btn-sm btn-secondary" onclick="alert('${escapeHtml(v.evidence || 'No details')}')">Details</button>
        </td>
      </tr>
    `).join('');
    } catch (error) {
        console.error('Failed to load vulnerabilities:', error);
    }
}

async function loadProjectScans() {
    if (!currentProject) return;

    try {
        const data = await api.getScans(currentProject.id);
        const container = document.getElementById('project-scans-list');

        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<p class="empty-state">No scans yet.</p>';
            return;
        }

        container.innerHTML = renderScansList(data.scans);
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

// All Scans
async function loadAllScans() {
    try {
        const data = await api.getScans();
        const container = document.getElementById('all-scans-list');

        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<p class="empty-state">No scans yet.</p>';
            return;
        }

        container.innerHTML = renderScansList(data.scans);
    } catch (error) {
        console.error('Failed to load scans:', error);
    }
}

function renderScansList(scans) {
    return `<table class="data-table">
    <thead>
      <tr>
        <th>Type</th>
        <th>Status</th>
        <th>Started</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      ${scans.map(s => `
        <tr>
          <td>${escapeHtml(s.scan_type)}</td>
          <td><span class="status-badge status-${s.status.toLowerCase()}">${s.status}</span></td>
          <td>${formatDate(s.started_at)}</td>
          <td>
            ${s.status === 'RUNNING' ? `<button class="btn btn-danger" onclick="stopScan(${s.id})">Stop</button>` : ''}
            <button class="btn btn-secondary" onclick="viewScanLogs(${s.id})">Logs</button>
          </td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
}

async function stopScan(scanId) {
    try {
        await api.stopScan(scanId);
        showNotification('Scan stopped', 'success');
        if (currentPage === 'scans') loadAllScans();
        if (currentPage === 'project-detail') loadProjectScans();
    } catch (error) {
        showNotification('Failed to stop scan', 'error');
    }
}

async function viewScanLogs(scanId) {
    try {
        const logs = await api.getScanLogs(scanId);
        document.getElementById('scan-logs-content').textContent = logs.logs || 'No logs available';
        openModal('scan-modal');
    } catch (error) {
        showNotification('Failed to load logs', 'error');
    }
}

function openScanModal(scanId, scanType) {
    document.getElementById('modal-scan-type').textContent = scanType;
    document.getElementById('modal-scan-status').textContent = 'Running';
    document.getElementById('scan-logs-content').textContent = 'Connecting...';
    openModal('scan-modal');

    // Connect WebSocket
    scanWs.connect(scanId);
    scanWs.onMessage(scanId, (msg) => {
        // Handle initial state
        if (msg.type === 'initial') {
            const data = msg.data;
            if (data.logs) {
                document.getElementById('scan-logs-content').textContent = data.logs;
                document.getElementById('scan-logs').scrollTop = document.getElementById('scan-logs').scrollHeight;
            } else {
                document.getElementById('scan-logs-content').textContent += '\nConnected to scan logs...';
            }
            if (data.status) {
                updateScanStatus(data.status);
            }
        }

        // Handle new logs
        if (msg.type === 'log') {
            const message = msg.data.message;
            if (message) {
                document.getElementById('scan-logs-content').textContent += message + '\n';
                document.getElementById('scan-logs').scrollTop = document.getElementById('scan-logs').scrollHeight;
            }
        }

        // Handle status updates
        if (msg.type === 'status') {
            updateScanStatus(msg.data.status);
        }
    });
}

function updateScanStatus(status) {
    const statusEl = document.getElementById('modal-scan-status');
    if (statusEl) {
        statusEl.textContent = status;
        statusEl.className = `status-badge status-${status.toLowerCase()}`;
    }
}

// All Vulnerabilities
async function loadAllVulnerabilities() {
    try {
        const severity = document.getElementById('severity-filter')?.value;
        const data = await api.getVulnerabilities(null, severity ? { severity } : {});
        const tbody = document.getElementById('all-vulns-tbody');

        const items = data.items || data.vulnerabilities || [];
        if (items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No vulnerabilities found.</td></tr>';
            return;
        }

        tbody.innerHTML = items.map(v => `
      <tr class="${v.false_positive ? 'false-positive' : ''} ${v.verified ? 'verified' : ''}">
        <td><span class="severity-badge severity-${v.severity}">${v.severity}</span></td>
        <td>${escapeHtml(v.vuln_type)}</td>
        <td><a href="${escapeHtml(v.url)}" target="_blank">${escapeHtml(truncate(v.url, 50))}</a></td>
        <td>${v.project_id || '-'}</td>
        <td>${escapeHtml(v.tool || '-')}</td>
      </tr>
    `).join('');
    } catch (error) {
        console.error('Failed to load vulnerabilities:', error);
    }
}

// Tools Status
async function loadToolStatus() {
    try {
        const data = await api.getToolStatus();

        document.getElementById('tools-count').textContent = `${data.available_count}/${data.total_count} tools`;

        const grid = document.getElementById('tools-grid');
        if (grid) {
            grid.innerHTML = Object.entries(data.tools).map(([name, available]) => `
        <div class="tool-card ${available ? 'available' : 'unavailable'}">
          <div class="tool-indicator ${available ? 'available' : 'unavailable'}"></div>
          <span>${name}</span>
        </div>
      `).join('');
        }
    } catch (error) {
        document.getElementById('tools-count').textContent = 'Error loading';
    }
}

// Vulnerability Actions
async function toggleVerify(id, verified) {
    try {
        await api.updateVulnerability(id, { verified });
        // Refresh current list
        if (currentPage === 'vulnerabilities') loadAllVulnerabilities();
        else loadProjectVulns();
    } catch (error) {
        showNotification('Failed to update vulnerability', 'error');
    }
}

async function toggleFalsePositive(id, falsePositive) {
    try {
        await api.updateVulnerability(id, { false_positive: falsePositive });
        // Refresh current list
        if (currentPage === 'vulnerabilities') loadAllVulnerabilities();
        else loadProjectVulns();
    } catch (error) {
        showNotification('Failed to update vulnerability', 'error');
    }
}

// Utilities
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[m]));
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
}

function showNotification(message, type = 'info') {
    console.log(`[${type}] ${message}`);
    // Could add toast notifications here
    alert(message);
}

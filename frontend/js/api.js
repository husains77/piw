/**
 * API Module - HTTP client for backend communication
 */

const API_BASE = '';

class ApiClient {
    constructor() {
        this.baseUrl = API_BASE;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options,
        };

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'API request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Projects
    async getProjects(limit = 100, offset = 0) {
        return this.request(`/api/projects?limit=${limit}&offset=${offset}`);
    }

    async getProject(projectId) {
        return this.request(`/api/projects/${projectId}`);
    }

    async getProjectStats(projectId) {
        return this.request(`/api/projects/${projectId}/stats`);
    }

    async createProject(data) {
        return this.request('/api/projects', { method: 'POST', body: data });
    }

    async deleteProject(projectId) {
        return this.request(`/api/projects/${projectId}`, { method: 'DELETE' });
    }

    // Scans
    async startScan(projectId, scanType, config = {}) {
        return this.request('/api/scans', {
            method: 'POST',
            body: { project_id: projectId, scan_type: scanType, config }
        });
    }

    async getScans(projectId = null, limit = 50) {
        let url = `/api/scans?limit=${limit}`;
        if (projectId) url += `&project_id=${projectId}`;
        return this.request(url);
    }

    async getScan(scanId) {
        return this.request(`/api/scans/${scanId}`);
    }

    async stopScan(scanId) {
        return this.request(`/api/scans/${scanId}/stop`, { method: 'POST' });
    }

    async getScanLogs(scanId) {
        return this.request(`/api/scans/${scanId}/logs`);
    }

    // Results
    async getSubdomains(projectId, params = {}) {
        const query = new URLSearchParams({ project_id: projectId, ...params });
        return this.request(`/api/results/subdomains?${query}`);
    }

    async getUrls(projectId, params = {}) {
        const query = new URLSearchParams({ project_id: projectId, ...params });
        return this.request(`/api/results/urls?${query}`);
    }

    async getVulnerabilities(projectId = null, params = {}) {
        const query = new URLSearchParams(params);
        if (projectId) query.set('project_id', projectId);
        return this.request(`/api/results/vulnerabilities?${query}`);
    }

    async updateVulnerability(vulnId, data) {
        return this.request(`/api/results/vulnerabilities/${vulnId}`, {
            method: 'PATCH',
            body: data
        });
    }

    // Tools
    async getToolStatus() {
        return this.request('/api/tools');
    }
}

const api = new ApiClient();

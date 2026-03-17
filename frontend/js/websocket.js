/**
 * WebSocket Module - Real-time updates
 */

class ScanWebSocket {
    constructor() {
        this.connections = new Map();
        this.handlers = new Map();
    }

    connect(scanId) {
        if (this.connections.has(scanId)) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scan/${scanId}`);

        ws.onopen = () => console.log(`WebSocket connected for scan ${scanId}`);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            const handler = this.handlers.get(scanId);
            if (handler) handler(data);
        };

        ws.onerror = (error) => console.error('WebSocket error:', error);

        ws.onclose = () => {
            this.connections.delete(scanId);
            console.log(`WebSocket closed for scan ${scanId}`);
        };

        this.connections.set(scanId, ws);
    }

    disconnect(scanId) {
        const ws = this.connections.get(scanId);
        if (ws) {
            ws.close();
            this.connections.delete(scanId);
        }
    }

    onMessage(scanId, handler) {
        this.handlers.set(scanId, handler);
    }

    send(scanId, message) {
        const ws = this.connections.get(scanId);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message));
        }
    }
}

const scanWs = new ScanWebSocket();

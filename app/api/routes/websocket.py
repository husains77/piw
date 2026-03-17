"""
WebSocket Routes for Real-time Updates

Provides real-time scan progress streaming via WebSocket.

WebSocket Endpoints:
- /ws/scan/{scan_id} - Stream logs for a specific scan
- /ws/project/{project_id} - Stream all activity for a project
"""

import asyncio
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, Scan


router = APIRouter(tags=["websocket"])


# Connection manager for WebSocket clients
class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.
    
    Supports:
    - Multiple clients per scan
    - Broadcast messages to all clients watching a scan
    - Clean disconnect handling
    """
    
    def __init__(self):
        # scan_id -> set of WebSocket connections
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # project_id -> set of WebSocket connections
        self.project_connections: Dict[int, Set[WebSocket]] = {}
    
    async def connect_scan(self, websocket: WebSocket, scan_id: int):
        """Accept a WebSocket connection for a scan."""
        await websocket.accept()
        
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        
        self.active_connections[scan_id].add(websocket)
    
    async def connect_project(self, websocket: WebSocket, project_id: int):
        """Accept a WebSocket connection for a project."""
        await websocket.accept()
        
        if project_id not in self.project_connections:
            self.project_connections[project_id] = set()
        
        self.project_connections[project_id].add(websocket)
    
    def disconnect_scan(self, websocket: WebSocket, scan_id: int):
        """Remove a WebSocket connection for a scan."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            
            # Clean up empty sets
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
    
    def disconnect_project(self, websocket: WebSocket, project_id: int):
        """Remove a WebSocket connection for a project."""
        if project_id in self.project_connections:
            self.project_connections[project_id].discard(websocket)
            
            if not self.project_connections[project_id]:
                del self.project_connections[project_id]
    
    async def broadcast_to_scan(self, scan_id: int, message: dict):
        """Send a message to all clients watching a scan."""
        if scan_id in self.active_connections:
            disconnected = set()
            
            for websocket in self.active_connections[scan_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.add(websocket)
            
            # Clean up disconnected clients
            for ws in disconnected:
                self.active_connections[scan_id].discard(ws)
    
    async def broadcast_to_project(self, project_id: int, message: dict):
        """Send a message to all clients watching a project."""
        if project_id in self.project_connections:
            disconnected = set()
            
            for websocket in self.project_connections[project_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.add(websocket)
            
            for ws in disconnected:
                self.project_connections[project_id].discard(ws)


# Global connection manager instance
manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: int):
    """
    WebSocket endpoint for streaming scan logs.
    
    Clients connect to receive real-time updates about:
    - Log output from tools
    - Scan status changes
    - Items found count updates
    
    Message format:
    {
        "type": "log" | "status" | "result" | "complete",
        "data": { ... }
    }
    """
    await manager.connect_scan(websocket, scan_id)
    
    try:
        # Send initial scan state
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            
            if scan:
                await websocket.send_json({
                    "type": "initial",
                    "data": {
                        "scan_id": scan.id,
                        "status": scan.status,
                        "logs": scan.log_output or "",
                        "items_found": scan.items_found,
                    }
                })
        
        # Keep connection alive and wait for messages
        while True:
            try:
                # Wait for client messages (ping/pong, etc.)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0  # 30 second timeout
                )
                
                # Handle ping
                if data == "ping":
                    await websocket.send_text("pong")
                    
            except asyncio.TimeoutError:
                # Send heartbeat
                try:
                    await websocket.send_json({"type": "heartbeat"})
                except Exception:
                    break
                    
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect_scan(websocket, scan_id)


@router.websocket("/ws/project/{project_id}")
async def websocket_project(websocket: WebSocket, project_id: int):
    """
    WebSocket endpoint for streaming all project activity.
    
    Clients receive updates about all scans in the project.
    """
    await manager.connect_project(websocket, project_id)
    
    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                if data == "ping":
                    await websocket.send_text("pong")
                    
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "heartbeat"})
                except Exception:
                    break
                    
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect_project(websocket, project_id)


# Helper function for pipeline to send updates
async def send_scan_update(scan_id: int, update_type: str, data: dict):
    """
    Send an update to all clients watching a scan.
    
    Called by the pipeline during scan execution.
    
    Args:
        scan_id: The scan being updated
        update_type: Type of update (log, status, result, complete)
        data: Update data
    """
    await manager.broadcast_to_scan(scan_id, {
        "type": update_type,
        "data": data
    })


async def send_project_update(project_id: int, update_type: str, data: dict):
    """
    Send an update to all clients watching a project.
    """
    await manager.broadcast_to_project(project_id, {
        "type": update_type,
        "data": data
    })

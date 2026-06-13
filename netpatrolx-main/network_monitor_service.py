#!/usr/bin/env python3
"""
NET-PATROL-X Network Monitor Service
Integrates real-time network monitoring with FastAPI backend
"""

import asyncio
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Optional
import psutil
import socket
import subprocess
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd

class NetworkStats(BaseModel):
    """Network statistics model"""
    timestamp: str
    interfaces: Dict
    connections: List[Dict]
    encrypted_traffic: List[Dict]
    network_io: Dict
    threats_detected: int
    total_flows_analyzed: int

class ThreatAlert(BaseModel):
    """Threat alert model"""
    timestamp: str
    threat_level: str
    flow_id: str
    probability: float
    top_contributors: List[List]
    description: str

class NetworkMonitorService:
    """Network monitoring service that integrates with FastAPI"""
    
    def __init__(self, model_path="./out/global_model.pkl"):
        self.model_path = model_path
        self.model = self._load_model()
        self.active_connections: Dict[str, WebSocket] = {}
        self.network_stats = {}
        self.threat_alerts = []
        self.is_monitoring = False
        self.monitoring_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'analyzed_flows': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }
    
    def _load_model(self):
        """Load the trained model"""
        try:
            model_data = joblib.load(self.model_path)
            print(f"✅ Loaded model from {self.model_path}")
            return model_data
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return None
    
    def get_network_interfaces(self):
        """Get network interfaces and their status"""
        interfaces = {}
        
        for interface_name, interface_addresses in psutil.net_if_addrs().items():
            interface_info = {
                'name': interface_name,
                'addresses': [],
                'is_up': False,
                'speed': 'Unknown',
                'mtu': 'Unknown'
            }
            
            for address in interface_addresses:
                interface_info['addresses'].append({
                    'family': str(address.family),
                    'address': address.address,
                    'netmask': address.netmask,
                    'broadcast': address.broadcast
                })
                
                if address.family == socket.AF_INET and address.address != '127.0.0.1':
                    interface_info['is_up'] = True
            
            interfaces[interface_name] = interface_info
        
        # Get interface statistics
        try:
            stats = psutil.net_if_stats()
            for interface_name in interfaces:
                if interface_name in stats:
                    stat = stats[interface_name]
                    interfaces[interface_name]['speed'] = f"{stat.speed} Mbps" if stat.speed > 0 else "Unknown"
                    interfaces[interface_name]['mtu'] = stat.mtu
                    interfaces[interface_name]['is_up'] = stat.isup
        except:
            pass
        
        return interfaces
    
    def _fallback_lsof_connections(self):
        """Fallback: use lsof to list connections for current user without sudo."""
        results = []
        try:
            # -nP: no DNS/port names, faster; -i: inet; -sTCP:ESTABLISHED for established only
            proc = subprocess.run([
                'lsof', '-nP', '-i',
            ], capture_output=True, text=True, timeout=3)
            lines = proc.stdout.strip().split('\n')
            # Typical format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            # We'll do a light parse to extract PID, USER, NAME (host:port->host:port), and state
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                command, pid, user = parts[0], parts[1], parts[2]
                name_col = parts[-2] if parts[-1] in {"(ESTABLISHED)", "(LISTEN)"} else parts[-1]
                state = 'ESTABLISHED' if parts[-1] == '(ESTABLISHED)' else ('LISTEN' if parts[-1] == '(LISTEN)' else 'UNKNOWN')
                if ':' in name_col:
                    # Split local and remote if present
                    if '->' in name_col:
                        local, remote = name_col.split('->', 1)
                    else:
                        local, remote = name_col, ''
                    results.append({
                        'family': 'INET',
                        'type': 'STREAM',
                        'local_address': local,
                        'remote_address': remote or 'Unknown',
                        'status': state,
                        'pid': int(pid) if pid.isdigit() else None,
                        'process_name': command
                    })
        except Exception:
            # As a last resort, return empty list silently
            return []
        return results

    def get_active_connections(self):
        """Get active network connections. Works without sudo by limiting to user-owned connections.
        Falls back to lsof parsing on platforms where psutil is restricted.
        """
        connections = []
        try:
            current_uid = None
            try:
                current_uid = psutil.Process().uids().real  # type: ignore[attr-defined]
            except Exception:
                current_uid = None

            for conn in psutil.net_connections(kind='inet'):
                if conn.status not in {'ESTABLISHED', 'LISTEN'}:
                    continue

                # Filter: if we don't have root, only include those with a PID and same user (best-effort)
                include = True
                proc_name = 'Unknown'
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                        if current_uid is not None:
                            puids = getattr(p, 'uids', None)
                            if callable(puids):
                                puid = puids().real  # type: ignore[call-arg]
                                include = (puid == current_uid)
                    except psutil.AccessDenied:
                        # Cannot inspect process; include but without name
                        include = True
                    except Exception:
                        include = True
                else:
                    # No PID info; likely requires elevated privileges. Skip to avoid noise.
                    include = False

                if not include:
                    continue

                connections.append({
                    'family': conn.family.name if conn.family else 'Unknown',
                    'type': conn.type.name if conn.type else 'Unknown',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'Unknown',
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'Unknown',
                    'status': conn.status,
                    'pid': conn.pid,
                    'process_name': proc_name
                })

            # If nothing found, try lsof fallback
            if not connections:
                connections = self._fallback_lsof_connections()

        except psutil.AccessDenied:
            connections = self._fallback_lsof_connections()
        except Exception:
            # Silent failure path to avoid log spam
            pass

        return connections
    
    def get_network_stats(self):
        """Get network I/O statistics"""
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            stats = {}
            
            for interface, counters in io_counters.items():
                stats[interface] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'errin': counters.errin,
                    'errout': counters.errout,
                    'dropin': counters.dropin,
                    'dropout': counters.dropout
                }
            
            return stats
        except Exception as e:
            print(f"Error getting network stats: {e}")
            return {}
    
    def analyze_encrypted_traffic(self, connections):
        """Analyze connections for encrypted traffic patterns"""
        encrypted_connections = []
        
        # Common encrypted ports
        encrypted_ports = {
            443: 'HTTPS/TLS',
            993: 'IMAPS',
            995: 'POP3S',
            587: 'SMTP+TLS',
            465: 'SMTPS',
            8443: 'HTTPS-Alt',
            8080: 'HTTP-Proxy',
            3128: 'Squid-Proxy'
        }
        
        for conn in connections:
            if conn['status'] == 'ESTABLISHED':
                local_port = int(conn['local_address'].split(':')[1]) if ':' in conn['local_address'] else 0
                remote_port = int(conn['remote_address'].split(':')[1]) if ':' in conn['remote_address'] else 0
                
                # Check if it's using an encrypted port
                if local_port in encrypted_ports or remote_port in encrypted_ports:
                    encrypted_conn = conn.copy()
                    encrypted_conn['encryption_type'] = encrypted_ports.get(local_port) or encrypted_ports.get(remote_port)
                    encrypted_conn['direction'] = 'Outbound' if remote_port in encrypted_ports else 'Inbound'
                    
                    # Simulate threat analysis for demo purposes
                    if self.model:
                        # Create synthetic features for demo
                        features = {
                            'packet_count': np.random.poisson(50) + 10,
                            'avg_pkt_size': np.random.normal(800, 200),
                            'entropy': np.random.beta(2, 5) * 8,
                            'tls_version': 1.3,
                            'cipher_rank': np.random.randint(20, 50),
                            'interarrival_mean': np.random.exponential(0.05),
                            'sni_entropy': np.random.beta(2, 6) * 8,
                            'session_resumption': np.random.choice([0, 1])
                        }
                        
                        # Make prediction
                        try:
                            feature_names = ["packet_count", "avg_pkt_size", "entropy", "tls_version", 
                                           "cipher_rank", "interarrival_mean", "sni_entropy", "session_resumption"]
                            
                            x_raw = [features.get(f, 0.0) for f in feature_names]
                            Xs = self.model['scaler'].transform([x_raw])[0]
                            
                            coef = np.array(self.model['coef'])
                            intercept = float(self.model['intercept'])
                            logit = Xs.dot(coef) + intercept
                            probability = 1 / (1 + np.exp(-logit))
                            
                            # Calculate feature contributions
                            contributions = Xs * coef
                            # Ensure JSON-serializable primitives
                            feature_contributions = [(name, float(val)) for name, val in zip(feature_names, contributions)]
                            feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
                            
                            # Cast features to primitives as well
                            serializable_features = {k: float(v) if isinstance(v, (np.floating, np.integer)) else float(v) if isinstance(v, (int, float)) else v for k, v in features.items()}

                            encrypted_conn['threat_analysis'] = {
                                'probability': float(probability),
                                'risk_level': 'HIGH' if probability > 0.7 else 'MEDIUM' if probability > 0.5 else 'LOW',
                                'top_contributors': feature_contributions[:3],
                                'features': serializable_features
                            }
                            
                            # Count threats
                            if probability > 0.5:
                                self.stats['threats_detected'] += 1
                                self.threat_alerts.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'threat_level': 'HIGH' if probability > 0.7 else 'MEDIUM',
                                    'flow_id': f"{conn['local_address']}->{conn['remote_address']}",
                                    'probability': float(probability),
                                    'top_contributors': feature_contributions[:3],
                                    'description': f"Suspicious {encrypted_conn['encryption_type']} connection"
                                })
                            
                            self.stats['analyzed_flows'] += 1
                            
                        except Exception as e:
                            print(f"Analysis error: {e}")
                    
                    encrypted_connections.append(encrypted_conn)
        
        return encrypted_connections
    
    def generate_network_stats(self):
        """Generate comprehensive network statistics"""
        interfaces = self.get_network_interfaces()
        connections = self.get_active_connections()
        encrypted_traffic = self.analyze_encrypted_traffic(connections)
        network_io = self.get_network_stats()
        
        stats = NetworkStats(
            timestamp=datetime.now().isoformat(),
            interfaces=interfaces,
            connections=connections,
            encrypted_traffic=encrypted_traffic,
            network_io=network_io,
            threats_detected=self.stats['threats_detected'],
            total_flows_analyzed=self.stats['analyzed_flows']
        )
        
        return stats
    
    async def monitoring_loop(self):
        """Main monitoring loop that sends updates to connected clients"""
        while self.is_monitoring:
            try:
                if self.active_connections:
                    # Generate network stats
                    network_stats = self.generate_network_stats()
                    
                    # Send to all connected clients
                    disconnected = []
                    for client_id, websocket in self.active_connections.items():
                        try:
                            # Pydantic v2 uses model_dump; v1 uses dict
                            try:
                                payload = network_stats.model_dump()  # type: ignore[attr-defined]
                            except Exception:
                                payload = network_stats.dict()  # type: ignore[attr-defined]
                            await websocket.send_json({"type": "network_stats", "data": payload})
                        except:
                            disconnected.append(client_id)
                    
                    # Remove disconnected clients
                    for client_id in disconnected:
                        del self.active_connections[client_id]
                    
                    # Send threat alerts if any
                    if self.threat_alerts:
                        for alert in self.threat_alerts[-5:]:  # Send last 5 alerts
                            for client_id, websocket in self.active_connections.items():
                                try:
                                    await websocket.send_json({
                                        "type": "threat_alert",
                                        "data": alert
                                    })
                                except:
                                    pass
                        
                        # Keep only last 10 alerts
                        self.threat_alerts = self.threat_alerts[-10:]
                
                await asyncio.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    def start_monitoring(self):
        """Start the monitoring service on the current asyncio loop"""
        if not self.is_monitoring:
            self.is_monitoring = True
            # Schedule on the running loop so websocket sends work
            try:
                loop = asyncio.get_running_loop()
                self.monitoring_task = loop.create_task(self.monitoring_loop())
            except RuntimeError:
                # Fallback if called outside a running loop
                self.monitoring_task = asyncio.create_task(self.monitoring_loop())
            print("🚀 Network monitoring service started")
    
    def stop_monitoring(self):
        """Stop the monitoring service"""
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            self.monitoring_task = None
        print("🛑 Network monitoring service stopped")
    
    async def connect_websocket(self, websocket: WebSocket, client_id: str):
        """Connect a new WebSocket client"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"📱 Client {client_id} connected to network monitoring")
        
        # Send initial data
        try:
            network_stats = self.generate_network_stats()
            try:
                payload = network_stats.model_dump()  # type: ignore[attr-defined]
            except Exception:
                payload = network_stats.dict()  # type: ignore[attr-defined]
            await websocket.send_json({"type": "network_stats", "data": payload})
        except Exception as e:
            print(f"Error sending initial data: {e}")
    
    def disconnect_websocket(self, client_id: str):
        """Disconnect a WebSocket client"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            print(f"📱 Client {client_id} disconnected from network monitoring")

# Global monitor service instance
monitor_service = NetworkMonitorService()

# Create FastAPI app
app = FastAPI(title="NET-PATROL-X Network Monitor API", version="1.0.0")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Start the network monitoring service"""
    # Ensure we start after the loop is running
    monitor_service.start_monitoring()

@app.on_event("shutdown")
async def shutdown_event():
    """Stop the network monitoring service"""
    monitor_service.stop_monitoring()

@app.websocket("/ws/network-monitor/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time network monitoring"""
    await monitor_service.connect_websocket(websocket, client_id)
    
    try:
        while True:
            # Keep-alive ping every 10s (client ignores content)
            await asyncio.sleep(10)
            try:
                await websocket.send_json({"type": "ping", "ts": datetime.now().isoformat()})
            except Exception:
                break
    except WebSocketDisconnect:
        monitor_service.disconnect_websocket(client_id)

@app.get("/api/network/stats")
async def get_network_stats():
    """Get current network statistics"""
    return monitor_service.generate_network_stats()

@app.get("/api/network/threats")
async def get_threat_alerts():
    """Get recent threat alerts"""
    return {"alerts": monitor_service.threat_alerts[-10:]}

@app.get("/api/network/summary")
async def get_network_summary():
    """Get network monitoring summary"""
    runtime = time.time() - monitor_service.stats['start_time']
    return {
        "monitoring_active": monitor_service.is_monitoring,
        "runtime_seconds": runtime,
        "total_threats_detected": monitor_service.stats['threats_detected'],
        "total_flows_analyzed": monitor_service.stats['analyzed_flows'],
        "connected_clients": len(monitor_service.active_connections),
        "model_loaded": monitor_service.model is not None
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "monitoring_active": monitor_service.is_monitoring,
        "model_loaded": monitor_service.model is not None
    }

# -----------------------------
# Simulation & Debug Endpoints
# -----------------------------
@app.post("/api/simulate/threat")
async def simulate_threat(level: str = "HIGH", probability: float = 0.85,
                          local: str = "10.0.0.5:52344", remote: str = "93.184.216.34:443",
                          description: str = "Simulated suspicious HTTPS connection"):
    """Create and broadcast a synthetic threat alert for demo/testing.

    - level: HIGH | MEDIUM | LOW
    - probability: 0..1 probability to display
    - local/remote: endpoints to show in the flow_id
    """
    level = level.upper()
    if level not in {"HIGH", "MEDIUM", "LOW"}:
        raise HTTPException(status_code=400, detail="level must be HIGH, MEDIUM, or LOW")

    alert = {
        'timestamp': datetime.now().isoformat(),
        'threat_level': level,
        'flow_id': f"{local}->{remote}",
        'probability': float(max(0.0, min(1.0, probability))),
        'top_contributors': [["cipher_rank", 1.2], ["sni_entropy", 0.9], ["interarrival_mean", 0.6]],
        'description': description
    }

    # Save and bump counters
    monitor_service.threat_alerts.append(alert)
    monitor_service.threat_alerts = monitor_service.threat_alerts[-10:]
    monitor_service.stats['threats_detected'] += 1
    monitor_service.stats['analyzed_flows'] += 1

    # Broadcast to connected websocket clients
    disconnected = []
    for client_id, websocket in monitor_service.active_connections.items():
        try:
            await websocket.send_json({"type": "threat_alert", "data": alert})
        except Exception:
            disconnected.append(client_id)
    for cid in disconnected:
        monitor_service.active_connections.pop(cid, None)

    return {"ok": True, "alert": alert, "connected_clients": len(monitor_service.active_connections)}

@app.post("/api/simulate/https-burst")
async def simulate_https_burst(count: int = 20, host: str = "https://example.com"):
    """Generate a burst of HTTPS requests (best-effort) to create encrypted traffic entries.
    This is lightweight and best-effort; it won't block the server.
    """
    try:
        # Fire-and-forget subprocesses to create outbound HTTPS traffic
        for _ in range(max(1, min(count, 200))):
            subprocess.Popen(["curl", "-s", "-o", "/dev/null", host])
        return {"ok": True, "requested": count, "host": host}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/network/resolve-threat")
async def resolve_threat(request: dict):
    """Log threat resolution attempt"""
    try:
        flow_id = request.get('flow_id')
        resolution_applied = request.get('resolution_applied')
        timestamp = request.get('timestamp')
        
        print(f"🛠️ Threat Resolution Logged:")
        print(f"   Flow: {flow_id}")
        print(f"   Resolution: {resolution_applied}")
        print(f"   Time: {timestamp}")
        
        return {
            "ok": True,
            "message": "Threat resolution logged successfully",
            "flow_id": flow_id,
            "timestamp": timestamp
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to log resolution: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)

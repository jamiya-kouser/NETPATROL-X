import React, { useState, useEffect, useRef } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import './NetPatrolXDemo.css';

const NetworkMonitor = () => {
  const [networkStats, setNetworkStats] = useState(null);
  const [threatAlerts, setThreatAlerts] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [monitoringSummary, setMonitoringSummary] = useState(null);
  const wsRef = useRef(null);
  const clientId = useRef(`client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);

  // Colors for charts
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  useEffect(() => {
    connectWebSocket();
    fetchInitialData();

    // REST polling fallback every 3s if no websocket data yet
    const poller = setInterval(async () => {
      try {
        const res = await fetch(`http://127.0.0.1:8001/api/network/stats`);
        if (res.ok) {
          const data = await res.json();
          if (data && !networkStats) {
            setNetworkStats(data);
          }
        }
      } catch (_) {}
    }, 3000);

    return () => {
      clearInterval(poller);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    const host = window.location.hostname || '127.0.0.1';
    const ws = new WebSocket(`ws://${host}:8001/ws/network-monitor/${clientId.current}`);
    
    ws.onopen = () => {
      console.log('🔗 Connected to network monitoring service');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'network_stats') {
          setNetworkStats(message.data);
        } else if (message.type === 'threat_alert') {
          setThreatAlerts(prev => [message.data, ...prev.slice(0, 9)]);
        }
      } catch (_) {}
    };

    ws.onclose = () => {
      console.log('🔌 Disconnected from network monitoring service');
      setIsConnected(false);
      
      // Attempt to reconnect after 3 seconds
      setTimeout(() => {
        connectWebSocket();
      }, 3000);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    };

    wsRef.current = ws;
  };

  const fetchInitialData = async () => {
    try {
      // Fetch monitoring summary
      const summaryResponse = await fetch('http://127.0.0.1:8001/api/network/summary');
      const summary = await summaryResponse.json();
      setMonitoringSummary(summary);

      // Fetch recent threat alerts
      const threatsResponse = await fetch('http://127.0.0.1:8001/api/network/threats');
      const threatsData = await threatsResponse.json();
      setThreatAlerts(threatsData.alerts || []);
    } catch (error) {
      console.error('Error fetching initial data:', error);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case 'HIGH': return '#e74c3c';
      case 'MEDIUM': return '#f39c12';
      case 'LOW': return '#27ae60';
      default: return '#95a5a6';
    }
  };

  const getThreatLevelIcon = (level) => {
    switch (level) {
      case 'HIGH': return '🚨';
      case 'MEDIUM': return '⚠️';
      case 'LOW': return '✅';
      default: return 'ℹ️';
    }
  };

  const getThreatDetails = (alert) => {
    const flow = alert.flow_id;
    const contributors = alert.top_contributors;
    
    // Extract IP and port information
    const [local, remote] = flow.split('->');
    const [remoteIP, remotePort] = remote.split(':');
    
    // Determine the target service based on IP and port
    let targetService = "Unknown Service";
    let serviceDescription = "Unknown application";
    let resolutionSteps = [];
    
    // Google Services
    if (remoteIP === '142.250.205.78' || remoteIP.startsWith('142.250.')) {
      targetService = "Google Services";
      serviceDescription = "Google's infrastructure (Gmail, Drive, YouTube, Search, etc.)";
      resolutionSteps = [
        "1. Verify this is legitimate Google service usage",
        "2. Check if you're using Google Workspace or personal Google account",
        "3. Update your browser to the latest version",
        "4. Clear browser cache and cookies",
        "5. Check Google Account security settings",
        "6. Review recent Google account activity"
      ];
    }
    // AWS Services
    else if (remoteIP === '34.231.206.163' || remoteIP.startsWith('34.') || remoteIP.startsWith('52.')) {
      targetService = "Amazon Web Services (AWS)";
      serviceDescription = "AWS cloud infrastructure (EC2, S3, Lambda, etc.)";
      resolutionSteps = [
        "1. Check AWS Console for recent activity",
        "2. Review AWS CloudTrail logs for unauthorized access",
        "3. Verify AWS IAM permissions and access keys",
        "4. Check for unexpected AWS service usage",
        "5. Review AWS billing for unusual charges",
        "6. Rotate AWS access keys if suspicious"
      ];
    }
    // Microsoft Services
    else if (remoteIP.startsWith('20.') || remoteIP.startsWith('40.')) {
      targetService = "Microsoft Services";
      serviceDescription = "Microsoft cloud services (Office 365, Azure, etc.)";
      resolutionSteps = [
        "1. Check Microsoft 365 admin center",
        "2. Review Azure Active Directory logs",
        "3. Verify Office 365 usage and permissions",
        "4. Check for suspicious Microsoft account activity",
        "5. Review Azure resource access logs"
      ];
    }
    // Generic HTTPS services
    else if (remotePort === '443') {
      targetService = "HTTPS Service";
      serviceDescription = "Encrypted web service (unknown provider)";
      resolutionSteps = [
        "1. Identify the specific service/website being accessed",
        "2. Check if this is legitimate business usage",
        "3. Verify SSL certificate validity",
        "4. Update browser and security software",
        "5. Monitor for unusual traffic patterns"
      ];
    }
    
    // Analyze threat contributors for specific technical fixes
    const technicalFixes = [];
    contributors.forEach(([feature, value]) => {
      switch (feature) {
        case 'cipher_rank':
          technicalFixes.push({
            issue: "Weak encryption cipher detected",
            fix: "Update to TLS 1.3 with AES-256 encryption",
            impact: "High - Security vulnerability"
          });
          break;
        case 'packet_count':
          technicalFixes.push({
            issue: "Unusual packet volume patterns",
            fix: "Monitor traffic patterns and investigate data exfiltration",
            impact: "Medium - Potential data breach"
          });
          break;
        case 'sni_entropy':
          technicalFixes.push({
            issue: "Suspicious Server Name Indication patterns",
            fix: "Check for domain fronting or suspicious SNI values",
            impact: "High - Possible DNS hijacking"
          });
          break;
        case 'interarrival_mean':
          technicalFixes.push({
            issue: "Unusual timing patterns detected",
            fix: "Investigate for timing-based attacks or covert channels",
            impact: "Medium - Covert communication"
          });
          break;
      }
    });
    
    return {
      targetService,
      serviceDescription,
      remoteIP,
      remotePort,
      resolutionSteps,
      technicalFixes
    };
  };


  if (!networkStats) {
    return (
      <div className="network-monitor-container">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <h3>Connecting to Network Monitor...</h3>
          <p>Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="network-monitor-container">
      <div className="monitor-header">
        <h1>🌐 NET-PATROL-X Real-Time Network Monitor</h1>
        <div className="connection-status">
          <span className={`status-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
            {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
          </span>
          {monitoringSummary && (
            <span className="monitoring-info">
              Runtime: {Math.floor(monitoringSummary.runtime_seconds / 60)}m {Math.floor(monitoringSummary.runtime_seconds % 60)}s
            </span>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="summary-cards">
        <div className="summary-card">
          <h3>🛡️ Security Status</h3>
          <div className="card-content">
            <div className="metric">
              <span className="metric-value">{networkStats.threats_detected}</span>
              <span className="metric-label">Threats Detected</span>
            </div>
            <div className="metric">
              <span className="metric-value">{networkStats.total_flows_analyzed}</span>
              <span className="metric-label">Flows Analyzed</span>
            </div>
          </div>
        </div>

        <div className="summary-card">
          <h3>🔗 Network Activity</h3>
          <div className="card-content">
            <div className="metric">
              <span className="metric-value">{Object.keys(networkStats.interfaces).length}</span>
              <span className="metric-label">Interfaces</span>
            </div>
            <div className="metric">
              <span className="metric-value">{networkStats.connections.length}</span>
              <span className="metric-label">Active Connections</span>
            </div>
          </div>
        </div>

        <div className="summary-card">
          <h3>🔒 Encrypted Traffic</h3>
          <div className="card-content">
            <div className="metric">
              <span className="metric-value">{networkStats.encrypted_traffic.length}</span>
              <span className="metric-label">Encrypted Connections</span>
            </div>
            <div className="metric">
              <span className="metric-value">
                {networkStats.encrypted_traffic.filter(conn => 
                  conn.threat_analysis && conn.threat_analysis.risk_level === 'HIGH'
                ).length}
              </span>
              <span className="metric-label">High Risk</span>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Alerts */}
      {threatAlerts.length > 0 && (
        <div className="threat-alerts-section">
          <h3>🚨 Recent Threat Alerts</h3>
          <div className="alerts-container">
            {threatAlerts.slice(0, 5).map((alert, index) => (
              <div key={index} className={`alert-item ${alert.threat_level.toLowerCase()}`}>
                <div className="alert-header">
                  <span className="alert-icon">{getThreatLevelIcon(alert.threat_level)}</span>
                  <span className="alert-level">{alert.threat_level} THREAT</span>
                  <span className="alert-time">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="alert-content">
                  <p><strong>Flow:</strong> {alert.flow_id}</p>
                  <p><strong>Probability:</strong> {(alert.probability * 100).toFixed(1)}%</p>
                  <p><strong>Description:</strong> {alert.description}</p>
                  
                  {(() => {
                    const threatDetails = getThreatDetails(alert);
                    
                    return (
                      <div className="threat-details">
                        <div className="service-info">
                          <h4>🎯 Target Service</h4>
                          <p><strong>Service:</strong> {threatDetails.targetService}</p>
                          <p><strong>Description:</strong> {threatDetails.serviceDescription}</p>
                          <p><strong>Remote IP:</strong> {threatDetails.remoteIP}</p>
                          <p><strong>Port:</strong> {threatDetails.remotePort}</p>
                        </div>
                        
                        <div className="resolution-steps">
                          <h4>🛠️ How to Fix This Issue</h4>
                          <ol>
                            {threatDetails.resolutionSteps.map((step, idx) => (
                              <li key={idx}>{step}</li>
                            ))}
                          </ol>
                        </div>
                        
                        <div className="technical-fixes">
                          <h4>🔧 Technical Issues Detected</h4>
                          {threatDetails.technicalFixes.map((fix, idx) => (
                            <div key={idx} className="technical-fix-item">
                              <p><strong>Issue:</strong> {fix.issue}</p>
                              <p><strong>Fix:</strong> {fix.fix}</p>
                              <p><strong>Impact:</strong> <span className={`impact-${fix.impact.split(' - ')[0].toLowerCase()}`}>{fix.impact}</span></p>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                  
                  <div className="contributors">
                    <strong>Top Contributors:</strong>
                    {alert.top_contributors.map((contributor, idx) => (
                      <span key={idx} className="contributor">
                        {contributor[0]} ({contributor[1].toFixed(3)})
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Network Interfaces */}
      <div className="interfaces-section">
        <h3>📡 Network Interfaces</h3>
        <div className="interfaces-grid">
          {Object.entries(networkStats.interfaces).map(([name, info]) => (
            <div key={name} className="interface-card">
              <div className="interface-header">
                <span className="interface-name">{name}</span>
                <span className={`interface-status ${info.is_up ? 'up' : 'down'}`}>
                  {info.is_up ? '🟢 UP' : '🔴 DOWN'}
                </span>
              </div>
              <div className="interface-details">
                <p><strong>Speed:</strong> {info.speed}</p>
                <p><strong>MTU:</strong> {info.mtu}</p>
                {info.addresses.map((addr, idx) => (
                  addr.family === 'AddressFamily.AF_INET' && addr.address !== '127.0.0.1' && (
                    <p key={idx}><strong>IP:</strong> {addr.address}/{addr.netmask}</p>
                  )
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Network I/O Statistics */}
      <div className="network-io-section">
        <h3>📊 Network I/O Statistics</h3>
        <div className="io-charts">
          <div className="chart-container">
            <h4>Data Transfer (Bytes)</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={Object.entries(networkStats.network_io).map(([iface, stats]) => ({
                interface: iface,
                sent: stats.bytes_sent,
                received: stats.bytes_recv
              }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="interface" />
                <YAxis />
                <Tooltip formatter={(value) => formatBytes(value)} />
                <Bar dataKey="sent" fill="#e74c3c" name="Sent" />
                <Bar dataKey="received" fill="#27ae60" name="Received" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-container">
            <h4>Packet Statistics</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={Object.entries(networkStats.network_io).map(([iface, stats]) => ({
                interface: iface,
                sent: stats.packets_sent,
                received: stats.packets_recv
              }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="interface" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="sent" fill="#3498db" name="Packets Sent" />
                <Bar dataKey="received" fill="#9b59b6" name="Packets Received" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Encrypted Traffic Analysis */}
      {networkStats.encrypted_traffic.length > 0 && (
        <div className="encrypted-traffic-section">
          <h3>🔒 Encrypted Traffic Analysis</h3>
          <div className="encrypted-flows">
            {networkStats.encrypted_traffic.map((flow, index) => (
              <div key={index} className="flow-card">
                <div className="flow-header">
                  <span className="flow-type">{flow.encryption_type}</span>
                  <span className="flow-direction">{flow.direction}</span>
                  {flow.threat_analysis && (
                    <span 
                      className={`risk-badge ${flow.threat_analysis.risk_level.toLowerCase()}`}
                    >
                      {flow.threat_analysis.risk_level} RISK
                    </span>
                  )}
                </div>
                <div className="flow-details">
                  <p><strong>Connection:</strong> {flow.local_address} ↔ {flow.remote_address}</p>
                  <p><strong>Process:</strong> {flow.process_name || 'Unknown'}</p>
                  {flow.threat_analysis && (
                    <>
                      <p><strong>Threat Probability:</strong> {(flow.threat_analysis.probability * 100).toFixed(1)}%</p>
                      <div className="contributors">
                        <strong>Top Contributors:</strong>
                        {flow.threat_analysis.top_contributors.map((contributor, idx) => (
                          <span key={idx} className="contributor">
                            {contributor[0]} ({contributor[1].toFixed(3)})
                          </span>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Connections */}
      <div className="connections-section">
        <h3>🔗 Active Connections</h3>
        <div className="connections-table">
          <table>
            <thead>
              <tr>
                <th>Local Address</th>
                <th>Remote Address</th>
                <th>Status</th>
                <th>Process</th>
              </tr>
            </thead>
            <tbody>
              {networkStats.connections.slice(0, 20).map((conn, index) => (
                <tr key={index}>
                  <td>{conn.local_address}</td>
                  <td>{conn.remote_address}</td>
                  <td><span className={`status-badge ${conn.status.toLowerCase()}`}>{conn.status}</span></td>
                  <td>{conn.process_name || 'Unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default NetworkMonitor;

import React, { useState } from "react";
import NetPatrolXDemo from "./NetPatrolXDemo";
import NetworkMonitor from "./NetworkMonitor";

function App() {
  const [activeTab, setActiveTab] = useState("predictions");

  return (
    <div className="app-container">
      <nav className="app-nav">
        <div className="nav-brand">
          <h2>🛡️ NET-PATROL-X</h2>
        </div>
        <div className="nav-tabs">
          <button 
            className={`nav-tab ${activeTab === "predictions" ? "active" : ""}`}
            onClick={() => setActiveTab("predictions")}
          >
            🔍 Traffic Analysis
          </button>
          <button 
            className={`nav-tab ${activeTab === "monitor" ? "active" : ""}`}
            onClick={() => setActiveTab("monitor")}
          >
            🌐 Network Monitor
          </button>
        </div>
      </nav>
      
      <main className="app-main">
        {activeTab === "predictions" && <NetPatrolXDemo />}
        {activeTab === "monitor" && <NetworkMonitor />}
      </main>
    </div>
  );
}

export default App;

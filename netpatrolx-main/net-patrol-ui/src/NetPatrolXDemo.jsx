import React, { useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from "recharts";
import "./NetPatrolXDemo.css";

/**
 * NetPatrolXDemo - Frontend that calls a FastAPI backend
 * - Single prediction: POST /predict { data: {feature: value ...} }
 * - Batch prediction: POST /predict_batch (file form field "file")
 *
 * Ensure backend is running at http://localhost:8000
 */

const BACKEND_BASE = "http://127.0.0.1:8000";

export default function NetPatrolXDemo() {
  const defaultFeatures = [
    "packet_count",
    "avg_pkt_size",
    "entropy",
    "tls_version",
    "cipher_rank",
    "interarrival_mean",
    "sni_entropy",
    "session_resumption",
  ];

  const [flowsFile, setFlowsFile] = useState(null); // File object for CSV
  const [manualInput, setManualInput] = useState({});
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  // handle picking a CSV file (stored until batch run)
  function handleCSVPick(e) {
    const f = e.target.files?.[0];
    setFlowsFile(f ?? null);
  }

  // Convert manualInput values into a numeric dict for predict
  function buildManualRow() {
    const row = {};
    defaultFeatures.forEach((f) => {
      const v = manualInput[f];
      if (v === undefined || v === "") row[f] = 0;
      else {
        // try number
        const n = Number(v);
        row[f] = Number.isNaN(n) ? v : n;
      }
    });
    return row;
  }

  async function runManual() {
    const row = buildManualRow();
    setLoading(true);
    try {
      const resp = await fetch(`${BACKEND_BASE}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: row }),
      });
      const j = await resp.json();
      // j: { probability, top_contributors, contributions }
      const alertText = j.probability > 0.7 ? `🚨 Suspicious (p=${j.probability.toFixed(2)})` : (j.probability > 0.5 ? `⚠️ Potentially risky (p=${j.probability.toFixed(2)})` : `✅ Benign (p=${j.probability.toFixed(2)})`);
      setResults([{ index: 0, ...row, probability: j.probability, alert: alertText, top: j.top_contributors }]);
    } catch (err) {
      console.error(err);
      alert("Prediction failed: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  async function runBatch() {
    if (!flowsFile) return alert("Select a CSV file first.");
    const fd = new FormData();
    fd.append("file", flowsFile);
    setLoading(true);
    try {
      const resp = await fetch(`${BACKEND_BASE}/predict_batch`, { method: "POST", body: fd });
      const j = await resp.json();
      // j: { results: [ { probability, top_contributors }, ... ] }
      // We need original CSV rows to display index + optional fields. We'll parse CSV lightly for headers -> rows
      const csvText = await flowsFile.text();
      const lines = csvText.split(/\r?\n/).filter((l) => l.trim() !== "");
      const headers = lines[0].split(",").map((h) => h.trim());
      const rows = lines.slice(1).map((line) => {
        const parts = line.split(",");
        const obj = {};
        headers.forEach((h, i) => {
          const v = parts[i] ?? "";
          obj[h] = isNaN(Number(v)) ? v : Number(v);
        });
        return obj;
      });

      const merged = rows.map((r, i) => {
        const pred = j.results[i] ?? {};
        const prob = pred.probability ?? null;
        const top = pred.top_contributors ?? [];
        const alertText = prob === null ? "no result" : (prob > 0.7 ? `🚨 Suspicious (p=${prob.toFixed(2)})` : (prob > 0.5 ? `⚠️ Potentially risky (p=${prob.toFixed(2)})` : `✅ Benign (p=${prob.toFixed(2)})`));
        return { index: i, ...r, probability: prob, alert: alertText, top };
      });
      setResults(merged);
    } catch (err) {
      console.error(err);
      alert("Batch prediction failed: " + err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="net-patrol-container">
      <h1 className="main-title">NET-PATROL-X — Encrypted Traffic Analysis</h1>

      <div className="input-sections">
        <div className="manual-section">
          <h3>Manual Input</h3>
          <div className="feature-grid">
            {defaultFeatures.map((f) => (
              <div key={f} className="feature-input">
                <label className="feature-label">{f}</label>
                <input
                  className="feature-field"
                  type="number"
                  step="any"
                  placeholder="Enter value"
                  value={manualInput[f] ?? ""}
                  onChange={(e) => setManualInput({ ...manualInput, [f]: e.target.value })}
                />
              </div>
            ))}
          </div>
          <div className="button-container">
            <button 
              className="predict-button"
              onClick={runManual} 
              disabled={loading}
            >
              {loading ? "Running..." : "Run Manual Prediction"}
            </button>
          </div>
        </div>

        <div className="batch-section">
          <h3>Batch CSV Upload</h3>
          <p className="csv-instructions">
            CSV header must match model features (packet_count, avg_pkt_size, entropy, tls_version, cipher_rank, interarrival_mean, sni_entropy, session_resumption)
          </p>
          <div className="file-input-container">
            <input 
              type="file" 
              accept=".csv,text/csv" 
              onChange={handleCSVPick}
              className="file-input"
            />
          </div>
          <div className="button-container">
            <button 
              className="predict-button batch-button"
              onClick={runBatch} 
              disabled={loading || !flowsFile}
            >
              {loading ? "Running Batch..." : "Run Batch Prediction"} 
            </button>
          </div>
        </div>
      </div>

      <div className="results-section">
        <h3>Results</h3>
        {results.length === 0 ? (
          <div className="no-results">No results yet. Run a prediction to see results here.</div>
        ) : (
          <>
            <div className="results-summary">
              <ul className="results-list">
                {results.slice(0, 20).map((r) => (
                  <li key={r.index} className="result-item">
                    <strong>Flow #{r.index}</strong>: {r.alert}
                    {r.top && r.top.length > 0 && (
                      <span className="top-features">
                        — Top contributors: {r.top.map(t => `${t[0]}(${t[1].toFixed(3)})`).join(", ")}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>

            <div className="chart-container">
              <h4>Prediction Probability Chart</h4>
              <ResponsiveContainer width="100%" height={240}>
                <LineChart data={results.map((r, i) => ({ name: i, p: r.probability ?? 0 }))}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" label={{ value: 'Flow Index', position: 'insideBottom', offset: -5 }} />
                  <YAxis domain={[0, 1]} label={{ value: 'Malicious Probability', angle: -90, position: 'insideLeft' }} />
                  <Tooltip formatter={(value) => [`${(value * 100).toFixed(1)}%`, 'Malicious Probability']} />
                  <Line type="monotone" dataKey="p" stroke="#e74c3c" strokeWidth={2} dot={{ fill: '#e74c3c', strokeWidth: 2, r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="results-table-container">
              <h4>Detailed Results</h4>
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Flow #</th>
                    <th>Probability</th>
                    <th>Alert</th>
                    <th>Top Contributors</th>
                  </tr>
                </thead>
                <tbody>
                  {results.slice(0, 50).map((r) => (
                    <tr key={r.index}>
                      <td>{r.index}</td>
                      <td className="probability-cell">
                        {r.probability !== null ? (
                          <span className={`probability-badge ${r.probability > 0.7 ? 'high-risk' : r.probability > 0.5 ? 'medium-risk' : 'low-risk'}`}>
                            {(r.probability * 100).toFixed(1)}%
                          </span>
                        ) : "—"}
                      </td>
                      <td>{r.alert}</td>
                      <td className="contributors-cell">
                        {Array.isArray(r.top) ? r.top.map(t => `${t[0]}(${t[1].toFixed(3)})`).join(", ") : JSON.stringify(r.top)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

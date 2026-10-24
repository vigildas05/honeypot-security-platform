import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { apiGet, login } from "./api/client.js";
import "./styles.css";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    try {
      const data = await login(username, password);
      localStorage.setItem("dashboardToken", data.token);
      onLogin();
    } catch {
      setError("Invalid credentials");
    }
  }

  return (
    <main className="login-screen">
      <form className="login-panel" onSubmit={handleSubmit}>
        <p className="eyebrow">Cloud Native Honeypot</p>
        <h1>Security Dashboard</h1>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error ? <p className="error">{error}</p> : null}
        <button type="submit">Login</button>
      </form>
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <section className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

function Dashboard({ onLogout }) {
  const [stats, setStats] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      const [nextStats, nextAttacks] = await Promise.all([
        apiGet("/stats"),
        apiGet("/attacks?limit=50")
      ]);
      setStats(nextStats);
      setAttacks(nextAttacks);
    } catch {
      setError("Could not load dashboard data. Check the backend and login token.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 5000);
    return () => clearInterval(timer);
  }, []);

  function logout() {
    localStorage.removeItem("dashboardToken");
    onLogout();
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Learning Lab</p>
          <h1>Honeypot Security Platform</h1>
        </div>
        <button className="secondary" onClick={logout}>
          Logout
        </button>
      </header>

      {error ? <p className="error">{error}</p> : null}

      <section className="metrics-grid">
        <Metric label="Total Attacks" value={stats?.totalAttacks ?? 0} />
        <Metric label="Attacks Today" value={stats?.attacksToday ?? 0} />
        <Metric label="Active Honeypots" value={stats?.activeHoneypots ?? 0} />
        <Metric label="Services" value={stats?.services?.length ?? 0} />
      </section>

      <section className="dashboard-grid">
        <div className="panel">
          <h2>Service Distribution</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={stats?.services ?? []}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="service" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#2563eb" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <h2>Top Passwords</h2>
          <ul className="rank-list">
            {(stats?.topPasswords ?? []).map((item) => (
              <li key={item.password}>
                <span>{item.password}</span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="panel">
        <h2>Live Feed</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Service</th>
                <th>IP</th>
                <th>Country</th>
                <th>Username</th>
                <th>Password</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map((attack) => (
                <tr key={attack.id}>
                  <td>{new Date(attack.timestamp).toLocaleTimeString()}</td>
                  <td>{attack.service}</td>
                  <td>{attack.ip}</td>
                  <td>{attack.country}</td>
                  <td>{attack.username ?? "-"}</td>
                  <td>{attack.password ?? "-"}</td>
                  <td>{attack.path ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState(
    Boolean(localStorage.getItem("dashboardToken"))
  );

  return authenticated ? (
    <Dashboard onLogout={() => setAuthenticated(false)} />
  ) : (
    <Login onLogin={() => setAuthenticated(true)} />
  );
}

createRoot(document.getElementById("root")).render(<App />);

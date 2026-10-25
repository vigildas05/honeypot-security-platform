import { useState } from "react";
import { login } from "../api/client.js";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  /** @param {import("react").FormEvent} event */
  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await login(username, password);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-screen">
      <form className="login-panel" onSubmit={handleSubmit}>
        <p className="eyebrow">Cloud Native Honeypot</p>
        <h1>Security Dashboard</h1>
        <label>
          Username
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error ? <p className="error">{error}</p> : null}
        <button type="submit" disabled={busy}>Login</button>
      </form>
    </main>
  );
}

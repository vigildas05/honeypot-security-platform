import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet } from "../api/client.js";
import { useApi } from "../api/useApi.js";
import { ErrorBox, RankList, Stat, Untrusted } from "../components/ui.jsx";

// The original dashboard (stats, service mix, top passwords, live feed).
export function Overview() {
  const { data, error } = useApi(
    () => Promise.all([apiGet("/stats"), apiGet("/attacks", { limit: 50 })]),
    [],
    { pollMs: 5000 }
  );
  const [stats, attacks] = data ?? [null, []];

  return (
    <>
      <ErrorBox message={error ? "Could not load dashboard data. Check the backend and your login." : ""} />
      <section className="metrics-grid">
        <Stat label="Total events" value={stats?.totalAttacks ?? 0} />
        <Stat label="Events today" value={stats?.attacksToday ?? 0} />
        <Stat label="Active honeypots" value={stats?.activeHoneypots ?? 0} />
        <Stat label="Services" value={stats?.services?.length ?? 0} />
      </section>

      <section className="dashboard-grid">
        <div className="panel">
          <h2>Service distribution</h2>
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
          <h2>Top passwords</h2>
          <RankList items={(stats?.topPasswords ?? []).map((/** @type {any} */ p) => ({ value: p.password, count: p.count }))} />
        </div>
      </section>

      <section className="panel">
        <h2>Live feed</h2>
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
                <th>Command / path</th>
              </tr>
            </thead>
            <tbody>
              {(attacks ?? []).map((/** @type {any} */ a) => (
                <tr key={a.id}>
                  <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td>{a.service}</td>
                  <td><code className="ip">{a.ip}</code></td>
                  <td>{a.country ?? "-"}</td>
                  <td><Untrusted value={a.username} max={40} /></td>
                  <td><Untrusted value={a.password} max={40} /></td>
                  <td><Untrusted value={a.command ?? a.path} max={80} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

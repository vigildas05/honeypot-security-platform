import { NavLink, Outlet } from "react-router-dom";
import { clearSession, getSession } from "../api/client.js";

export function Layout() {
  const session = getSession();
  const isAdmin = session?.role === "admin";
  const links = [
    ["/", "Overview"],
    ["/incidents", "Incidents"],
    ["/approvals", "Approvals"],
    ["/blocklist", "Blocklist"],
    ["/metrics", "Metrics"],
    ...(isAdmin ? [["/audit", "Audit log"]] : [])
  ];

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Honeypot SOC</p>
          <h1>Honeypot Security Platform</h1>
        </div>
        <div className="session">
          <span className={`badge ${isAdmin ? "role-admin" : "role-demo"}`}>
            {session?.username} · {isAdmin ? "admin" : "read-only demo"}
          </span>
          <button className="secondary" onClick={clearSession}>
            Logout
          </button>
        </div>
      </header>
      <nav className="tabs" aria-label="Main">
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : undefined)}>
            {label}
          </NavLink>
        ))}
      </nav>
      {!isAdmin ? (
        <p className="notice">Read-only demo: IP addresses are partially masked and approval controls are disabled.</p>
      ) : null}
      <Outlet />
    </main>
  );
}

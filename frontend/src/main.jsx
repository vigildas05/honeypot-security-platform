import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { getSession } from "./api/client.js";
import { Layout } from "./components/Layout.jsx";
import { Approvals } from "./pages/Approvals.jsx";
import { Audit } from "./pages/Audit.jsx";
import { Blocklist } from "./pages/Blocklist.jsx";
import { IncidentDetail } from "./pages/IncidentDetail.jsx";
import { Incidents } from "./pages/Incidents.jsx";
import { Login } from "./pages/Login.jsx";
import { Metrics } from "./pages/Metrics.jsx";
import { Overview } from "./pages/Overview.jsx";
import "./styles.css";

export function App() {
  const [session, setSession] = useState(getSession);

  useEffect(() => {
    const sync = () => setSession(getSession());
    window.addEventListener("session-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("session-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  if (!session) return <Login />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="approvals" element={<Approvals />} />
        <Route path="blocklist" element={<Blocklist />} />
        <Route path="metrics" element={<Metrics />} />
        {session.role === "admin" ? <Route path="audit" element={<Audit />} /> : null}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <React.StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </React.StrictMode>
  );
}

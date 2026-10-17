import { FormEvent, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Vulnerabilities from "./pages/Vulnerabilities";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import ThreatIntel from "./pages/ThreatIntel";
import CloudSecurity from "./pages/CloudSecurity";
import Compliance from "./pages/Compliance";
import Settings from "./pages/Settings";

const NAV: [string, string, string?][] = [
  ["/", "Dashboard"], ["/assets", "Assets"], ["/vulnerabilities", "Vulnerabilities"], ["/alerts", "Alerts & SIEM"],
  ["/incidents", "Incidents & Response"], ["/intel", "Threat Intelligence"], ["/cloud", "Cloud Security"],
  ["/compliance", "Compliance", "view_compliance"], ["/settings", "Settings"],
];

function Login() {
  const { login } = useAuth();
  const [u, setU] = useState(""); const [p, setP] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try { await login(u, p); } catch (x: any) { setErr(x.message); } finally { setBusy(false); }
  };
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand">Cyber<span>Fusion</span></div>
        <p className="muted">Sign in to the security operations console</p>
        <label htmlFor="u">Username</label>
        <input id="u" value={u} onChange={e => setU(e.target.value)} autoComplete="username" autoFocus required />
        <label htmlFor="p">Password</label>
        <input id="p" type="password" value={p} onChange={e => setP(e.target.value)} autoComplete="current-password" required />
        {err && <div className="notice err" role="alert">{err}</div>}
        <button className="btn" style={{ width: "100%", marginTop: 14 }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}

export default function App() {
  const { me, logout, can } = useAuth();
  if (!me) return <Login />;
  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">Cyber<span>Fusion</span></div>
        <nav className="nav">
          {NAV.filter(([, , perm]) => !perm || can(perm)).map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"}>{label}</NavLink>
          ))}
        </nav>
        <div className="side-foot">
          <div><b>{me.username}</b> · {me.role.replace("_", " ")}</div>
          <button className="btn ghost sm" style={{ marginTop: 8 }} onClick={logout}>Sign out</button>
        </div>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/intel" element={<ThreatIntel />} />
          <Route path="/cloud" element={<CloudSecurity />} />
          <Route path="/compliance" element={can("view_compliance") ? <Compliance /> : <Navigate to="/" />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}

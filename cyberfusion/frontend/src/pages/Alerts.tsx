import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Page, ago, useAction, useFetch } from "../ui";

function AlertsTab() {
  const { can } = useAuth();
  const nav = useNavigate();
  const [status, setStatus] = useState("");
  const { data, error, loading, reload } = useFetch<any[]>(`/alerts${status ? `?status=${status}` : ""}`, 15000);
  const act = useAction(reload);
  return (
    <Card>
      <div className="filters">
        <select aria-label="Filter by status" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All statuses</option>{["new", "investigating", "closed"].map(s => <option key={s}>{s}</option>)}</select>
      </div>
      {act.err && <div className="notice err">{act.err}</div>}
      <Loading error={error} loading={loading} />
      {data && (data.length === 0 ? <Empty text="No alerts." /> : (
        <div className="scroll"><table>
          <thead><tr><th>Severity</th><th>Alert</th><th>Rule</th><th>Host</th><th>Status</th><th>When</th><th /></tr></thead>
          <tbody>{data.map(a => (
            <tr key={a.id}>
              <td><Badge value={a.severity} /></td>
              <td>{a.title}<div className="muted">{a.description}</div></td>
              <td className="mono">{a.rule || a.source}</td><td>{a.host}</td><td><Badge value={a.status} /></td>
              <td className="muted">{ago(a.created_at)}</td>
              <td style={{ whiteSpace: "nowrap" }}>
                {can("manage_alerts") && a.status === "new" && <button className="btn ghost sm" disabled={act.busy}
                  onClick={() => act.run(() => api(`/alerts/${a.id}`, { method: "PATCH", body: { status: "investigating" } }))}>Investigate</button>}{" "}
                {can("manage_alerts") && a.status !== "closed" && <button className="btn ghost sm" disabled={act.busy}
                  onClick={() => act.run(() => api(`/alerts/${a.id}`, { method: "PATCH", body: { status: "closed" } }))}>Close</button>}{" "}
                {can("manage_incidents") && !a.incident_id && a.status !== "closed" && <button className="btn sm" disabled={act.busy}
                  onClick={() => act.run(async () => { await api(`/alerts/${a.id}/incident`, { method: "POST" }); nav("/incidents"); })}>→ Incident</button>}
                {a.incident_id && <span className="muted">Incident #{a.incident_id}</span>}
              </td>
            </tr>))}</tbody>
        </table></div>))}
    </Card>
  );
}

function EventsTab() {
  const [q, setQ] = useState(""); const [type, setType] = useState("");
  const params = new URLSearchParams({ ...(q && { q }), ...(type && { event_type: type }) }).toString();
  const { data, error, loading } = useFetch<any[]>(`/events${params ? "?" + params : ""}`, 15000);
  return (
    <Card>
      <div className="filters">
        <input aria-label="Search events" placeholder="Search host, user, IP, message…" value={q} onChange={e => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <select aria-label="Event type" value={type} onChange={e => setType(e.target.value)}>
          <option value="">All types</option>
          {["auth_failure", "auth_success", "defender_disabled", "firewall_disabled", "audit_log_cleared"].map(t => <option key={t}>{t}</option>)}</select>
      </div>
      <Loading error={error} loading={loading} />
      {data && (data.length === 0 ? <Empty text="No events match." /> : (
        <div className="scroll"><table>
          <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Host</th><th>User</th><th>Source IP</th><th>Message</th></tr></thead>
          <tbody>{data.map(e => (
            <tr key={e.id}><td className="muted" style={{ whiteSpace: "nowrap" }}>{ago(e.timestamp)}</td><td>{e.source}</td>
              <td className="mono">{e.event_type}</td><td>{e.host}</td><td>{e.user}</td><td className="mono">{e.src_ip}</td><td>{e.message}</td></tr>))}</tbody>
        </table></div>))}
    </Card>
  );
}

function RulesTab() {
  const { data, error, loading } = useFetch<any[]>("/siem/rules");
  return (
    <Card title="Detection rules">
      <p className="muted" style={{ marginTop: 0 }}>Log source → Ingestion → Normalisation → Correlation → Detection → Alert → Incident</p>
      <Loading error={error} loading={loading} />
      {data && <table><thead><tr><th>ID</th><th>Name</th><th>Logic</th><th>Severity</th></tr></thead><tbody>
        {data.map(r => <tr key={r.id}><td className="mono">{r.id}</td><td>{r.name}</td><td>{r.logic}</td><td><Badge value={r.severity} /></td></tr>)}
      </tbody></table>}
    </Card>
  );
}

export default function Alerts() {
  const [tab, setTab] = useState<"alerts" | "events" | "rules">("alerts");
  return (
    <Page title="Alerts & SIEM" subtitle="Detections raised by correlation rules over ingested security events"
      actions={<>{(["alerts", "events", "rules"] as const).map(t =>
        <button key={t} className={`btn ${tab === t ? "" : "ghost"}`} onClick={() => setTab(t)} style={{ textTransform: "capitalize" }}>{t}</button>)}</>}>
      {tab === "alerts" && <AlertsTab />}{tab === "events" && <EventsTab />}{tab === "rules" && <RulesTab />}
    </Page>
  );
}

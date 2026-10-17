import { useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Modal, Page, ago, useAction, useFetch } from "../ui";

function AssetDetail({ id, onClose, onChange }: { id: number; onClose: () => void; onChange: () => void }) {
  const { can } = useAuth();
  const { data: a, error, loading, reload } = useFetch<any>(`/assets/${id}`);
  const act = useAction(() => { reload(); onChange(); });
  return (
    <Modal title={a ? a.hostname : "Asset"} onClose={onClose}>
      <Loading error={error} loading={loading} />
      {a && <>
        <div className="row" style={{ marginBottom: 8 }}>
          <div><span className="muted">Status</span><br /><Badge value={a.status} /></div>
          <div><span className="muted">OS</span><br />{a.os || "—"}</div>
          <div><span className="muted">IP</span><br /><span className="mono">{a.ip || "—"}</span></div>
          <div><span className="muted">Agent</span><br />{a.agent_version || "—"}</div>
          <div><span className="muted">Risk</span><br /><b>{a.risk_score}</b>/100</div>
        </div>
        {can("manage_assets") && (
          <div className="row">
            <div><label htmlFor="crit">Business criticality</label>
              <select id="crit" value={a.criticality} onChange={e => act.run(() => api(`/assets/${id}`, { method: "PATCH", body: { criticality: e.target.value } }))}>
                {["low", "medium", "high", "critical"].map(c => <option key={c}>{c}</option>)}
              </select></div>
            {!a.revoked && <button className="btn danger sm" disabled={act.busy}
              onClick={() => confirm(`Revoke the agent on ${a.hostname}? It will no longer be able to authenticate.`) && act.run(() => api(`/agents/${id}/revoke`, { method: "POST" }))}>
              Revoke agent</button>}
          </div>)}
        {act.err && <div className="notice err">{act.err}</div>}
        <h3 style={{ margin: "16px 0 6px" }}>Telemetry</h3>
        <div className="mono" style={{ background: "var(--bg)", padding: 10, borderRadius: 8, overflow: "auto" }}>
          {Object.keys(a.telemetry || {}).length === 0 ? "No telemetry yet" :
            Object.entries(a.telemetry).map(([k, v]) => <div key={k}>{k}: {typeof v === "object" ? JSON.stringify(v) : String(v)}</div>)}
        </div>
        <h3 style={{ margin: "16px 0 6px" }}>Vulnerabilities ({a.vulnerabilities.length})</h3>
        {a.vulnerabilities.length === 0 ? <Empty text="None recorded" /> :
          <table><tbody>{a.vulnerabilities.map((v: any) => (
            <tr key={v.id}><td><Badge value={v.severity} /></td><td className="mono">{v.cve}</td><td>{v.title}</td><td><Badge value={v.status} /></td></tr>))}</tbody></table>}
        <h3 style={{ margin: "16px 0 6px" }}>Alerts</h3>
        {a.alerts.length === 0 ? <Empty text="None" /> :
          <table><tbody>{a.alerts.map((x: any) => (
            <tr key={x.id}><td><Badge value={x.severity} /></td><td>{x.title}</td><td className="muted">{ago(x.created_at)}</td></tr>))}</tbody></table>}
      </>}
    </Modal>
  );
}

function Enroll({ onClose }: { onClose: () => void }) {
  const [label, setLabel] = useState("");
  const [tok, setTok] = useState("");
  const act = useAction();
  const origin = window.location.origin;
  return (
    <Modal title="Enroll a new endpoint" onClose={onClose}>
      {!tok ? <>
        <p className="muted">Generate a single-use enrollment token (valid 24 h). Run the agent installer with it on the endpoint.</p>
        <label htmlFor="lbl">Label (e.g. the machine you're enrolling)</label>
        <input id="lbl" value={label} onChange={e => setLabel(e.target.value)} />
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" style={{ marginTop: 12 }} disabled={act.busy}
          onClick={() => act.run(async () => setTok((await api("/agents/enrollment-tokens", { method: "POST", body: { label } })).enrollment_token))}>
          Generate token</button>
      </> : <>
        <div className="notice ok">Copy this now. It is shown once and only its hash is stored.</div>
        <div className="mono" style={{ background: "var(--bg)", padding: 10, borderRadius: 8, wordBreak: "break-all" }}>{tok}</div>
        <p className="muted">On the Windows endpoint (elevated PowerShell):</p>
        <div className="mono" style={{ background: "var(--bg)", padding: 10, borderRadius: 8, wordBreak: "break-all" }}>
          .\CyberFusionAgent.ps1 -Enroll -Server "{origin}" -EnrollmentToken "{tok}"</div>
      </>}
    </Modal>
  );
}

export default function Assets() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/assets", 20000);
  const [sel, setSel] = useState<number | null>(null);
  const [enroll, setEnroll] = useState(false);
  return (
    <Page title="Assets" subtitle="Enrolled endpoints and their security posture"
      actions={can("manage_assets") && <button className="btn" onClick={() => setEnroll(true)}>+ Enroll endpoint</button>}>
      <Card>
        <Loading error={error} loading={loading} />
        {data && (data.length === 0 ? <Empty text="No endpoints yet. Enroll one to get started." /> : (
          <div className="scroll"><table>
            <thead><tr><th>Host</th><th>Status</th><th>OS</th><th>IP</th><th>Criticality</th><th>Open vulns</th><th>Risk</th><th>Last seen</th></tr></thead>
            <tbody>{data.map(a => (
              <tr key={a.id} className="click" onClick={() => setSel(a.id)}>
                <td><b>{a.hostname}</b></td><td><Badge value={a.status} /></td><td>{a.os}</td><td className="mono">{a.ip}</td>
                <td><Badge value={a.criticality} /></td><td>{a.open_vulns}</td><td><b>{a.risk_score}</b></td><td className="muted">{ago(a.last_seen)}</td>
              </tr>))}</tbody>
          </table></div>))}
      </Card>
      {sel !== null && <AssetDetail id={sel} onClose={() => setSel(null)} onChange={reload} />}
      {enroll && <Enroll onClose={() => { setEnroll(false); reload(); }} />}
    </Page>
  );
}

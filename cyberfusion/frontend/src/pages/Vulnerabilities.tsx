import { FormEvent, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Modal, Page, useAction, useFetch } from "../ui";

const NEXT: Record<string, string | null> = { open: "in_progress", in_progress: "remediated", remediated: "verified", verified: null };

function AddVuln({ assets, onClose }: { assets: any[]; onClose: () => void }) {
  const [f, setF] = useState({ asset_id: assets[0]?.id ?? 0, cve: "", title: "", software: "", cvss: "7.5", epss: "0.1", remediation: "" });
  const act = useAction(onClose);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(() => api("/vulnerabilities", { method: "POST",
    body: { ...f, asset_id: Number(f.asset_id), cvss: Number(f.cvss), epss: Number(f.epss) } })); };
  return (
    <Modal title="Add vulnerability" onClose={onClose}>
      <form onSubmit={submit}>
        <label htmlFor="va">Affected asset</label>
        <select id="va" value={f.asset_id} onChange={set("asset_id")}>{assets.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}</select>
        <div className="row"><div><label htmlFor="vc">CVE</label><input id="vc" placeholder="CVE-2024-12345" value={f.cve} onChange={set("cve")} required /></div>
          <div><label htmlFor="vs">Affected software</label><input id="vs" value={f.software} onChange={set("software")} /></div></div>
        <label htmlFor="vt">Title</label><input id="vt" value={f.title} onChange={set("title")} required />
        <div className="row"><div><label htmlFor="vcv">CVSS (0–10)</label><input id="vcv" type="number" step="0.1" min="0" max="10" value={f.cvss} onChange={set("cvss")} /></div>
          <div><label htmlFor="ve">EPSS (0–1)</label><input id="ve" type="number" step="0.01" min="0" max="1" value={f.epss} onChange={set("epss")} /></div></div>
        <label htmlFor="vr">Recommended remediation</label><textarea id="vr" rows={2} value={f.remediation} onChange={set("remediation")} />
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" style={{ marginTop: 12 }} disabled={act.busy}>Add</button>
      </form>
    </Modal>
  );
}

export default function Vulnerabilities() {
  const { can } = useAuth();
  const [status, setStatus] = useState(""); const [sev, setSev] = useState("");
  const qs = new URLSearchParams({ ...(status && { status }), ...(sev && { severity: sev }) }).toString();
  const { data, error, loading, reload } = useFetch<any[]>(`/vulnerabilities${qs ? "?" + qs : ""}`);
  const assets = useFetch<any[]>("/assets");
  const [adding, setAdding] = useState(false);
  const act = useAction(reload);
  return (
    <Page title="Vulnerability Management" subtitle="Asset → Vulnerability → Severity → Risk → Remediation → Verification"
      actions={can("manage_vulns") && assets.data && <button className="btn" onClick={() => setAdding(true)}>+ Add vulnerability</button>}>
      <Card>
        <div className="filters">
          <select aria-label="Filter by status" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">All statuses</option>{["open", "in_progress", "remediated", "verified"].map(s => <option key={s}>{s}</option>)}</select>
          <select aria-label="Filter by severity" value={sev} onChange={e => setSev(e.target.value)}>
            <option value="">All severities</option>{["critical", "high", "medium", "low"].map(s => <option key={s}>{s}</option>)}</select>
        </div>
        {act.err && <div className="notice err">{act.err}</div>}
        <Loading error={error} loading={loading} />
        {data && (data.length === 0 ? <Empty text="No vulnerabilities match." /> : (
          <div className="scroll"><table>
            <thead><tr><th>Severity</th><th>CVE</th><th>Title / software</th><th>Asset</th><th>CVSS</th><th>EPSS</th><th title="CVSS × exploit likelihood × asset criticality">Business risk</th><th>Status</th><th /></tr></thead>
            <tbody>{data.map(v => (
              <tr key={v.id}>
                <td><Badge value={v.severity} /></td><td className="mono">{v.cve}</td>
                <td>{v.title}<div className="muted">{v.software}{v.remediation && <> · {v.remediation}</>}</div></td>
                <td>{v.hostname}</td><td>{v.cvss.toFixed(1)}</td><td>{(v.epss * 100).toFixed(0)}%</td><td><b>{v.business_risk}</b></td>
                <td><Badge value={v.status} /></td>
                <td>{can("manage_vulns") && NEXT[v.status] && <button className="btn ghost sm" disabled={act.busy}
                  onClick={() => act.run(() => api(`/vulnerabilities/${v.id}`, { method: "PATCH", body: { status: NEXT[v.status] } }))}>
                  → {NEXT[v.status]!.replace("_", " ")}</button>}</td>
              </tr>))}</tbody>
          </table></div>))}
      </Card>
      {adding && assets.data && <AddVuln assets={assets.data} onClose={() => { setAdding(false); reload(); }} />}
    </Page>
  );
}

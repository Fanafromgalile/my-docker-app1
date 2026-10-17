import { FormEvent, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Modal, Page, ago, useAction, useFetch } from "../ui";

function IncidentDetail({ id, onClose, onChange }: { id: number; onClose: () => void; onChange: () => void }) {
  const { can } = useAuth();
  const { data: i, error, loading, reload } = useFetch<any>(`/incidents/${id}`);
  const assets = useFetch<any[]>("/assets");
  const [note, setNote] = useState(""); const [notes, setNotes] = useState<string | null>(null);
  const [soarAsset, setSoarAsset] = useState(""); const [soarAction, setSoarAction] = useState("isolate_endpoint"); const [reason, setReason] = useState("");
  const act = useAction(() => { reload(); onChange(); });
  const patch = (body: object) => act.run(() => api(`/incidents/${id}`, { method: "PATCH", body }));
  const canEdit = can("manage_incidents");

  const requestAction = (e: FormEvent) => { e.preventDefault();
    act.run(async () => { await api("/soar", { method: "POST", body: { action: soarAction, asset_id: Number(soarAsset), incident_id: id, reason } }); setReason(""); }); };

  return (
    <Modal title={i ? `#${i.id} · ${i.title}` : "Incident"} onClose={onClose}>
      <Loading error={error} loading={loading} />
      {i && <>
        <div className="row" style={{ marginBottom: 8 }}>
          <div><span className="muted">Severity</span><br /><Badge value={i.severity} /></div>
          <div><span className="muted">Status</span><br />{canEdit ? <select aria-label="Status" value={i.status} onChange={e => patch({ status: e.target.value })}>
            {["open", "investigating", "contained", "resolved"].map(s => <option key={s}>{s}</option>)}</select> : <Badge value={i.status} />}</div>
          <div><span className="muted">Containment</span><br />{canEdit ? <select aria-label="Containment" value={i.containment_status} onChange={e => patch({ containment_status: e.target.value })}>
            {["none", "in_progress", "contained"].map(s => <option key={s}>{s}</option>)}</select> : <Badge value={i.containment_status} />}</div>
          <div><span className="muted">Remediation</span><br />{canEdit ? <select aria-label="Remediation" value={i.remediation_status} onChange={e => patch({ remediation_status: e.target.value })}>
            {["none", "in_progress", "done"].map(s => <option key={s}>{s}</option>)}</select> : <Badge value={i.remediation_status} />}</div>
        </div>
        <p className="muted">Detected by <span className="mono">{i.detection_source}</span> · assigned to <b>{i.assigned_to || "unassigned"}</b> · affected: {i.affected_assets.join(", ") || "—"}</p>
        {act.err && <div className="notice err">{act.err}</div>}

        <h3 style={{ margin: "14px 0 8px" }}>Timeline</h3>
        <ul className="timeline">{i.timeline.map((t: any, k: number) => (
          <li key={k}><div>{t.entry}</div><div className="muted">{t.by} · {ago(t.time)}</div></li>))}</ul>
        {canEdit && <div className="row"><input aria-label="Add timeline entry" placeholder="Add a timeline entry…" value={note} onChange={e => setNote(e.target.value)} />
          <button className="btn sm" disabled={!note || act.busy} onClick={() => { patch({ timeline_entry: note }); setNote(""); }}>Add</button></div>}

        <h3 style={{ margin: "16px 0 8px" }}>Evidence</h3>
        {i.evidence.length === 0 ? <Empty text="No evidence attached" /> : <table><tbody>{i.evidence.map((e: any, k: number) => (
          <tr key={k}><td><Badge value={e.type} /></td><td className="mono">{String(e.ref)}</td><td>{e.summary}</td></tr>))}</tbody></table>}

        <h3 style={{ margin: "16px 0 8px" }}>Investigation notes</h3>
        <textarea aria-label="Investigation notes" rows={3} readOnly={!canEdit} value={notes ?? i.notes} onChange={e => setNotes(e.target.value)} />
        {canEdit && notes !== null && <button className="btn sm" style={{ marginTop: 6 }} disabled={act.busy} onClick={() => { patch({ notes }); setNotes(null); }}>Save notes</button>}

        <h3 style={{ margin: "16px 0 8px" }}>Linked alerts</h3>
        {i.alerts.length === 0 ? <Empty text="None" /> : <table><tbody>{i.alerts.map((a: any) => (
          <tr key={a.id}><td><Badge value={a.severity} /></td><td>{a.title}</td></tr>))}</tbody></table>}

        {can("request_response") && assets.data && <>
          <h3 style={{ margin: "16px 0 8px" }}>Request response action <span className="muted">(needs a second person's approval)</span></h3>
          <form onSubmit={requestAction}>
            <div className="row">
              <select aria-label="Action" value={soarAction} onChange={e => setSoarAction(e.target.value)}>
                <option value="isolate_endpoint">Isolate endpoint</option><option value="release_endpoint">Release endpoint</option><option value="revoke_agent">Revoke agent</option></select>
              <select aria-label="Asset" value={soarAsset} onChange={e => setSoarAsset(e.target.value)} required>
                <option value="">Select asset…</option>{assets.data.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}</select>
            </div>
            <input aria-label="Reason" style={{ marginTop: 8 }} placeholder="Reason (required)" minLength={5} value={reason} onChange={e => setReason(e.target.value)} required />
            <button className="btn" style={{ marginTop: 8 }} disabled={act.busy}>Request approval</button>
          </form></>}
        {i.soar_actions.length > 0 && <table style={{ marginTop: 10 }}><tbody>{i.soar_actions.map((s: any) => (
          <tr key={s.id}><td>{s.action.replace("_", " ")}</td><td><Badge value={s.status} /></td><td className="muted">{s.requested_by}</td></tr>))}</tbody></table>}
      </>}
    </Modal>
  );
}

function NewIncident({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ title: "", severity: "medium", assets: "" });
  const act = useAction(onClose);
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(() => api("/incidents", { method: "POST",
    body: { title: f.title, severity: f.severity, affected_assets: f.assets.split(",").map(s => s.trim()).filter(Boolean) } })); };
  return (
    <Modal title="New incident" onClose={onClose}>
      <form onSubmit={submit}>
        <label htmlFor="it">Title</label><input id="it" value={f.title} onChange={e => setF({ ...f, title: e.target.value })} required />
        <label htmlFor="is">Severity</label>
        <select id="is" value={f.severity} onChange={e => setF({ ...f, severity: e.target.value })}>{["low", "medium", "high", "critical"].map(s => <option key={s}>{s}</option>)}</select>
        <label htmlFor="ia">Affected hosts (comma separated)</label><input id="ia" value={f.assets} onChange={e => setF({ ...f, assets: e.target.value })} />
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" style={{ marginTop: 12 }} disabled={act.busy}>Create</button>
      </form>
    </Modal>
  );
}

function Approvals() {
  const { me, can } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/soar", 10000);
  const act = useAction(reload);
  return (
    <Card title="Response actions (SOAR)">
      <p className="muted" style={{ marginTop: 0 }}>Alert → Investigation → Approval → Action → Verification. Nobody can approve their own request.</p>
      {act.err && <div className="notice err">{act.err}</div>}
      <Loading error={error} loading={loading} />
      {data && (data.length === 0 ? <Empty text="No response actions requested." /> : (
        <div className="scroll"><table>
          <thead><tr><th>Action</th><th>Host</th><th>Reason</th><th>Requested by</th><th>Status</th><th /></tr></thead>
          <tbody>{data.map(s => (
            <tr key={s.id}><td>{s.action.replace(/_/g, " ")}</td><td>{s.hostname}</td><td>{s.reason}</td>
              <td>{s.requested_by}<div className="muted">{ago(s.created_at)}</div></td>
              <td><Badge value={s.status} />{s.approved_by && <div className="muted">by {s.approved_by}</div>}</td>
              <td style={{ whiteSpace: "nowrap" }}>{s.status === "pending" && can("approve_response") && (s.requested_by === me?.username
                ? <span className="muted">awaiting another approver</span>
                : <><button className="btn sm" disabled={act.busy} onClick={() => confirm(`Approve and execute: ${s.action.replace(/_/g, " ")} on ${s.hostname}?`) && act.run(() => api(`/soar/${s.id}/decision`, { method: "POST", body: { decision: "approve" } }))}>Approve</button>{" "}
                  <button className="btn ghost sm" disabled={act.busy} onClick={() => act.run(() => api(`/soar/${s.id}/decision`, { method: "POST", body: { decision: "reject" } }))}>Reject</button></>)}</td></tr>))}</tbody>
        </table></div>))}
    </Card>
  );
}

export default function Incidents() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/incidents", 20000);
  const [sel, setSel] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  return (
    <Page title="Incidents & Response" subtitle="Investigate cases and approve containment actions"
      actions={can("manage_incidents") && <button className="btn" onClick={() => setAdding(true)}>+ New incident</button>}>
      <Card title="Incidents">
        <Loading error={error} loading={loading} />
        {data && (data.length === 0 ? <Empty text="No incidents." /> : (
          <div className="scroll"><table>
            <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th><th>Containment</th><th>Assigned</th><th>Updated</th></tr></thead>
            <tbody>{data.map(i => (
              <tr key={i.id} className="click" onClick={() => setSel(i.id)}>
                <td>{i.id}</td><td><Badge value={i.severity} /></td><td><b>{i.title}</b></td><td><Badge value={i.status} /></td>
                <td><Badge value={i.containment_status} /></td><td>{i.assigned_to || "—"}</td><td className="muted">{ago(i.updated_at)}</td></tr>))}</tbody>
          </table></div>))}
      </Card>
      <Approvals />
      {sel !== null && <IncidentDetail id={sel} onClose={() => setSel(null)} onChange={reload} />}
      {adding && <NewIncident onClose={() => { setAdding(false); reload(); }} />}
    </Page>
  );
}

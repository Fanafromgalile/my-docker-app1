import { FormEvent, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Page, ago, useAction, useFetch } from "../ui";

const ROLES = ["admin", "analyst", "vuln_analyst", "auditor", "readonly"];
const ROLE_DESC: Record<string, string> = {
  admin: "Full platform access, approves response actions",
  analyst: "Investigates alerts and incidents, requests response actions",
  vuln_analyst: "Manages vulnerabilities and remediation",
  auditor: "Read-only access to security, compliance and audit data",
  readonly: "Views dashboards only",
};

function Users() {
  const { me } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/users");
  const [f, setF] = useState({ username: "", password: "", role: "readonly" });
  const act = useAction(() => { reload(); setF({ username: "", password: "", role: "readonly" }); });
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(() => api("/users", { method: "POST", body: f })); };
  const role = useAction(reload);
  return (
    <Card title="Users & roles">
      <Loading error={error} loading={loading} />
      {role.err && <div className="notice err">{role.err}</div>}
      {data && <div className="scroll"><table><thead><tr><th>User</th><th>Role</th><th>Created</th></tr></thead><tbody>
        {data.map(u => <tr key={u.id}><td><b>{u.username}</b></td>
          <td><select aria-label={`Role for ${u.username}`} value={u.role} disabled={u.username === me?.username}
            onChange={e => role.run(() => api(`/users/${u.id}/role`, { method: "PATCH", body: { role: e.target.value } }))}>
            {ROLES.map(r => <option key={r}>{r}</option>)}</select></td><td className="muted">{ago(u.created_at)}</td></tr>)}
      </tbody></table></div>}
      <h3 style={{ margin: "16px 0 4px" }}>Add user</h3>
      <form onSubmit={submit}>
        <div className="row">
          <div><label htmlFor="nu">Username</label><input id="nu" value={f.username} onChange={e => setF({ ...f, username: e.target.value })} required minLength={3} autoComplete="off" /></div>
          <div><label htmlFor="np">Password (12+ chars, mixed case, a digit)</label><input id="np" type="password" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} required autoComplete="new-password" /></div>
          <div><label htmlFor="nr">Role</label><select id="nr" value={f.role} onChange={e => setF({ ...f, role: e.target.value })}>{ROLES.map(r => <option key={r}>{r}</option>)}</select></div>
        </div>
        <p className="muted">{ROLE_DESC[f.role]}</p>
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" disabled={act.busy}>Create user</button>
      </form>
    </Card>
  );
}

function Audit() {
  const { data, error, loading, reload } = useFetch<any[]>("/audit?limit=200");
  const [ver, setVer] = useState<any>(null);
  const act = useAction();
  return (
    <Card title="Audit trail" right={<div className="row" style={{ flexWrap: "nowrap" }}>
      <button className="btn ghost sm" onClick={reload}>Refresh</button>
      <button className="btn sm" disabled={act.busy} onClick={() => act.run(async () => setVer(await api("/audit/verify")))}>Verify integrity</button></div>}>
      <p className="muted" style={{ marginTop: 0 }}>Append-only and hash-chained: editing or deleting any entry breaks verification.</p>
      {ver && <div className={`notice ${ver.valid ? "ok" : "err"}`}>{ver.valid ? `Chain intact — ${ver.entries} entries verified.` : `Chain broken at entry #${ver.broken_at}. Treat as tampering.`}</div>}
      {act.err && <div className="notice err">{act.err}</div>}
      <Loading error={error} loading={loading} />
      {data && (data.length === 0 ? <Empty text="No entries." /> : <div className="scroll"><table>
        <thead><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody>{data.map(a => <tr key={a.id}><td>{a.id}</td><td className="muted" style={{ whiteSpace: "nowrap" }}>{ago(a.timestamp)}</td><td>{a.actor}</td>
          <td className="mono">{a.action}</td><td>{a.target}</td><td>{a.detail}</td><td className="mono">{a.ip}</td></tr>)}</tbody></table></div>)}
    </Card>
  );
}

export default function Settings() {
  const { me, can } = useAuth();
  return (
    <Page title="Settings" subtitle="Account, users and audit">
      <Card title="Your account">
        <p>Signed in as <b>{me?.username}</b> <Badge value={me?.role ?? ""} /></p>
        <p className="muted">{ROLE_DESC[me?.role ?? ""]}</p>
        <p className="muted">Sessions use short-lived tokens held in memory only; closing or refreshing the tab signs you out.</p>
      </Card>
      {can("manage_users") && <Users />}
      {can("view_audit") && <Audit />}
    </Page>
  );
}

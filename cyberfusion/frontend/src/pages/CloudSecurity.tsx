import { FormEvent, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Modal, Page, Stat, ago, useAction, useFetch } from "../ui";

const CATS = ["network_security", "access_control", "logging_monitoring", "encryption", "config_management"];

function Add({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ provider: "azure", resource: "", category: CATS[0], title: "", severity: "medium" });
  const act = useAction(onClose);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(() => api("/cloud", { method: "POST", body: f })); };
  return (
    <Modal title="Add cloud finding" onClose={onClose}>
      <form onSubmit={submit}>
        <div className="row"><div><label htmlFor="p">Provider</label><select id="p" value={f.provider} onChange={set("provider")}>{["azure", "aws", "gcp"].map(x => <option key={x}>{x}</option>)}</select></div>
          <div><label htmlFor="s">Severity</label><select id="s" value={f.severity} onChange={set("severity")}>{["low", "medium", "high", "critical"].map(x => <option key={x}>{x}</option>)}</select></div></div>
        <label htmlFor="r">Resource</label><input id="r" value={f.resource} onChange={set("resource")} required />
        <label htmlFor="c">Category</label><select id="c" value={f.category} onChange={set("category")}>{CATS.map(x => <option key={x} value={x}>{x.replace(/_/g, " ")}</option>)}</select>
        <label htmlFor="t">Finding</label><input id="t" value={f.title} onChange={set("title")} required />
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" style={{ marginTop: 12 }} disabled={act.busy}>Add</button>
      </form>
    </Modal>
  );
}

export default function CloudSecurity() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/cloud");
  const [adding, setAdding] = useState(false);
  const act = useAction(reload);
  const open = (data ?? []).filter(c => c.status === "open");
  const by = (p: string) => open.filter(c => c.provider === p).length;
  return (
    <Page title="Cloud Security" subtitle="Misconfigurations across Azure, AWS and Google Cloud"
      actions={can("manage_cloud") && <button className="btn" onClick={() => setAdding(true)}>+ Add finding</button>}>
      <div className="notice" style={{ marginBottom: 14 }}>
        Findings are entered manually or via the API for now. Live Azure / AWS / GCP scanning is a planned integration.
      </div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Azure open findings" value={by("azure")} /><Stat label="AWS open findings" value={by("aws")} /><Stat label="GCP open findings" value={by("gcp")} />
      </div>
      <Card>
        {act.err && <div className="notice err">{act.err}</div>}
        <Loading error={error} loading={loading} />
        {data && (data.length === 0 ? <Empty text="No cloud findings." /> : (
          <div className="scroll"><table>
            <thead><tr><th>Severity</th><th>Provider</th><th>Resource</th><th>Finding</th><th>Category</th><th>Status</th><th>Found</th><th /></tr></thead>
            <tbody>{data.map(c => (
              <tr key={c.id}><td><Badge value={c.severity} /></td><td style={{ textTransform: "uppercase" }}>{c.provider}</td><td className="mono">{c.resource}</td>
                <td>{c.title}</td><td>{c.category.replace(/_/g, " ")}</td><td><Badge value={c.status} /></td><td className="muted">{ago(c.created_at)}</td>
                <td>{can("manage_cloud") && <button className="btn ghost sm" disabled={act.busy}
                  onClick={() => act.run(() => api(`/cloud/${c.id}`, { method: "PATCH", body: { status: c.status === "open" ? "resolved" : "open" } }))}>
                  {c.status === "open" ? "Resolve" : "Reopen"}</button>}</td></tr>))}</tbody>
          </table></div>))}
      </Card>
      {adding && <Add onClose={() => { setAdding(false); reload(); }} />}
    </Page>
  );
}

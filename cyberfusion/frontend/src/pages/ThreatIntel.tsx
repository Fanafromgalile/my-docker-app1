import { FormEvent, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, Empty, Loading, Modal, Page, ago, useAction, useFetch } from "../ui";

function Lookup() {
  const [v, setV] = useState("");
  const [res, setRes] = useState<any>(null);
  const act = useAction();
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(async () => setRes(await api(`/intel/lookup?value=${encodeURIComponent(v.trim())}`))); };
  return (
    <Card title="Investigate an indicator">
      <form className="row" onSubmit={submit}>
        <input aria-label="Indicator" placeholder="IP address, domain, URL or file hash" value={v} onChange={e => setV(e.target.value)} required />
        <button className="btn" disabled={act.busy}>Look up</button>
      </form>
      {act.err && <div className="notice err">{act.err}</div>}
      {res && (res.known ? (
        <div style={{ marginTop: 12 }}>
          <div className="row"><div><span className="muted">Reputation</span><br /><Badge value={res.indicator.reputation} /></div>
            <div><span className="muted">Confidence</span><br /><b>{res.indicator.confidence}%</b></div>
            <div><span className="muted">First seen</span><br />{ago(res.indicator.first_seen)}</div>
            <div><span className="muted">Last seen</span><br />{ago(res.indicator.last_seen)}</div></div>
          <p>Malware: <b>{res.indicator.malware || "—"}</b> · Campaign: <b>{res.indicator.campaign || "—"}</b></p>
          <p className="muted">Seen {res.local_sightings} time(s) in your events{res.hosts_contacted.length > 0 && <> · hosts: {res.hosts_contacted.join(", ")}</>}</p>
        </div>) : <div className="notice" style={{ marginTop: 12 }}>Not in the local intelligence store. {res.local_sightings} local sighting(s). Reputation is unknown, not benign.</div>)}
    </Card>
  );
}

function Add({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ type: "ip", value: "", reputation: "suspicious", confidence: "60", malware: "", campaign: "" });
  const act = useAction(onClose);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  const submit = (e: FormEvent) => { e.preventDefault(); act.run(() => api("/intel", { method: "POST", body: { ...f, confidence: Number(f.confidence) } })); };
  return (
    <Modal title="Add indicator" onClose={onClose}>
      <form onSubmit={submit}>
        <div className="row"><div><label htmlFor="t">Type</label><select id="t" value={f.type} onChange={set("type")}>{["ip", "domain", "url", "hash"].map(x => <option key={x}>{x}</option>)}</select></div>
          <div><label htmlFor="r">Reputation</label><select id="r" value={f.reputation} onChange={set("reputation")}>{["malicious", "suspicious", "benign", "unknown"].map(x => <option key={x}>{x}</option>)}</select></div></div>
        <label htmlFor="v">Value</label><input id="v" value={f.value} onChange={set("value")} required minLength={3} />
        <label htmlFor="c">Confidence (0–100)</label><input id="c" type="number" min="0" max="100" value={f.confidence} onChange={set("confidence")} />
        <div className="row"><div><label htmlFor="m">Associated malware</label><input id="m" value={f.malware} onChange={set("malware")} /></div>
          <div><label htmlFor="ca">Campaign</label><input id="ca" value={f.campaign} onChange={set("campaign")} /></div></div>
        {act.err && <div className="notice err">{act.err}</div>}
        <button className="btn" style={{ marginTop: 12 }} disabled={act.busy}>Add</button>
      </form>
    </Modal>
  );
}

export default function ThreatIntel() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useFetch<any[]>("/intel");
  const [adding, setAdding] = useState(false);
  return (
    <Page title="Threat Intelligence" subtitle="Enrich indicators and match them against your events (malicious IPs raise alerts automatically)"
      actions={can("manage_intel") && <button className="btn" onClick={() => setAdding(true)}>+ Add indicator</button>}>
      <Lookup />
      <Card title="Indicator store">
        <Loading error={error} loading={loading} />
        {data && (data.length === 0 ? <Empty text="No indicators yet." /> : (
          <div className="scroll"><table>
            <thead><tr><th>Type</th><th>Value</th><th>Reputation</th><th>Confidence</th><th>Malware</th><th>Campaign</th><th>Last seen</th></tr></thead>
            <tbody>{data.map(i => (
              <tr key={i.id}><td>{i.type}</td><td className="mono" style={{ wordBreak: "break-all" }}>{i.value}</td><td><Badge value={i.reputation} /></td>
                <td>{i.confidence}%</td><td>{i.malware || "—"}</td><td>{i.campaign || "—"}</td><td className="muted">{ago(i.last_seen)}</td></tr>))}</tbody>
          </table></div>))}
      </Card>
      {adding && <Add onClose={() => { setAdding(false); reload(); }} />}
    </Page>
  );
}

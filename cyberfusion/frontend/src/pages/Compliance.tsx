import { useState } from "react";
import { Badge, Card, Loading, Page, useFetch } from "../ui";

export default function Compliance() {
  const { data, error, loading } = useFetch<any[]>("/compliance", 30000);
  const [fw, setFw] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const active = data?.find(f => f.framework === (fw ?? data[0]?.framework));
  return (
    <Page title="Compliance" subtitle="Finding → Security control → Framework → Remediation">
      <Loading error={error} loading={loading} />
      {data && <>
        <div className="grid g4" style={{ marginBottom: 14 }}>
          {data.map(f => (
            <button key={f.framework} className="stat" onClick={() => setFw(f.framework)} aria-pressed={active?.framework === f.framework}
              style={{ textAlign: "left", cursor: "pointer", color: "inherit", font: "inherit",
                outline: active?.framework === f.framework ? "2px solid var(--accent)" : undefined,
                borderLeftColor: f.score >= 80 ? "var(--ok)" : f.score >= 50 ? "var(--med)" : "var(--crit)" }}>
              <div className="stat-v">{f.score}%</div><div className="stat-l">{f.framework}</div>
              <div className="stat-s">{f.passing}/{f.total} controls passing</div>
            </button>))}
        </div>
        {active && <Card title={`${active.framework} controls`}>
          <p className="muted" style={{ marginTop: 0 }}>A control fails while any open finding maps to its category. Scores reflect what CyberFusion can observe, not a formal audit.</p>
          <div className="scroll"><table>
            <thead><tr><th>Control</th><th>Requirement</th><th>Area</th><th>Status</th><th>Findings</th></tr></thead>
            <tbody>{active.controls.map((c: any) => {
              const key = `${active.framework}${c.control_id}`;
              return [
                <tr key={key} className={c.finding_count ? "click" : ""} onClick={() => c.finding_count && setOpen(open === key ? null : key)}>
                  <td className="mono">{c.control_id}</td><td>{c.title}</td><td>{c.category.replace(/_/g, " ")}</td><td><Badge value={c.status} /></td><td>{c.finding_count || "—"}</td></tr>,
                open === key && <tr key={key + "d"}><td colSpan={5} style={{ background: "var(--bg)" }}>
                  <b>Remediation:</b> {c.remediation}
                  <ul>{c.findings.map((f: any, i: number) => <li key={i}><Badge value={f.severity} /> <span className="muted">{f.kind}</span> · {f.title}</li>)}</ul>
                  {c.finding_count > c.findings.length && <span className="muted">…and {c.finding_count - c.findings.length} more</span>}</td></tr>];
            })}</tbody>
          </table></div>
        </Card>}
      </>}
    </Page>
  );
}

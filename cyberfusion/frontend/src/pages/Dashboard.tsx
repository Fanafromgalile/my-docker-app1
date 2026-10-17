import { Badge, Card, Empty, Loading, Page, Stat, ago, useFetch } from "../ui";

const SEV = ["critical", "high", "medium", "low"] as const;
const SEV_COLOR: Record<string, string> = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)" };

function riskLabel(n: number) { return n >= 75 ? ["Critical", "crit"] : n >= 50 ? ["High", "high"] : n >= 25 ? ["Moderate", "med"] : ["Low", "ok"]; }

function Trend({ data }: { data: { day: string; alerts: number; events: number }[] }) {
  const W = 520, H = 160, P = 24;
  const max = Math.max(1, ...data.flatMap(d => [d.alerts * 4, d.events]));
  const x = (i: number) => P + (i * (W - 2 * P)) / Math.max(1, data.length - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const line = (k: "alerts" | "events", mul: number) => data.map((d, i) => `${i ? "L" : "M"}${x(i)},${y(d[k] * mul)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Events and alerts over the last 7 days" style={{ width: "100%" }}>
      <path d={line("events", 1)} fill="none" stroke="var(--accent)" strokeWidth="2" />
      <path d={line("alerts", 4)} fill="none" stroke="var(--crit)" strokeWidth="2" strokeDasharray="4 3" />
      {data.map((d, i) => <text key={i} x={x(i)} y={H - 6} fill="var(--muted)" fontSize="10" textAnchor="middle">{d.day}</text>)}
      <text x={P} y={12} fill="var(--accent)" fontSize="10">— events</text>
      <text x={P + 70} y={12} fill="var(--crit)" fontSize="10">-- alerts (scaled ×4)</text>
    </svg>
  );
}

function SevBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div>
      {SEV.map(s => (
        <div key={s} className="row" style={{ marginBottom: 8, flexWrap: "nowrap" }}>
          <span style={{ width: 70, flex: "0 0 70px", textTransform: "capitalize" }}>{s}</span>
          <div className="bar" style={{ flex: 1 }}><i style={{ width: `${(counts[s] / max) * 100}%`, background: SEV_COLOR[s] }} /></div>
          <b style={{ width: 28, flex: "0 0 28px", textAlign: "right" }}>{counts[s]}</b>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { data: d, error, loading } = useFetch<any>("/dashboard", 15000);
  if (!d) return <Page title="Dashboard"><Loading error={error} loading={loading} /></Page>;
  const [label, tone] = riskLabel(d.risk_score);
  return (
    <Page title="Security Dashboard" subtitle="Live view of your environment · refreshes every 15 s">
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Organisation risk score" value={`${d.risk_score}/100`} tone={tone} sub={label} />
        <Stat label="Active endpoints" value={`${d.active_endpoints}/${d.total_endpoints}`} tone={d.active_endpoints < d.total_endpoints ? "med" : "ok"} sub="seen in the last 5 min" />
        <Stat label="Critical vulnerabilities" value={d.critical_vulnerabilities} tone={d.critical_vulnerabilities ? "crit" : "ok"} />
        <Stat label="Open alerts" value={d.open_alerts} tone={d.alerts_by_severity.critical ? "crit" : d.open_alerts ? "high" : "ok"} />
        <Stat label="Open incidents" value={d.open_incidents} tone={d.open_incidents ? "high" : "ok"} />
        <Stat label="Pending approvals" value={d.pending_approvals} tone={d.pending_approvals ? "med" : "ok"} sub="response actions" />
      </div>

      <div className="grid g2" style={{ marginBottom: 14 }}>
        <Card title="Security trend (7 days)"><Trend data={d.trend} /></Card>
        <Card title="Endpoint health">
          <div className="row" style={{ justifyContent: "space-around", textAlign: "center" }}>
            <div><div className="stat-v" style={{ color: "var(--low)" }}>{d.endpoint_health.online}</div><div className="muted">Online</div></div>
            <div><div className="stat-v" style={{ color: "var(--med)" }}>{d.endpoint_health.offline}</div><div className="muted">Offline</div></div>
            <div><div className="stat-v" style={{ color: "var(--crit)" }}>{d.endpoint_health.revoked}</div><div className="muted">Revoked</div></div>
          </div>
        </Card>
        <Card title="Open vulnerabilities by severity"><SevBars counts={d.vulnerabilities_by_severity} /></Card>
        <Card title="Open alerts by severity"><SevBars counts={d.alerts_by_severity} /></Card>
      </div>

      <div className="grid g2">
        <Card title="Highest-risk assets">
          {d.top_assets.length === 0 ? <Empty text="No assets enrolled yet" /> : (
            <table><thead><tr><th>Host</th><th>Criticality</th><th>Risk</th></tr></thead><tbody>
              {d.top_assets.map((a: any) => (
                <tr key={a.id}><td>{a.hostname}</td><td><Badge value={a.criticality} /></td>
                  <td style={{ width: "40%" }}><div className="row" style={{ flexWrap: "nowrap" }}>
                    <div className="bar" style={{ flex: 1 }}><i style={{ width: `${a.risk_score}%`, background: a.risk_score >= 50 ? "var(--crit)" : "var(--accent)" }} /></div>
                    <b>{a.risk_score}</b></div></td></tr>
              ))}
            </tbody></table>
          )}
        </Card>
        <Card title="Recent alerts">
          {d.recent_alerts.length === 0 ? <Empty text="No alerts" /> : (
            <table><thead><tr><th>Severity</th><th>Alert</th><th>When</th></tr></thead><tbody>
              {d.recent_alerts.map((a: any) => (
                <tr key={a.id}><td><Badge value={a.severity} /></td><td>{a.title}</td><td className="muted">{ago(a.created_at)}</td></tr>
              ))}
            </tbody></table>
          )}
        </Card>
      </div>
    </Page>
  );
}

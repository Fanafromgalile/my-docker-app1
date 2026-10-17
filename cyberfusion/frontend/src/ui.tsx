import { ReactNode, useCallback, useEffect, useState } from "react";
import { api } from "./api";

export function Badge({ value }: { value: string }) {
  return <span className={`badge b-${value.replace(/[^a-z_]/gi, "").toLowerCase()}`}>{value.replace(/_/g, " ")}</span>;
}

export function Card({ title, right, children, className = "" }:
  { title?: string; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && <header className="card-h"><h3>{title}</h3>{right}</header>}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone, sub }: { label: string; value: ReactNode; tone?: string; sub?: string }) {
  return (
    <div className={`stat ${tone ? "t-" + tone : ""}`}>
      <div className="stat-v">{value}</div>
      <div className="stat-l">{label}</div>
      {sub && <div className="stat-s">{sub}</div>}
    </div>
  );
}

export function Page({ title, subtitle, actions, children }:
  { title: string; subtitle?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="page">
      <div className="page-h">
        <div><h1>{title}</h1>{subtitle && <p className="muted">{subtitle}</p>}</div>
        <div className="actions">{actions}</div>
      </div>
      {children}
    </div>
  );
}

export const ago = (iso?: string | null) => {
  if (!iso) return "never";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

export function useFetch<T>(path: string, refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const load = useCallback(() => {
    api<T>(path).then(d => { setData(d); setError(""); }).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [path]);
  useEffect(() => {
    load();
    if (!refreshMs) return;
    const t = setInterval(load, refreshMs);
    return () => clearInterval(t);
  }, [load, refreshMs]);
  return { data, error, loading, reload: load };
}

export function Loading({ error, loading }: { error: string; loading: boolean }) {
  if (error) return <div className="notice err">{error}</div>;
  if (loading) return <div className="muted">Loading…</div>;
  return null;
}

export function Empty({ text }: { text: string }) { return <div className="empty">{text}</div>; }

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" role="dialog" aria-label={title} onClick={e => e.stopPropagation()}>
        <header className="card-h"><h3>{title}</h3><button className="btn ghost" onClick={onClose}>✕</button></header>
        {children}
      </div>
    </div>
  );
}

/** Runs an async action and reports failure inline instead of silently. */
export function useAction(after?: () => void) {
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true); setErr("");
    try { await fn(); after?.(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return { run, err, busy, clear: () => setErr("") };
}

// The access token lives in memory only (not localStorage), so XSS cannot read a persisted token
// and closing the tab ends the session.
let token: string | null = null;
let onUnauthorized: () => void = () => {};

export const setToken = (t: string | null) => { token = t; };
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn; };

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: opts.method ?? "GET",
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && token) { onUnauthorized(); }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* non-JSON error body */ }
    throw new Error(msg);
  }
  return res.json();
}

export type Severity = "critical" | "high" | "medium" | "low";

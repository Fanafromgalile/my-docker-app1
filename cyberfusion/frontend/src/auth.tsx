import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from "react";
import { api, setToken, setUnauthorizedHandler } from "./api";

interface Me { username: string; role: string; permissions: string[]; }
interface AuthCtx {
  me: Me | null;
  login: (u: string, p: string) => Promise<void>;
  logout: () => void;
  can: (perm: string) => boolean;
}

const Ctx = createContext<AuthCtx>(null as unknown as AuthCtx);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);

  const logout = useCallback(() => { setToken(null); setMe(null); }, []);
  useEffect(() => setUnauthorizedHandler(logout), [logout]);

  const login = async (username: string, password: string) => {
    const r = await api("/auth/login", { method: "POST", body: { username, password } });
    setToken(r.access_token);
    setMe(await api("/auth/me"));
  };

  const can = (perm: string) => !!me?.permissions.includes(perm);
  return <Ctx.Provider value={{ me, login, logout, can }}>{children}</Ctx.Provider>;
}

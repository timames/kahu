import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  username: string | null;
  role: string | null;
}

interface AuthContextValue extends AuthState {
  login: (token: string, refreshToken: string, username: string, role: string) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const STORAGE_KEY = "kahu_auth";

function loadAuth(): AuthState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return { token: null, refreshToken: null, username: null, role: null };
}

function saveAuth(state: AuthState) {
  if (state.token) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } else {
    localStorage.removeItem(STORAGE_KEY);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(loadAuth);

  useEffect(() => { saveAuth(state); }, [state]);

  const login = useCallback((token: string, refreshToken: string, username: string, role: string) => {
    setState({ token, refreshToken, username, role });
  }, []);

  const logout = useCallback(() => {
    setState({ token: null, refreshToken: null, username: null, role: null });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, logout, isAuthenticated: !!state.token }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

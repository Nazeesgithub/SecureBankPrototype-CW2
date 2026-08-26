import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "../api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);

  const refreshSession = useCallback(async () => {
    try {
      const data = await api.session();
      setUser(data.user);
    } catch {
      setUser(null);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  useEffect(() => {
    if (!user) return undefined;
    const intervalId = setInterval(refreshSession, 30_000);
    return () => clearInterval(intervalId);
  }, [user, refreshSession]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, setUser, checking, refreshSession, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function homeForRole(role) {
  return role === "security" || role === "admin" ? "/security-center" : "/dashboard";
}

export function ProtectedRoute() {
  const { user, checking } = useAuth();
  if (checking) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <Outlet />;
}

export function CustomerRoute() {
  const { user, checking } = useAuth();
  if (checking) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "customer" && user.role !== "admin") {
    return <Navigate to={homeForRole(user.role)} replace />;
  }
  return <Outlet />;
}

export function SecurityRoute() {
  const { user, checking } = useAuth();
  if (checking) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "security" && user.role !== "admin") {
    return <Navigate to={homeForRole(user.role)} replace />;
  }
  return <Outlet />;
}

export function AdminRoute() {
  const { user, checking } = useAuth();
  if (checking) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "admin") return <Navigate to={homeForRole(user.role)} replace />;
  return <Outlet />;
}

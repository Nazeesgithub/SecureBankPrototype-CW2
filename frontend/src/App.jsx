import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import {
  ProtectedRoute,
  CustomerRoute,
  SecurityRoute,
  AdminRoute,
} from "./components/ProtectedRoute";
import AppShell from "./components/AppShell";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Otp from "./pages/Otp";
import Dashboard from "./pages/Dashboard";
import SecurityCenter from "./pages/SecurityCenter";
import Transfer from "./pages/Transfer";
import TransactionHistory from "./pages/TransactionHistory";
import Profile from "./pages/Profile";
import Settings from "./pages/Settings";
import Admin from "./pages/Admin";
import EncryptionLab from "./pages/EncryptionLab";
import AttackSimulation from "./pages/AttackSimulation";
import ThreatMap from "./pages/ThreatMap";
import SecurityLogs from "./pages/SecurityLogs";
import DatabaseViewer from "./pages/DatabaseViewer";
import BackupCenter from "./pages/BackupCenter";
import SecurityReport from "./pages/SecurityReport";

export function homeForRole(role) {
  return role === "security" || role === "admin" ? "/security-center" : "/dashboard";
}

function Home() {
  const { user, checking } = useAuth();
  if (checking) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <Navigate to={homeForRole(user.role)} replace />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/otp" element={<Otp />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route element={<CustomerRoute />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/transfer" element={<Transfer />} />
            <Route path="/history" element={<TransactionHistory />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
          </Route>

          <Route element={<SecurityRoute />}>
            <Route path="/security-center" element={<SecurityCenter />} />
            <Route path="/encryption-lab" element={<EncryptionLab />} />
            <Route path="/attack-simulation" element={<AttackSimulation />} />
            <Route path="/threat-map" element={<ThreatMap />} />
            <Route path="/security-logs" element={<SecurityLogs />} />
            <Route path="/database-viewer" element={<DatabaseViewer />} />
            <Route path="/backup-center" element={<BackupCenter />} />
            <Route path="/security-report" element={<SecurityReport />} />
          </Route>

          <Route element={<AdminRoute />}>
            <Route path="/admin" element={<Admin />} />
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

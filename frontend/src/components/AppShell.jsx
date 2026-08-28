import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  CircleDot,
  ArrowLeftRight,
  ListOrdered,
  ShieldCheck,
  FlaskConical,
  Zap,
  Radar,
  ScrollText,
  Database,
  FileText,
  RotateCcw,
  Settings,
  LogOut,
  Menu,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const CUSTOMER_NAV = [
  { to: "/dashboard", label: "Dashboard", icon: CircleDot },
  { to: "/transfer", label: "Transfer", icon: ArrowLeftRight },
  { to: "/history", label: "History", icon: ListOrdered },
  { to: "/profile", label: "Profile", icon: CircleDot },
  { to: "/settings", label: "Settings", icon: Settings },
];

const SECURITY_NAV = [
  { to: "/security-center", label: "Security Center", icon: ShieldCheck },
  { to: "/encryption-lab", label: "Encryption Lab", icon: FlaskConical },
  { to: "/attack-simulation", label: "Attack Sim", icon: Zap },
  { to: "/threat-map", label: "Threat Map", icon: Radar },
  { to: "/security-logs", label: "Security Logs", icon: ScrollText },
  { to: "/database-viewer", label: "Database", icon: Database },
  { to: "/security-report", label: "Report", icon: FileText },
  { to: "/backup-center", label: "Backup", icon: RotateCcw },
];

export default function AppShell() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  const navItems = [
    ...(user?.role === "customer" || user?.role === "admin"
      ? CUSTOMER_NAV
      : []),
    ...(user?.role === "security" || user?.role === "admin"
      ? SECURITY_NAV
      : []),
  ];

  return (
    <div className="app-shell">
      <button
        type="button"
        className="sidebar-toggle"
        aria-label={mobileOpen ? "Close menu" : "Open menu"}
        onClick={() => setMobileOpen((open) => !open)}
      >
        {mobileOpen ? (
          <X size={20} strokeWidth={1.5} />
        ) : (
          <Menu size={20} strokeWidth={1.5} />
        )}
      </button>

      {mobileOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside className={`sidebar${mobileOpen ? " sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <span className="dot" />
          <span>
            {user?.role === "customer" ? "SecureBank" : "SecureBank SOC"}
          </span>
        </div>

        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              `sidebar-link${isActive ? " active" : ""}`
            }
          >
            <item.icon aria-hidden="true" size={18} strokeWidth={1.5} />
            <span>{item.label}</span>
          </NavLink>
        ))}

        {user?.role === "admin" && (
          <NavLink
            to="/admin"
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              `sidebar-link${isActive ? " active" : ""}`
            }
          >
            <Settings aria-hidden="true" size={18} strokeWidth={1.5} />
            <span>Admin</span>
          </NavLink>
        )}

        <div className="sidebar-spacer" />

        <button
          className="sidebar-link"
          style={{
            border: "none",
            background: "none",
            cursor: "pointer",
            width: "100%",
            textAlign: "left",
          }}
          onClick={handleLogout}
        >
          <LogOut aria-hidden="true" size={18} strokeWidth={1.5} />
          <span>Logout</span>
        </button>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}

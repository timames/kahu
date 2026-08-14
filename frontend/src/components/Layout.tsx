import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  ListFilter,
  MessageSquare,
  FileText,
  ShieldCheck,
  Cable,
  Radar,
  Swords,
  Trophy,
  Settings,
  LogOut,
  Sun,
  Moon,
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useTheme } from "@/hooks/useTheme";

interface NavItem {
  to: string;
  icon: React.ComponentType<{ size?: number }>;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/", icon: Activity, label: "Glance" },
  { to: "/score", icon: Trophy, label: "Score" },
  { to: "/feed", icon: ListFilter, label: "Feed" },
  { to: "/investigate", icon: MessageSquare, label: "Investigate" },
  { to: "/reports", icon: FileText, label: "Reports" },
  { to: "/compliance", icon: ShieldCheck, label: "Compliance" },
  { to: "/connectors", icon: Cable, label: "Connectors" },
  { to: "/recon", icon: Radar, label: "Recon" },
  { to: "/arsenal", icon: Swords, label: "Arsenal" },
];

const SETTINGS_ITEM: NavItem = { to: "/settings", icon: Settings, label: "Settings" };

export function Layout() {
  const { username, logout } = useAuth();
  const { theme, toggle: toggleTheme } = useTheme();

  const items = [...NAV_ITEMS, SETTINGS_ITEM];

  return (
    <div className="flex h-full">
      {/* Desktop sidebar */}
      <nav className="hidden md:flex flex-col w-56 bg-kahu-card border-r border-kahu-border shrink-0">
        <div className="flex items-center gap-2 px-5 py-5 border-b border-kahu-border">
          <div className="w-8 h-8 rounded-lg bg-kahu-accent flex items-center justify-center text-white font-bold text-sm">
            K
          </div>
          <span className="text-lg font-semibold text-white">Kahu</span>
        </div>
        <div className="flex-1 py-2 overflow-y-auto">
          {items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-5 py-2.5 text-sm transition-colors ${
                  isActive
                    ? "text-white bg-kahu-accent/10 border-r-2 border-kahu-accent"
                    : "text-slate-400 hover:text-white hover:bg-white/5"
                }`
              }
            >
              <item.icon size={18} />
              {item.label}
            </NavLink>
          ))}
        </div>
        <div className="border-t border-kahu-border px-5 py-3 flex items-center justify-between">
          <span className="text-xs text-slate-500 truncate">{username}</span>
          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              className="text-slate-500 hover:text-white transition-colors"
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            >
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <button onClick={logout} className="text-slate-500 hover:text-white transition-colors" title="Sign out">
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4 md:p-6 pb-20 md:pb-6">
          <Outlet />
        </div>
      </main>

      {/* Mobile bottom tabs */}
      <nav className="md:hidden fixed bottom-0 inset-x-0 bg-kahu-card border-t border-kahu-border safe-bottom z-50">
        <div className="flex justify-around py-1 pb-[env(safe-area-inset-bottom)]">
          {items.slice(0, 5).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex flex-col items-center gap-0.5 px-2 py-2 text-[10px] transition-colors ${
                  isActive ? "text-kahu-accent" : "text-slate-500"
                }`
              }
            >
              <item.icon size={20} />
              {item.label}
            </NavLink>
          ))}
          <NavLink
            to="/more"
            className={({ isActive }) =>
              `flex flex-col items-center gap-0.5 px-2 py-2 text-[10px] transition-colors ${
                isActive ? "text-kahu-accent" : "text-slate-500"
              }`
            }
          >
            <Settings size={20} />
            More
          </NavLink>
        </div>
      </nav>
    </div>
  );
}

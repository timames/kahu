import { NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  MessageSquare,
  FileText,
  ShieldCheck,
  ClipboardCheck,
  Cable,
  Radar,
  Swords,
  Trophy,
  Settings,
  ChevronRight,
} from "lucide-react";
import { getProfiles } from "@/api/client";
import { useSettings } from "@/hooks/useSettings";

const ITEMS = [
  { to: "/ask-ai", icon: MessageSquare, label: "Ask AI", desc: "AI investigation chat" },
  { to: "/reports", icon: FileText, label: "Reports", desc: "Generated reports" },
  { to: "/compliance", icon: ShieldCheck, label: "Compliance", desc: "Framework coverage" },
  { to: "/connectors", icon: Cable, label: "Connectors", desc: "Data sources" },
  { to: "/recon", icon: Radar, label: "Recon", desc: "Discovery & vuln scanning" },
  { to: "/arsenal", icon: Swords, label: "Arsenal", desc: "Offensive tools" },
];

const GRC_ITEM = { to: "/grc", icon: ClipboardCheck, label: "GRC", desc: "Selected framework coverage" };
const SCORE_ITEM = { to: "/score", icon: Trophy, label: "Score", desc: "XP, badges, tickets" };
const SETTINGS_ITEM = { to: "/settings", icon: Settings, label: "Settings", desc: "Preferences" };

export function More() {
  const { gamificationEnabled } = useSettings();
  const { data: profiles } = useQuery({ queryKey: ["profiles"], queryFn: getProfiles });

  const items = [...ITEMS];
  if ((profiles?.length ?? 0) > 0) items.splice(3, 0, GRC_ITEM);
  if (gamificationEnabled) items.push(SCORE_ITEM);
  items.push(SETTINGS_ITEM);

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">More</h1>
      <div className="flex flex-col gap-2">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className="bg-kahu-card border border-kahu-border rounded-xl p-4 flex items-center gap-3 hover:border-kahu-accent/30 transition-colors"
          >
            <div className="w-10 h-10 rounded-lg bg-kahu-elevated flex items-center justify-center shrink-0">
              <item.icon size={18} className="text-slate-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-white">{item.label}</div>
              <div className="text-xs text-slate-500">{item.desc}</div>
            </div>
            <ChevronRight size={16} className="text-slate-600 shrink-0" />
          </NavLink>
        ))}
      </div>
    </div>
  );
}

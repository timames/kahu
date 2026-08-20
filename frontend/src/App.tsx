import { Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Login } from "@/pages/Login";
import { Glance } from "@/pages/Glance";
import { Feed } from "@/pages/Feed";
import { AskAI } from "@/pages/AskAI";
import { Investigations } from "@/pages/Investigations";
import { Incidents } from "@/pages/Incidents";
import { Reports } from "@/pages/Reports";
import { Compliance } from "@/pages/Compliance";
import { GRC } from "@/pages/GRC";
import { Connectors } from "@/pages/Connectors";
import { Recon } from "@/pages/Recon";
import { Arsenal } from "@/pages/Arsenal";
import { Score } from "@/pages/Score";
import { SettingsPage } from "@/pages/SettingsPage";
import { More } from "@/pages/More";
import { useAuth } from "@/hooks/useAuth";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Glance />} />
        <Route path="feed" element={<Feed />} />
        <Route path="investigations" element={<Investigations />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="ask-ai" element={<AskAI />} />
        <Route path="investigate" element={<Navigate to="/ask-ai" replace />} />
        <Route path="reports" element={<Reports />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="grc" element={<GRC />} />
        <Route path="connectors" element={<Connectors />} />
        <Route path="recon" element={<Recon />} />
        <Route path="arsenal" element={<Arsenal />} />
        <Route path="score" element={<Score />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="more" element={<More />} />
      </Route>
    </Routes>
  );
}

import { Routes, Route } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Glance } from "@/pages/Glance";
import { Feed } from "@/pages/Feed";
import { Investigate } from "@/pages/Investigate";
import { Reports } from "@/pages/Reports";
import { Compliance } from "@/pages/Compliance";
import { Connectors } from "@/pages/Connectors";
import { Recon } from "@/pages/Recon";
import { Arsenal } from "@/pages/Arsenal";
import { Score } from "@/pages/Score";
import { SettingsPage } from "@/pages/SettingsPage";
import { More } from "@/pages/More";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Glance />} />
        <Route path="feed" element={<Feed />} />
        <Route path="investigate" element={<Investigate />} />
        <Route path="reports" element={<Reports />} />
        <Route path="compliance" element={<Compliance />} />
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

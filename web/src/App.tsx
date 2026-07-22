import { useState } from "react";
import Posture from "./views/Posture";
import Findings from "./views/Findings";
import Timeline from "./views/Timeline";
import Alerts from "./views/Alerts";
import Scan from "./views/Scan";
import Agents from "./views/Agents";
import Host from "./views/Host";
import Ai from "./views/Ai";
import Messaging from "./views/Messaging";
import ApprovalSurface from "./components/ApprovalSurface";
import Welcome from "./components/Welcome";
import DetectionBanner from "./components/DetectionBanner";
import UpdateBanner from "./components/UpdateBanner";
import { UpdaterProvider } from "./lib/updater";
import Sidebar from "./components/Sidebar";

type Tab =
  | "posture" | "findings" | "timeline" | "alerts" | "scan" | "agents" | "host" | "ai" | "messaging"
  ;

export default function App() {
  const [tab, setTab] = useState<Tab>("posture");
  return (
    <UpdaterProvider>
    <div className="flex h-screen text-[var(--text-primary)] overflow-hidden gap-2.5 p-2.5"
      style={{ background: "var(--lg-ambient)" }}>
      <Sidebar tab={tab} onNavigate={setTab} />
      <main className="flex-1 overflow-y-auto min-w-0 rounded-[var(--lg-r-chrome)]">
        {/* In-app update prompt (desktop only; hidden when no update) */}
        <UpdateBanner />
        {tab === "posture" && (
          <>
            <DetectionBanner onNavigate={setTab} />
            <Posture />
          </>
        )}
        {tab === "findings" && <Findings />}
        {tab === "timeline" && <Timeline />}
        {tab === "alerts" && <Alerts />}
        {tab === "scan" && <Scan />}
        {tab === "agents" && <Agents />}
        {tab === "host" && <Host />}
        {tab === "ai" && <Ai />}
        {tab === "messaging" && <Messaging />}
      </main>
      {/* Single approval overlay: polls getPending() under Tauri only (self-guarded).
          Supersedes the former DecisionModal (deleted) — no more duplicate polls. */}
      <ApprovalSurface />
      {/* First-run welcome overlay: gated by localStorage flag; renders nothing on repeat visits. */}
      <Welcome />
    </div>
    </UpdaterProvider>
  );
}

// Top-level "AI Explanations" view — promoted out of Host Protection's AI
// sub-tab so it's directly reachable from the sidebar. Renders the existing
// AiSettings panel (mode/provider/model/consent + key field) under a
// page-level header consistent with Host.tsx's header pattern.
import AiSettings from "./host/AiSettings";

export default function Ai() {
  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div className="mb-2">
        <h1 className="text-sm font-semibold text-[#8E8E93] uppercase tracking-widest">
          AI Explanations
        </h1>
        <p className="text-xs text-[#8E8E93] mt-0.5">
          Plain-English second opinions on flagged actions. Off by default; Local runs
          on-device, Cloud is opt-in.
        </p>
      </div>

      <AiSettings />
    </div>
  );
}

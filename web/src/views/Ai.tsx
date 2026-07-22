// Top-level "AI" view — promoted out of Host Protection's AI sub-tab so it's
// directly reachable from the sidebar. Renders the existing AiSettings panel
// (Connection/Explanations/Skill Judge sections) under a page-level header
// consistent with Host.tsx's header pattern.
import AiSettings from "./host/AiSettings";

export default function Ai() {
  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div className="mb-2">
        <h1 className="text-sm font-semibold text-[var(--text-tertiary)] uppercase tracking-widest">
          AI
        </h1>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          Explanations and the Skill Judge. Off by default; Local runs on-device, Cloud is opt-in.
        </p>
      </div>

      <AiSettings />
    </div>
  );
}

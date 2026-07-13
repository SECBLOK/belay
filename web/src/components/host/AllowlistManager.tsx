import { useState } from "react";
import type { EgressRule } from "../../lib/hostTypes";
import DestOwner from "./DestOwner";

interface Props {
  rules: EgressRule[];
  onRemove: (id: string) => void;
  onAdd: (rule: Omit<EgressRule, "id">) => void;
}

interface AddForm {
  host: string;
  port: string;
  proto: "tcp" | "udp" | "any";
  action: "allow" | "deny";
  comment: string;
}

const EMPTY_FORM: AddForm = {
  host: "",
  port: "",
  proto: "tcp",
  action: "allow",
  comment: "",
};

function RuleRow({ rule, onRemove }: { rule: EgressRule; onRemove: (id: string) => void }) {
  const [confirming, setConfirming] = useState(false);

  const handleClick = () => {
    if (confirming) {
      onRemove(rule.id);
    } else {
      setConfirming(true);
    }
  };

  return (
    <tr className="border-t border-black/5 text-sm">
      <td className="py-2 pr-3 font-mono text-[#1C1C1E] break-all">
        <div>{rule.host}</div>
        <DestOwner dest={rule.host} />
      </td>
      <td className="py-2 pr-3 text-[#636366]">{rule.port ?? "—"}</td>
      <td className="py-2 pr-3 text-[#636366] uppercase text-xs">{rule.proto}</td>
      <td className="py-2 pr-3">
        <span
          className={`text-xs font-medium px-1.5 py-0.5 rounded ${
            rule.action === "allow"
              ? "bg-green-100 text-green-700"
              : "bg-red-100 text-red-700"
          }`}
        >
          {rule.action}
        </span>
      </td>
      <td className="py-2 pr-3 text-[#636366]">{rule.comment ?? ""}</td>
      <td className="py-2 text-right">
        <button
          onClick={handleClick}
          onBlur={() => setConfirming(false)}
          className={`text-xs px-2 py-1 rounded transition-colors ${
            confirming
              ? "bg-red-600 text-white"
              : "bg-[#E5E5EA] text-[#636366] hover:bg-[#D1D1D6]"
          }`}
        >
          {confirming ? "Confirm remove?" : "Remove"}
        </button>
      </td>
    </tr>
  );
}

export default function AllowlistManager({ rules, onRemove, onAdd }: Props) {
  const [form, setForm] = useState<AddForm>(EMPTY_FORM);
  const [hostError, setHostError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.host.trim()) {
      setHostError("Host is required");
      return;
    }
    setHostError("");
    onAdd({
      host: form.host.trim(),
      port: form.port ? Number(form.port) : undefined,
      proto: form.proto,
      action: form.action,
      comment: form.comment.trim() || undefined,
    });
    setForm(EMPTY_FORM);
  };

  return (
    <div className="space-y-4">
      {/* Rules table */}
      {rules.length === 0 ? (
        <p className="text-sm text-[#636366]">No allowlist rules configured.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-[#8E8E93] uppercase tracking-wide">
                <th className="pb-2 pr-3 font-medium">Host</th>
                <th className="pb-2 pr-3 font-medium">Port</th>
                <th className="pb-2 pr-3 font-medium">Proto</th>
                <th className="pb-2 pr-3 font-medium">Action</th>
                <th className="pb-2 pr-3 font-medium">Comment</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <RuleRow key={r.id} rule={r} onRemove={onRemove} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add-rule form */}
      <form onSubmit={handleSubmit} className="space-y-3 pt-2 border-t border-black/5">
        <p className="text-xs font-semibold text-[#8E8E93] uppercase tracking-wide">Add rule</p>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {/* Host */}
          <div className="col-span-2 sm:col-span-1 space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-host">Host</label>
            <input
              id="al-host"
              type="text"
              placeholder="e.g. api.example.com"
              value={form.host}
              onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            {hostError && <p className="text-xs text-red-600">{hostError}</p>}
          </div>

          {/* Port */}
          <div className="space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-port">Port</label>
            <input
              id="al-port"
              type="number"
              min={1}
              max={65535}
              placeholder="443"
              value={form.port}
              onChange={(e) => setForm((f) => ({ ...f, port: e.target.value }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Proto */}
          <div className="space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-proto">Protocol</label>
            <select
              id="al-proto"
              value={form.proto}
              onChange={(e) => setForm((f) => ({ ...f, proto: e.target.value as AddForm["proto"] }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="any">Any</option>
            </select>
          </div>

          {/* Action */}
          <div className="space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-action">Action</label>
            <select
              id="al-action"
              value={form.action}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as AddForm["action"] }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>

          {/* Comment */}
          <div className="col-span-2 space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-comment">Comment (optional)</label>
            <input
              id="al-comment"
              type="text"
              placeholder="e.g. OpenAI API"
              value={form.comment}
              onChange={(e) => setForm((f) => ({ ...f, comment: e.target.value }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        <button
          type="submit"
          className="px-4 py-1.5 rounded-lg bg-[#1C1C1E] text-white text-sm font-medium hover:bg-black/80 transition-colors"
        >
          Add rule
        </button>
      </form>
    </div>
  );
}

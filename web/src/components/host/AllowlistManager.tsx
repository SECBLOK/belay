import { useState } from "react";
import type { EgressRule } from "../../lib/hostTypes";
import DestOwner from "./DestOwner";
import { Trans, useLingui } from "@lingui/react/macro";

// Tauri usually rejects with a plain string (the Rust command's Err
// payload); stay defensive about Error-shaped values too.
function errorMessage(e: unknown): string {
  return String((e as { message?: string } | undefined)?.message ?? e);
}

interface Props {
  rules: EgressRule[];
  onRemove: (id: string) => Promise<void>;
  onAdd: (rule: Omit<EgressRule, "id">) => Promise<void>;
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

function RuleRow({ rule, onRemove }: { rule: EgressRule; onRemove: (id: string) => Promise<void> }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  // Set only when the in-flight remove actually failed; cleared on the next
  // attempt. `onRemove` used to be called without awaiting or catching, so a
  // rejection went unhandled: the row just sat there looking untouched, which
  // is indistinguishable from the click doing nothing. The rule now stays on
  // screen (no optimistic/silent removal) and the button stays retryable.
  const [removeError, setRemoveError] = useState<string | null>(null);

  const handleClick = async () => {
    if (!confirming) {
      setConfirming(true);
      return;
    }
    setBusy(true);
    setRemoveError(null);
    try {
      await onRemove(rule.id);
      // On success the parent drops this rule from `rules`, so the row
      // unmounts - no local state to reset here.
    } catch (err) {
      setBusy(false);
      setConfirming(false);
      setRemoveError(errorMessage(err));
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
          onBlur={() => { if (!busy) setConfirming(false); }}
          disabled={busy}
          className={`text-xs px-2 py-1 rounded transition-colors disabled:opacity-60 ${
            confirming
              ? "bg-red-600 text-white"
              : "bg-[#E5E5EA] text-[#636366] hover:bg-[#D1D1D6]"
          }`}
        >
          {busy ? <Trans>Removing…</Trans> : confirming ? <Trans>Confirm remove?</Trans> : <Trans>Remove</Trans>}
        </button>
        {removeError && (
          <p role="alert" data-testid="allowlist-remove-error" className="text-xs text-red-600 mt-1">
            <Trans>Could not remove rule: {removeError}</Trans>
          </p>
        )}
      </td>
    </tr>
  );
}

export default function AllowlistManager({ rules, onRemove, onAdd }: Props) {
  const { t } = useLingui();
  const [form, setForm] = useState<AddForm>(EMPTY_FORM);
  const [hostError, setHostError] = useState("");
  const [busy, setBusy] = useState(false);
  // Set only when the in-flight add actually failed; cleared on the next
  // submit. `onAdd` used to be called without awaiting and the form cleared
  // synchronously right after, so a failure looked exactly like success -
  // the rule silently never got added. The form now keeps what the user
  // typed until the add actually succeeds.
  const [addError, setAddError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.host.trim()) {
      setHostError(t`Host is required`);
      return;
    }
    setHostError("");
    setAddError(null);
    setBusy(true);
    try {
      await onAdd({
        host: form.host.trim(),
        port: form.port ? Number(form.port) : undefined,
        proto: form.proto,
        action: form.action,
        comment: form.comment.trim() || undefined,
      });
      setForm(EMPTY_FORM);
      setBusy(false);
    } catch (err) {
      setBusy(false);
      setAddError(errorMessage(err));
    }
  };

  return (
    <div className="space-y-4">
      {/* Rules table */}
      {rules.length === 0 ? (
        <p className="text-sm text-[#636366]"><Trans>No allowlist rules configured.</Trans></p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-[var(--text-tertiary)] uppercase tracking-wide">
                <th className="pb-2 pr-3 font-medium"><Trans>Host</Trans></th>
                <th className="pb-2 pr-3 font-medium"><Trans>Port</Trans></th>
                <th className="pb-2 pr-3 font-medium"><Trans>Proto</Trans></th>
                <th className="pb-2 pr-3 font-medium"><Trans>Action</Trans></th>
                <th className="pb-2 pr-3 font-medium"><Trans>Comment</Trans></th>
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
        <p className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wide"><Trans>Add rule</Trans></p>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {/* Host */}
          <div className="col-span-2 sm:col-span-1 space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-host"><Trans>Host</Trans></label>
            <input
              id="al-host"
              type="text"
              placeholder={t`e.g. api.example.com`}
              value={form.host}
              onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            {hostError && <p className="text-xs text-red-600">{hostError}</p>}
          </div>

          {/* Port */}
          <div className="space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-port"><Trans>Port</Trans></label>
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
            <label className="text-xs text-[#636366]" htmlFor="al-proto"><Trans>Protocol</Trans></label>
            <select
              id="al-proto"
              value={form.proto}
              onChange={(e) => setForm((f) => ({ ...f, proto: e.target.value as AddForm["proto"] }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="tcp"><Trans>TCP</Trans></option>
              <option value="udp"><Trans>UDP</Trans></option>
              <option value="any"><Trans>Any</Trans></option>
            </select>
          </div>

          {/* Action */}
          <div className="space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-action"><Trans>Action</Trans></label>
            <select
              id="al-action"
              value={form.action}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as AddForm["action"] }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="allow"><Trans>Allow</Trans></option>
              <option value="deny"><Trans>Deny</Trans></option>
            </select>
          </div>

          {/* Comment */}
          <div className="col-span-2 space-y-1">
            <label className="text-xs text-[#636366]" htmlFor="al-comment"><Trans>Comment (optional)</Trans></label>
            <input
              id="al-comment"
              type="text"
              placeholder={t`e.g. OpenAI API`}
              value={form.comment}
              onChange={(e) => setForm((f) => ({ ...f, comment: e.target.value }))}
              className="w-full rounded-lg border border-black/10 px-3 py-1.5 text-sm text-[#1C1C1E] bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={busy}
          className="px-4 py-1.5 rounded-lg bg-[#1C1C1E] text-white text-sm font-medium hover:bg-black/80 transition-colors disabled:opacity-60"
        >
          {busy ? <Trans>Adding…</Trans> : <Trans>Add rule</Trans>}
        </button>
        {addError && (
          <p role="alert" data-testid="allowlist-add-error" className="text-xs text-red-600">
            <Trans>Could not add rule: {addError}</Trans>
          </p>
        )}
      </form>
    </div>
  );
}

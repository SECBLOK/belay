import { it, expect, vi, beforeEach } from "vitest";

const invoke = vi.fn();
const listen = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: any[]) => invoke(...a) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: (...a: any[]) => listen(...a) }));

import {
  getPosture,
  getFindings,
  getSessions,
  getEgress,
  getPending,
  resolve,
  setProtection,
  streamAudit,
} from "./ipc";

beforeEach(() => {
  invoke.mockReset();
  listen.mockReset();
});

it("getPosture invokes get_posture", async () => {
  invoke.mockResolvedValue({ score: 85 });
  expect((await getPosture()).score).toBe(85);
  expect(invoke).toHaveBeenCalledWith("get_posture");
});

it("getFindings invokes get_findings", async () => {
  invoke.mockResolvedValue([]);
  await getFindings();
  expect(invoke).toHaveBeenCalledWith("get_findings");
});

it("getSessions invokes get_sessions", async () => {
  invoke.mockResolvedValue({});
  await getSessions();
  expect(invoke).toHaveBeenCalledWith("get_sessions");
});


it("getEgress invokes get_egress", async () => {
  invoke.mockResolvedValue({});
  await getEgress();
  expect(invoke).toHaveBeenCalledWith("get_egress");
});

it("getPending invokes get_pending and falls back to [] when it rejects", async () => {
  invoke.mockRejectedValue(new Error("not implemented yet"));
  expect(await getPending()).toEqual([]);
  expect(invoke).toHaveBeenCalledWith("get_pending");
});

it("getPending unwraps the daemon { pending: [...] } object shape", async () => {
  const entry = { id: "p1", session: "claude-code", tool: "Bash", input: {}, reason: "r", rule: "x", created_ms: 1 };
  invoke.mockResolvedValue({ pending: [entry] });
  expect(await getPending()).toEqual([entry]);
  expect(invoke).toHaveBeenCalledWith("get_pending");
});

it("getPending falls back to [] when the object has no pending key", async () => {
  invoke.mockResolvedValue({});
  expect(await getPending()).toEqual([]);
});

it("resolve invokes respond_approval with explicit scope", async () => {
  invoke.mockResolvedValue({});
  await resolve("a1", "allow", "always");
  expect(invoke).toHaveBeenCalledWith("respond_approval", {
    id: "a1",
    decision: "allow",
    scope: "always",
  });
});

it("resolve defaults scope to once", async () => {
  invoke.mockResolvedValue({});
  await resolve("a2", "deny");
  expect(invoke).toHaveBeenCalledWith("respond_approval", {
    id: "a2",
    decision: "deny",
    scope: "once",
  });
});

it("setProtection invokes set_protection", async () => {
  invoke.mockResolvedValue({});
  await setProtection(true);
  expect(invoke).toHaveBeenCalledWith("set_protection", { on: true });
});

it("streamAudit subscribes to audit-event and forwards e.payload", async () => {
  let handler: ((e: any) => void) | undefined;
  const unlisten = vi.fn();
  listen.mockImplementation((_name: string, cb: (e: any) => void) => {
    handler = cb;
    return Promise.resolve(unlisten);
  });
  const rows: any[] = [];
  const teardown = streamAudit((r) => rows.push(r));
  expect(listen).toHaveBeenCalledWith("audit-event", expect.any(Function));
  handler!({ payload: { event: "exec", verdict: "deny" } });
  expect(rows).toEqual([{ event: "exec", verdict: "deny" }]);
  teardown();
  await Promise.resolve();
  expect(unlisten).toHaveBeenCalled();
});

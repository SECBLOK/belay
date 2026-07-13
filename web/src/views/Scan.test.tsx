import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";
import Scan from "./Scan";

vi.mock("../lib/api", () => ({
  runScan: vi.fn(),
}));

import { runScan } from "../lib/api";

const mockRunScan = runScan as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockRunScan.mockReset();
});

it("renders idle state with explanatory text", () => {
  render(<Scan />);
  expect(screen.getByPlaceholderText(/Downloads/i)).toBeTruthy();
  expect(screen.getByRole("button", { name: /^scan$/i })).toBeTruthy();
  // Idle copy mentions checking a folder
  expect(screen.getByText(/check a folder/i)).toBeTruthy();
});

it("disables scan button when input is empty", () => {
  render(<Scan />);
  const btn = screen.getByRole("button", { name: /^scan$/i }) as HTMLButtonElement;
  expect(btn.disabled).toBe(true);
});

it("calls runScan with the entered target and shows recommendation banner + humanized finding", async () => {
  mockRunScan.mockResolvedValue({
    score: 80,
    severity: "HIGH",
    recommendation: "CAUTION",
    findings: [
      { rule_id: "secrets.aws_credentials", severity: "HIGH", reason: "AWS key found [file: .env]" },
    ],
  });

  render(<Scan />);
  const input = screen.getByPlaceholderText(/Downloads/i);
  fireEvent.change(input, { target: { value: "/home/user/some-repo" } });

  const btn = screen.getByRole("button", { name: /^scan$/i }) as HTMLButtonElement;
  expect(btn.disabled).toBe(false);

  await act(async () => { fireEvent.click(btn); });

  expect(mockRunScan).toHaveBeenCalledWith("/home/user/some-repo");

  // Recommendation banner
  await waitFor(() => expect(screen.getByText(/be careful/i)).toBeTruthy());

  // Humanized finding (NOT raw rule_id as primary label)
  expect(screen.getByText(/tried to read your credentials or passwords/i)).toBeTruthy();

  // Raw rule id must NOT appear as plain text node
  expect(screen.queryByText("secrets.aws_credentials")).toBeNull();

  // Reason text shown
  expect(screen.getByText(/AWS key found/i)).toBeTruthy();
});

it("shows SAFE banner with reassuring message when findings are empty", async () => {
  mockRunScan.mockResolvedValue({
    score: 0,
    severity: "INFO",
    recommendation: "SAFE",
    findings: [],
  });

  render(<Scan />);
  fireEvent.change(screen.getByPlaceholderText(/Downloads/i), { target: { value: "~/safe-project" } });

  await act(async () => { fireEvent.click(screen.getByRole("button", { name: /^scan$/i })); });

  await waitFor(() => expect(screen.getByText(/looks safe/i)).toBeTruthy());
  expect(screen.getByText(/no risky patterns found/i)).toBeTruthy();
});

it("shows DO_NOT_INSTALL red banner for dangerous result", async () => {
  mockRunScan.mockResolvedValue({
    score: 100,
    severity: "CRITICAL",
    recommendation: "DO_NOT_INSTALL",
    findings: [
      { rule_id: "rce.shell_exec", severity: "CRITICAL", reason: "Runs arbitrary shell [file: install.sh]" },
    ],
  });

  render(<Scan />);
  fireEvent.change(screen.getByPlaceholderText(/Downloads/i), { target: { value: "~/malware-repo" } });

  await act(async () => { fireEvent.click(screen.getByRole("button", { name: /^scan$/i })); });

  await waitFor(() => expect(screen.getByText(/do not install/i)).toBeTruthy());
  expect(screen.getByText(/tried to run system code/i)).toBeTruthy();
});

it("shows loading state while scan is running", async () => {
  let resolveScan: (v: any) => void;
  mockRunScan.mockReturnValue(new Promise((r) => { resolveScan = r; }));

  render(<Scan />);
  fireEvent.change(screen.getByPlaceholderText(/Downloads/i), { target: { value: "/some/path" } });
  fireEvent.click(screen.getByRole("button", { name: /^scan$/i }));

  // Loading state text and disabled button (both the button label and the panel say "Scanning")
  await waitFor(() => expect(screen.getAllByText(/scanning/i).length).toBeGreaterThanOrEqual(1));
  const btn = screen.getByRole("button", { name: /scanning/i }) as HTMLButtonElement;
  expect(btn.disabled).toBe(true);

  // Resolve to clean up
  await act(async () => { resolveScan!({ score: 0, severity: "INFO", recommendation: "SAFE", findings: [] }); });
  await waitFor(() => expect(screen.getByText(/looks safe/i)).toBeTruthy());
});

it("shows desktop-only note (not a raw error) when runScan rejects with desktop-only error", async () => {
  mockRunScan.mockRejectedValue(new Error("runScan: Available in the Belay desktop app"));

  render(<Scan />);
  fireEvent.change(screen.getByPlaceholderText(/Downloads/i), { target: { value: "/some/path" } });

  await act(async () => { fireEvent.click(screen.getByRole("button", { name: /^scan$/i })); });

  await waitFor(() => expect(screen.getAllByText(/desktop app/i).length).toBeGreaterThanOrEqual(1));
  // Must NOT show raw error prefix as visible text
  expect(screen.queryByText(/runScan:/)).toBeNull();
});

it("submits via Enter key", async () => {
  mockRunScan.mockResolvedValue({
    score: 0,
    severity: "INFO",
    recommendation: "SAFE",
    findings: [],
  });

  render(<Scan />);
  const input = screen.getByPlaceholderText(/Downloads/i);
  fireEvent.change(input, { target: { value: "/some/path" } });

  await act(async () => { fireEvent.keyDown(input, { key: "Enter", code: "Enter" }); });

  await waitFor(() => expect(mockRunScan).toHaveBeenCalledWith("/some/path"));
});

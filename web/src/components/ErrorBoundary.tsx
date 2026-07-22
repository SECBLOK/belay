// ErrorBoundary — a React class boundary so a single sub-view that throws (a JS
// exception OR a render fault, e.g. WebKitGTK compositing glitches inside a VM)
// can NEVER blank the entire application. Without this, an exception in any view
// propagates to the root and unmounts the whole tree, leaving a blank window.
//
// Place one at the app root (catch-all) AND around each swappable sub-view so a
// crash stays localized: the surrounding chrome (nav/header) keeps working and
// the user sees a readable error with a "Try again" reset instead of nothing.

import { Component, type ErrorInfo, type ReactNode } from "react";

export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Short human label for the region, e.g. "Firewall setup". */
  label?: string;
  /**
   * Resets the boundary when this value changes (e.g. the active section key),
   * so navigating to a different view clears a previous view's error.
   */
  resetKey?: unknown;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export default class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidUpdate(prev: ErrorBoundaryProps) {
    // Clear the captured error when the caller swaps resetKey (e.g. nav change).
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface to the console for debugging; never rethrow.
    // eslint-disable-next-line no-console
    console.error(`Belay: error in ${this.props.label ?? "view"}:`, error, info);
  }

  private reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const region = this.props.label ?? "This view";
    return (
      <div
        role="alert"
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-2"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium">{region} hit an unexpected error</p>
        <p className="font-mono text-xs text-[var(--text-tertiary)] break-words">
          {error.message || String(error)}
        </p>
        <button
          onClick={this.reset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          Try again
        </button>
      </div>
    );
  }
}

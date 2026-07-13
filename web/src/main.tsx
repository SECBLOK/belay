import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './desktop/tokens.css'
import App from './App.tsx'
import TrayPopover from './components/TrayPopover.tsx'
import Toast from './components/Toast.tsx'
import ErrorBoundary from './components/ErrorBoundary.tsx'

document.documentElement.setAttribute("data-theme", "dark")

// Branch on the URL hash: the tray popover window loads index.html#popover and
// the bottom-right notification window loads index.html#toast. The main window
// (and all existing App tests that render <App/> directly) are unaffected —
// this is purely additive.
const hash = typeof window !== "undefined" ? window.location.hash : "";
const isPopover = hash.includes("popover");
const isToast = hash.includes("toast");

function Root() {
  if (isToast) return <Toast />;
  if (isPopover) return <TrayPopover />;
  return <App />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* Root catch-all: even a top-level crash shows a message, never a blank. */}
    <ErrorBoundary label="Belay">
      <Root />
    </ErrorBoundary>
  </StrictMode>,
)

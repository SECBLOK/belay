import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './desktop/tokens.css'
import './design/liquid-glass.css'
import App from './App.tsx'
import TrayPopover from './components/TrayPopover.tsx'
import Toast from './components/Toast.tsx'
import ErrorBoundary from './components/ErrorBoundary.tsx'
import { I18nProvider } from '@lingui/react'
import { i18n } from '@lingui/core'
import { activateLocale, initLocale } from './lib/i18n'

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

// Activate English synchronously so the first paint is never blank, then ask
// the daemon for the operator's actual choice. Rendering is NOT blocked on that
// round-trip: if the daemon is down the GUI still comes up, in English.
activateLocale('en')

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* Root catch-all: even a top-level crash shows a message, never a blank. */}
    <ErrorBoundary label="Belay">
      <I18nProvider i18n={i18n}>
        <Root />
      </I18nProvider>
    </ErrorBoundary>
  </StrictMode>,
)

void initLocale()

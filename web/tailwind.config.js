/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}", "../desktop/index.html"],
  theme: {
    extend: {
      colors: {
        window: "var(--bg-window)", elevated: "var(--bg-elevated)",
        "text-primary": "var(--text-primary)", "text-secondary": "var(--text-secondary)",
        accent: "var(--accent)",
        "status-protected": "var(--status-protected)", "status-monitoring": "var(--status-monitoring)",
        "status-action": "var(--status-action)", "status-blocked": "var(--status-blocked)",
      },
      borderRadius: { card: "14px", modal: "20px", pill: "999px" },
      fontSize: { hero: "2.75rem", title1: "1.5rem", body: ".9375rem", mono: ".8125rem" },
      fontFamily: { mono: ['"SF Mono"', "ui-monospace", "monospace"] },
      transitionTimingFunction: { apple: "cubic-bezier(.32,.72,0,1)" },
    },
  },
  plugins: [],
}

import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        kahu: {
          bg: "#0a0e17",
          card: "#141b2d",
          elevated: "#1a2340",
          border: "#1e2a45",
          accent: "#3b82f6",
        },
        sev: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#3b82f6",
          info: "#64748b",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "system-ui",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
} satisfies Config;

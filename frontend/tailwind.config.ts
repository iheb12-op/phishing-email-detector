import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./features/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // SOC dashboard palette - defined now so every later phase
        // (findings, severity badges, charts) stays visually consistent.
        soc: {
          bg: "#0b0f14",
          panel: "#121822",
          panelBorder: "#1f2a37",
          text: "#e6edf3",
          muted: "#8b98a5",
        },
        severity: {
          critical: "#e11d48",
          high: "#f97316",
          medium: "#eab308",
          low: "#3b82f6",
          safe: "#22c55e",
        },
      },
    },
  },
  plugins: [],
};

export default config;

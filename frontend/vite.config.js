import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";
import { buildCsp } from "./csp.js";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const apiBase = env.VITE_API_BASE_URL || "http://localhost:8000";
  return {
    plugins: [
      react(),
      {
        name: "inject-csp",
        apply: "build",
        transformIndexHtml(html) {
          return html.replace(
            "<head>",
            `<head>\n    <meta http-equiv="Content-Security-Policy" content="${buildCsp(apiBase)}" />`
          );
        }
      }
    ],
    build: {
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: { react: ["react", "react-dom", "react-router-dom"], charts: ["recharts"] }
        }
      }
    },
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.{js,jsx}"]
    }
  };
});

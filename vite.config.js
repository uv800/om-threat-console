import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api/* to the OM backend (server.js) on :8787,
// so the browser never sees your Anthropic API key.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
    },
  },
});

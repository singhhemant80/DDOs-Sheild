import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development the API runs on 127.0.0.1:8080; in production nginx serves dist/ and proxies /api.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8080", ws: true, changeOrigin: false },
    },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 900 },
});

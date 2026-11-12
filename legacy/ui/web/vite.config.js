import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

// Output goes straight into the Python server's static folder. No inline scripts
// (the server's Content-Security-Policy allows only same-origin script files).
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: process.env.UI_OUT_DIR || fileURLToPath(new URL('../server/static', import.meta.url)),
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
})

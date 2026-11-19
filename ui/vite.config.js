import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The React app is a static bundle served by FastAPI in production (built to
// web/app). In dev, Vite serves it and proxies /api to the running backend so
// there is no CORS surface and no separate base URL to configure.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.CLOCKWORK_API || 'http://localhost:8899',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../web/app',
    emptyOutDir: true,
  },
})

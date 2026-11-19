import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  server: {
    port: 3000,
    proxy: {
      '/': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        bypass(req) {
          if (!req.url || !req.url.includes('action=')) {
            return req.url;
          }
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const backend = 'http://127.0.0.1:8080';
const proxy = Object.fromEntries(
  ['/api', '/pki', '/issuers', '/crl', '/ocsp', '/tsa', '/health'].map((path) => [
    path,
    { target: backend, changeOrigin: false },
  ]),
);

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': new URL('./src', import.meta.url).pathname } },
  server: {
    port: 5173,
    strictPort: true,
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      'pki.localhost',
      'pki-console.localhost',
      'pki.altasci.com',
      'pki-console.altasci.com',
    ],
    proxy,
  },
  preview: {
    port: 4173,
    strictPort: true,
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      'pki.localhost',
      'pki-console.localhost',
      'pki.altasci.com',
      'pki-console.altasci.com',
    ],
  },
  build: {
    target: 'baseline-widely-available',
    sourcemap: false,
    manifest: true,
    chunkSizeWarningLimit: 600,
  },
});

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'

// The Flask API serves HTTPS by default, so the dev server must do the same.
// The session cookie is Secure + SameSite=None, and a browser will not send a
// Secure cookie from an http:// page to an https:// API - the whole stack has
// to be on TLS or authentication silently breaks.
//
// Both processes share one certificate pair in the project root. Create it with:
//     python scripts/generate_cert.py
const certPath = path.resolve(import.meta.dirname, '..', 'cert.pem')
const keyPath = path.resolve(import.meta.dirname, '..', 'key.pem')
const httpsAvailable = fs.existsSync(certPath) && fs.existsSync(keyPath)

if (!httpsAvailable) {
  console.warn(
    '\n[vite] cert.pem / key.pem not found in the project root - falling back to plain HTTP.' +
      '\n       Run "python scripts/generate_cert.py" from the project root to enable HTTPS.\n',
  )
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Reading the files (rather than passing paths) keeps the config working
    // regardless of which directory npm was invoked from.
    https: httpsAvailable
      ? { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }
      : undefined,
  },
})

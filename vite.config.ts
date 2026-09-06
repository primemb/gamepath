import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: './',
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/engine/target/**', '**/relay/target/**', '**/service/target/**', '**/vendor/**', '**/work/**', '**/.secrets/**'] },
  },
})

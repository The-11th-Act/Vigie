import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiTarget = process.env.VITE_API_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],

  build: {
    // Une seule requete de 640 ko bloque le premier rendu, et la moindre
    // modification du code applicatif invalide le cache des dependances.
    // Separer les vendors permet au navigateur de garder React et Recharts
    // en cache entre deux deploiements.
    // Vite 8 bundles with Rolldown, which only takes the function form.
    rolldownOptions: {
      output: {
        // Module ids use forward slashes on every platform.
        manualChunks(id) {
          if (/\/node_modules\/(react|react-dom|react-router|react-router-dom|scheduler|@tanstack\/[^/]+)\//.test(id)) {
            return 'react'
          }
          if (/\/node_modules\/(recharts|recharts-scale|d3-[^/]+|victory-vendor)\//.test(id)) {
            return 'charts'
          }
          return undefined
        },
      },
    },
    // Utile pour lire une stacktrace de production sans exposer les sources :
    // les .map sont generes mais peuvent etre servis uniquement en interne.
    sourcemap: true,
  },

  server: {
    port: 5173,
    // Proxy du serveur de developpement uniquement. En production, c'est
    // frontend/nginx.conf qui route /api vers l'API.
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})

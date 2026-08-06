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
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
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

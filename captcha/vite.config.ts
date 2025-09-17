import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'
import tailwindcss from '@tailwindcss/vite'
// @ts-ignore TODO
import { fileURLToPath, URL } from 'node:url'


// https://vite.dev/config/
export default defineConfig({
  plugins: [
    preact(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      // @ts-ignore TODO
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  build:{
    assetsDir: '__pingoo/captcha/assets',
    rollupOptions: {
      output: {
        // we use the full hashes to reduces the risk of collision with assets cached for long time
        assetFileNames(_chunkInfo) {
          return `__pingoo/captcha/assets/[name]-[hash:21][extname]`;
        },
        chunkFileNames(_chunkInfo) {
          return `__pingoo/captcha/assets/[name]-[hash:21].js`;
        },
        entryFileNames(_chunkInfo) {
          return `__pingoo/captcha/assets/[name]-[hash:21].js`;
        },
      }
    },
  },
  esbuild: {
    legalComments: 'none',
  },
})

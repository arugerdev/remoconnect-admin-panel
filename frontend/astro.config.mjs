import { defineConfig } from 'astro/config';

import tailwind from '@astrojs/tailwind';

// https://astro.build/config
export default defineConfig({
  integrations: [tailwind()],
  vite: {
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:3030', // Puerto de tu servidor Express
          changeOrigin: true,
          ws: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  },
});
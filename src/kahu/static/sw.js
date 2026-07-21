const CACHE_NAME = 'kahu-v1';
const SHELL_FILES = [
  '/',
  '/static/styles.css',
  '/static/app.js',
  '/static/manifest.json',
];

// Install — cache the app shell
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first for API, cache first for shell
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API calls: network only, queue if offline
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request).catch(() => {
        // If it's a swipe POST and we're offline, queue it
        if (e.request.method === 'POST' && url.pathname.includes('/swipe')) {
          return new Response(JSON.stringify({
            queued: true,
            message: 'Offline. Your action will sync when reconnected.'
          }), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
        // For GET, try cache
        return caches.match(e.request);
      })
    );
    return;
  }

  // Shell files: cache first, then network
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request))
  );
});

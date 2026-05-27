// Service Worker minimal pour fonctionnement offline.
// Cache les assets statiques (sauf scams.json qui doit rester à jour).

const CACHE = 'sentinel-v3';
const ASSETS = [
  './',
  './index.html',
  './app.js',
  './rules.js',
  './manifest.json',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // scams.json : always network first (la donnée doit être fraîche)
  if (url.pathname.endsWith('/scams.json')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // Assets statiques : cache first
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request))
  );
});

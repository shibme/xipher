const CACHE_NAME = 'xipher-cache';
const urlsToCache = [
  '/',
  '/assets/images/github.svg',
  '/assets/images/logo.svg',
  '/css/app.css',
  '/css/base.css',
  '/css/objects.css',
  '/index.html',
  '/js/datastore.js',
  '/js/main.js',
  '/lib/StreamSaver/mitm.html',
  '/lib/StreamSaver/StreamSaver.js',
  '/lib/StreamSaver/sw.js',
  '/js/ui.js',
  '/js/xipher.js',
  '/wasm/wasm_exec.js',
  '/wasm/xipher.wasm',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
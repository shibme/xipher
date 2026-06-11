// The release workflow rewrites "xipher-cache" to "xipher-v<release-version>"
// (see .github/workflows/release.yaml), so the cache name tracks the release and
// busts on every version. Leave this placeholder as-is; do not hand-version it.
const CACHE_NAME = 'xipher-cache';
const urlsToCache = [
  '/',
  '/index.html',
  '/resolve/',
  '/resolve/index.html',
  '/js/resolve.js',
  '/manifest.json',
  '/assets/images/github.svg',
  '/assets/images/logo.svg',
  '/css/app.css',
  '/css/base.css',
  '/css/objects.css',
  '/js/datastore.js',
  '/js/main.js',
  '/js/passkey.js',
  '/js/provider.js',
  '/js/ui.js',
  '/js/xipher.js',
  '/lib/StreamSaver/mitm.html',
  '/lib/StreamSaver/StreamSaver.js',
  '/lib/StreamSaver/sw.js',
  '/wasm/wasm_exec.js',
  '/wasm/xipher.wasm',
  '/docs/',
  '/docs/index.html',
  '/docs/docs.css',
  '/docs/docs.js',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      // Use individual puts so one missing asset doesn't fail the whole install.
      return Promise.all(
        urlsToCache.map(url =>
          cache.add(url).catch(err => console.warn('Cache skip:', url, err))
        )
      );
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') {
    return;
  }
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});

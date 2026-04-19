/* LA DIOSA — Service Worker (network-first for HTML/API, cache-first for static) */
const VERSION = 'ladiosa-v2';
const STATIC_CACHE = 'ladiosa-static-' + VERSION;
const RUNTIME_CACHE = 'ladiosa-runtime-' + VERSION;

const PRECACHE = [
  '/',
  '/manifest.webmanifest',
  '/assets/icons/LaDiosa.png',
  '/assets/icons/LaDiosa_arch.png',
  '/assets/icons/LaDiosa_unicolor.png',
  '/offline.html'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((c) => c.addAll(PRECACHE).catch(() => null))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => !k.endsWith(VERSION)).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

function isNavigation(req) {
  return req.mode === 'navigate' || (req.method === 'GET' && req.headers.get('accept')?.includes('text/html'));
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Don't intercept cross-origin requests — let the browser handle them
  // directly (CDNs for fonts, scripts, etc). Intercepting would route the
  // fetch through the SW under the page's CSP connect-src.
  if (url.origin !== location.origin) {
    return;
  }

  // Never cache API / auth / admin
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/rss') || url.pathname.startsWith('/share')) {
    return; // fall through to network
  }

  // HTML: network-first, fall back to cached index or offline page
  if (isNavigation(req)) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() =>
          caches.match(req).then((r) => r || caches.match('/') || caches.match('/offline.html'))
        )
    );
    return;
  }

  // Static: cache-first
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (res.ok && (url.origin === location.origin)) {
          const copy = res.clone();
          caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      }).catch(() => cached);
    })
  );
});

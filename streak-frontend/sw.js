const CACHE_NAME = "streak-tracker-static-v8";
const STATIC_ASSETS = [
  "./",
  "./index.html",
  "./login.html",
  "./register.html",
  "./dashboard.html",
  "./forgot-password.html",
  "./reset-password.html",
  "./verify-otp.html",
  "./verify-email.html",
  "./manifest.json",
  "./pwa.js",
  "./assets/icons/favicon-32.png",
  "./assets/icons/apple-touch-icon.png",
  "./assets/icons/icon-192.png",
  "./assets/icons/icon-512.png",
  "./assets/icons/icon-maskable-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await cache.addAll(STATIC_ASSETS);
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      );
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") {
    return;
  }

  const requestUrl = new URL(request.url);
  if (requestUrl.origin !== self.location.origin) {
    return;
  }

  // Never cache API responses; always hit network for fresh streak data.
  if (requestUrl.pathname.startsWith("/api/")) {
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const networkResponse = await fetch(request);
          const cache = await caches.open(CACHE_NAME);
          cache.put(request, networkResponse.clone());
          return networkResponse;
        } catch {
          const cachedPage = await caches.match(request);
          if (cachedPage) {
            return cachedPage;
          }
          return caches.match("./index.html");
        }
      })()
    );
    return;
  }

  event.respondWith(
    (async () => {
      const cachedResponse = await caches.match(request);
      if (cachedResponse) {
        return cachedResponse;
      }

      try {
        const networkResponse = await fetch(request);
        if (networkResponse && networkResponse.status === 200) {
          const cache = await caches.open(CACHE_NAME);
          cache.put(request, networkResponse.clone());
        }
        return networkResponse;
      } catch {
        return new Response("Offline", {
          status: 503,
          statusText: "Offline",
          headers: { "Content-Type": "text/plain" },
        });
      }
    })()
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const targetPath = event.notification?.data?.url || "./dashboard.html";

  event.waitUntil(
    (async () => {
      const targetUrl = new URL(targetPath, self.location.origin).href;
      const clientsList = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });

      for (const client of clientsList) {
        const clientUrl = new URL(client.url);
        if (clientUrl.origin !== self.location.origin) {
          continue;
        }

        if ("focus" in client) {
          await client.focus();
        }
        if ("navigate" in client && client.url !== targetUrl) {
          await client.navigate(targetUrl);
        }
        return;
      }

      if (self.clients.openWindow) {
        await self.clients.openWindow(targetUrl);
      }
    })()
  );
});

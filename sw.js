```javascript
const CACHE_NAME = "netsentry-cache-v1";

self.addEventListener("install", (event) => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        (async () => {
            await self.clients.claim();
        })()
    );
});

self.addEventListener("fetch", (event) => {
    // Keep API data fresh; don't cache API responses.
    if (event.request.url.includes("/api/")) {
        return;
    }

    // Let the browser load other resources normally.
});
```
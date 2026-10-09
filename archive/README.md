# Archive

Files that are not used by BinTalk, kept for reference only.

- `mobile-scaffold/`: the start of a React Native app. It does not build: `App.tsx` imports
  screens and a Redux store that were never written. The supported client is the web app in
  [`web/`](../web/). A mobile client would need its own WebSocket client (BinTalk does not use
  socket.io) built on the API described in the main README.
- `nginx.conf.unused`: an older gateway configuration that is not mounted by Docker Compose and
  proxies plain HTTP to the HTTPS-only API. The active configuration is
  [`nginx/nginx.conf`](../nginx/nginx.conf).

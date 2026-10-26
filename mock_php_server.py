#!/usr/bin/env python3
"""
Sahte "PHP sunucusu" — PHP Envanter Tarayıcı'yı denemek için.
Gerçek PHP KURULU OLMADAN, tarayıcının aradığı başlıkları ve yolları taklit eder.

Kullanım:
    python mock_php_server.py [port] [mod]

port : varsayılan 8080
mod  :
    vuln   (varsayılan) -> X-Powered-By: PHP/8.2.1  -> ZAFİYETLİ tespit edilmeli
    safe                -> PHP/8.4.27               -> GÜVENLİ tespit edilmeli
    hidden              -> X-Powered-By YOK, sadece PHPSESSID -> "Gizli";
                           derin modda phpinfo'dan sürüm (8.2.1) bulunup düzeltilir

Taklit edilen derin-tarama yolları (hepsi "açıkta" -> güvenlik bulgusu üretir):
    /phpinfo.php /info.php  (PHP Version + phpinfo())
    /.env  /.git/config  /composer.json  /_ignition/health-check  /_profiler
Kök sayfa WordPress generator etiketi içerir (uygulama parmak izi testi).

YALNIZCA 127.0.0.1'e bağlanır (kendi makinen). Tüm ağa açmak için 3. argüman 'all'.
Durdurmak için Ctrl+C.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
MODE = sys.argv[2] if len(sys.argv) > 2 else "vuln"
BIND = "0.0.0.0" if (len(sys.argv) > 3 and sys.argv[3] == "all") else "127.0.0.1"

VERSION = "8.4.27" if MODE == "safe" else "8.2.1"
EXPOSE_PHP = MODE != "hidden"        # hidden modda X-Powered-By gönderme

ROOT_HTML = f"""<!doctype html><html><head>
<meta name="generator" content="WordPress 6.5.2" />
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
</head><body><h1>Mock PHP site ({MODE})</h1></body></html>"""

PHPINFO_HTML = f"""<!doctype html><html><head><title>phpinfo()</title></head><body>
<h1 class="p">PHP Version {VERSION}</h1>
<table><tr><td class="e">System</td><td class="v">Linux mock 5.15</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/php.ini</td></tr></table>
phpinfo()</body></html>"""

ENV_TXT = ("APP_NAME=MockApp\nAPP_ENV=production\nAPP_DEBUG=true\n"
           "APP_KEY=base64:ZmFrZWtleWZha2VrZXlmYWtla2V5MTIzNDU2Nzg=\n"
           "DB_CONNECTION=mysql\nDB_PASSWORD=supersecret123\n")
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = git@x\n"
COMPOSER_JSON = '{"name":"mock/app","require":{"php":"^8.2","laravel/framework":"^11.0"}}'
IGNITION_JSON = '{"can_execute_commands":true,"status":"ok"}'
PROFILER_HTML = "<html><head><title>Symfony Profiler</title></head><body>profiler/latest</body></html>"

ROUTES = {
    "/phpinfo.php": ("text/html", PHPINFO_HTML),
    "/info.php":    ("text/html", PHPINFO_HTML),
    "/phpinfo":     ("text/html", PHPINFO_HTML),
    "/.env":        ("text/plain", ENV_TXT),
    "/.git/config": ("text/plain", GIT_CONFIG),
    "/composer.json": ("application/json", COMPOSER_JSON),
    "/_ignition/health-check": ("application/json", IGNITION_JSON),
    "/_profiler":   ("text/html", PROFILER_HTML),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.52"           # -> "Server: Apache/2.4.52"
    sys_version = ""                            # nötr; '(Ubuntu)' yazsan distro->MUHTEMELEN olur

    def _php_headers(self):
        if EXPOSE_PHP:
            self.send_header("X-Powered-By", f"PHP/{VERSION}")
        self.send_header("Set-Cookie", "PHPSESSID=mockabc123; path=/")

    def log_message(self, fmt, *args):         # sessiz log
        pass

    def do_HEAD(self):
        self.send_response(200)
        self._php_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            ctype, body = "text/html; charset=utf-8", ROOT_HTML
        elif path in ROUTES:
            ctype, body = ROUTES[path]
        else:
            self.send_response(404)
            self._php_headers()
            self.end_headers()
            return
        data = body.encode("utf-8")
        self.send_response(200)
        self._php_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"Mock PHP sunucusu calisiyor:  http://{BIND}:{PORT}/   (mod={MODE}, surum={VERSION})")
    print(f"Tarayicida tara:  {('127.0.0.1' if BIND=='127.0.0.1' else BIND)}/32   port {PORT}   (Derin tarama acik)")
    print("Durdurmak icin Ctrl+C")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nKapatiliyor…")
        srv.shutdown()


if __name__ == "__main__":
    main()

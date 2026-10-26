# PHP Inventory Scanner

A small desktop tool that sweeps an **internal** network for HTTP/HTTPS services, detects the
**PHP version** from HTTP headers (and, in deep mode, from the page body and known paths), and
classifies each host as safe / vulnerable / EOL against a built-in patch and EOL table.

- **No dependencies** — Python standard library only (Tkinter GUI included).
- **Single file / single exe** — build one portable `.exe`, no install, works offline.
- **Bilingual UI** — English (default) and Turkish, switch top-right (EN/TR).

> ⚠️ **Authorized use only.** This is a vulnerability-auditing tool. Scan only networks you own or
> are explicitly authorized to test. Deep mode actively probes paths such as `/.env`, `/.git/` and
> `phpinfo.php`. Do **not** point it at hosts you do not control.

## Features

- Concurrent TCP/HTTP sweep of one or more CIDR ranges (safety cap blocks huge blocks like `0.0.0.0/0`).
- Version detection from `Server` / `X-Powered-By` headers, `PHPSESSID` hint, and HEAD→GET fallback.
- **Deep scan (optional, slower):**
  - App/framework fingerprint: WordPress, Laravel, Joomla, Drupal, Symfony.
  - Version from an exposed `phpinfo()` page when headers hide it.
  - Security findings: exposed `phpinfo()`, `.env`, `.git/config`, `composer.json`,
    Laravel Ignition, Symfony profiler.
- EOL date + affected-CVE hints from an offline table.
- Live, color-coded results table.
- Export to **Excel (.xlsx)**, **CSV**, **JSON**, and a self-contained **HTML report**.
- **Compare** against a previous JSON scan (new / fixed / disappeared / still-vulnerable).

## Requirements

- Python **3.9+** (uses `concurrent.futures` `cancel_futures`, `addinfourl.status`).
- Tkinter (bundled with the standard CPython installer on Windows/macOS).

## Run from source

```bash
python php_tarayici.py
```

## Build a standalone .exe (Windows)

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name "PHP-Tarayici" php_tarayici.py
```

The binary is produced at `dist/PHP-Tarayici.exe`.

## Try it against a mock server (no real PHP needed)

`mock_php_server.py` emulates a PHP host so you can verify detection locally:

```bash
python mock_php_server.py 8080 vuln     # modes: vuln | safe | hidden
```

Then in the scanner set **Subnet** `127.0.0.1/32`, **Ports** `8080`, enable **Deep scan**, and Start.

## Notes

- The EOL dates and CVE references come from an **offline table** in the source; verify them against
  the official php.net release notes and update as needed.
- TLS verification is intentionally relaxed in the scanner (self-signed internal hosts). That code
  path is scanner-only — do not reuse it in a general-purpose client.

---

**Türkçe:** İç ağda HTTP/HTTPS servislerini tarayıp PHP sürümünü tespit eden, güvenli/zafiyetli/EOL
olarak sınıflandıran bağımlılıksız masaüstü aracı (TR/EN arayüz). Yalnızca **yetkili** ağlarda kullanın.

# PHP Inventory Scanner

**English** | [Türkçe](#türkçe)

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

# Türkçe

[English](#php-inventory-scanner) | **Türkçe**

**İç** ağdaki HTTP/HTTPS servislerini tarayan; **PHP sürümünü** HTTP başlıklarından (derin modda
ayrıca sayfa gövdesi ve bilinen yollardan) tespit eden; her host'u yerleşik yama ve EOL tablosuna
göre güvenli / zafiyetli / EOL olarak sınıflandıran küçük bir masaüstü aracı.

- **Bağımlılık yok** — yalnız Python standart kütüphanesi (Tkinter arayüz dahil).
- **Tek dosya / tek exe** — taşınabilir tek bir `.exe` derlenir, kurulum gerekmez, çevrimdışı çalışır.
- **Çift dilli arayüz** — İngilizce (varsayılan) ve Türkçe, sağ üstten değiştirilir (EN/TR).

> ⚠️ **Yalnızca yetkili kullanım.** Bu bir zafiyet denetim aracıdır. Sadece sahibi olduğun ya da
> test etmeye açıkça yetkili olduğun ağları tara. Derin mod `/.env`, `/.git/` ve `phpinfo.php` gibi
> yolları aktif olarak yoklar. Kontrolünde **olmayan** hostlara **yöneltme**.

## Özellikler

- Bir veya birden çok CIDR aralığında eşzamanlı TCP/HTTP taraması (güvenlik freni `0.0.0.0/0` gibi
  devasa blokları engeller).
- `Server` / `X-Powered-By` başlıklarından, `PHPSESSID` ipucundan ve HEAD→GET geri dönüşünden sürüm tespiti.
- **Derin tarama (isteğe bağlı, daha yavaş):**
  - Uygulama/çerçeve parmak izi: WordPress, Laravel, Joomla, Drupal, Symfony.
  - Başlıklar sürümü gizlediğinde, açıkta kalan bir `phpinfo()` sayfasından sürüm.
  - Güvenlik bulguları: açıkta `phpinfo()`, `.env`, `.git/config`, `composer.json`,
    Laravel Ignition, Symfony profiler.
- Çevrimdışı tablodan EOL tarihi + etkilenen CVE ipuçları.
- Canlı, renk kodlu sonuç tablosu.
- **Excel (.xlsx)**, **CSV**, **JSON** ve kendi kendine yeten **HTML rapor** dışa aktarma.
- Önceki bir JSON taramasıyla **karşılaştırma** (yeni / yamalanmış / kaybolan / hâlâ zafiyetli).

## Gereksinimler

- Python **3.9+** (`concurrent.futures` `cancel_futures`, `addinfourl.status` kullanılır).
- Tkinter (Windows/macOS'taki standart CPython kurulumuyla birlikte gelir).

## Kaynaktan çalıştırma

```bash
python php_tarayici.py
```

## Tek başına .exe derleme (Windows)

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name "PHP-Tarayici" php_tarayici.py
```

İkili dosya `dist/PHP-Tarayici.exe` altında oluşur.

## Sahte sunucuyla deneme (gerçek PHP gerekmez)

`mock_php_server.py`, bir PHP host'unu taklit eder; tespiti yerelde doğrulayabilirsin:

```bash
python mock_php_server.py 8080 vuln     # modlar: vuln | safe | hidden
```

Sonra tarayıcıda **Alt ağ** `127.0.0.1/32`, **Port** `8080` gir, **Derin tarama**yı işaretle ve başlat.

## Notlar

- EOL tarihleri ve CVE referansları kaynaktaki **çevrimdışı tablodandır**; resmî php.net sürüm
  notlarıyla doğrula ve gerektikçe güncelle.
- Tarayıcıda TLS doğrulaması bilinçli olarak gevşetilmiştir (self-signed iç hostlar). Bu kod yolu
  yalnızca tarayıcıya özeldir — genel amaçlı bir istemcide yeniden kullanma.

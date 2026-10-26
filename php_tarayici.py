#!/usr/bin/env python3
"""
PHP Inventory Scanner / PHP Envanter Tarayıcı — Desktop (Tkinter)
Detects PHP version from HTTP headers (and, in deep mode, page body + known paths) on an
internal network and classifies it against CVE-2026-109618 / CVE-2026-109619 (2026-10-21
patches) and php.net EOL dates.

No dependencies — Python standard library only (tkinter included).
Languages: English (default) + Turkish, switchable top-right (EN/TR).

Run:       python php_tarayici.py
Single exe: pyinstaller --onefile --noconsole --name "PHP-Tarayici" php_tarayici.py
"""
import concurrent.futures
import csv
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import threading
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from datetime import date, datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_VERSION = "1.5.1"

# =========================== DÜZELTME TABLOLARI / DATA ===========================

SAFE_VERSIONS = {            # branch -> patched minimum
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
EOL_BRANCHES = {(8, 0), (8, 1)}
CVE_IDS = ["CVE-2026-109618", "CVE-2026-109619"]

# branch -> security-support end (ISO). 8.2+ are ESTIMATES — verify against php.net!
PHP_EOL = {
    (7, 0): "2019-01-10", (7, 1): "2019-12-01", (7, 2): "2020-11-30",
    (7, 3): "2021-12-06", (7, 4): "2022-11-28",
    (8, 0): "2023-11-26", (8, 1): "2025-12-31",
    (8, 2): "2026-12-31", (8, 3): "2027-12-31",
    (8, 4): "2028-12-31", (8, 5): "2029-12-31",
}
TODAY = date.today().isoformat()

PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?([^\s,;)]*)", re.I)
DISTRO_RE = re.compile(r"ubuntu|debian|deb\d+u|red ?hat|rhel|centos|rocky|alma|\.el\d|suse", re.I)
PHP_COOKIES = ("phpsessid", "laravel_session")
UA = "Internal-SecAudit/1.0"

GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
WP_VER_RE = re.compile(r"WordPress\s*([\d.]+)", re.I)
JOOMLA_VER_RE = re.compile(r"Joomla!?\s*([\d.]*)", re.I)
DRUPAL_VER_RE = re.compile(r"Drupal\s*([\d.]*)", re.I)
PHPINFO_VER_RE = re.compile(r"PHP Version\s*(?:<[^>]*>\s*)*([\d]+\.[\d]+\.[\d]+)", re.I)

# Status codes (language-neutral). Display text + color + vuln-flag derived from these.
STATUS_TAG = {"safe": "safe", "vuln": "vuln", "vuln_eol": "vuln", "maybe": "maybe",
              "manual_nopatch": "warn", "manual_unknown": "warn", "hidden": "warn", "nophp": "none"}
STATUS_VULN = {"vuln", "vuln_eol", "maybe"}

COL_KEYS = ["ip", "port", "proto", "code", "server", "xpb",
            "version", "app", "distro", "status", "detail"]
COL_WIDTH = {"ip": 110, "port": 50, "proto": 55, "code": 48, "server": 200, "xpb": 140,
             "version": 130, "app": 120, "distro": 55, "status": 270, "detail": 320}
COL_ANCHOR = {"port": "center", "proto": "center", "code": "center", "distro": "center"}
COL_STRETCH = {"server", "status", "detail"}
PUBLIC_FIELDS = ["ip", "port", "proto", "code", "server", "xpb", "version",
                 "mmp", "app", "distro", "status", "findings"]

RISK_COLORS = {
    "vuln":  ("#ffd4d4", "#8a0000"),
    "maybe": ("#ffe3c2", "#8a4b00"),
    "warn":  ("#fff6c2", "#6b5900"),
    "safe":  ("#d7f5dd", "#0a5a24"),
    "none":  ("#eef0f2", "#555555"),
}

SOFT_WARN_TARGETS = 20_000
HARD_CAP_TARGETS = 500_000

# =============================== TRANSLATIONS ===============================

T = {
    "en": {
        "win_title": "PHP Inventory Scanner",
        "settings": "Scan Settings",
        "subnet": "Subnet(s):", "ports": "Ports:", "workers": "Workers:",
        "ctimeout": "Connect timeout (s):", "htimeout": "HTTP timeout (s):",
        "start": "▶  Start Scan", "stop": "■  Stop", "export": "⤓  Export",
        "html": "🖹  HTML Report", "compare": "⇄  Compare…", "clear": "Clear",
        "deep": "Deep scan (slow): app fingerprint + phpinfo/.env/.git/debug security findings",
        "hint": "Separate multiple networks with comma/space — e.g. 192.168.1.0/24, 10.0.10.0/24"
                "   ·   huge blocks like 0.0.0.0/0 are blocked",
        "c_ip": "IP Address", "c_port": "Port", "c_proto": "Protocol", "c_code": "HTTP Code",
        "c_server": "Server", "c_xpb": "X-Powered-By", "c_version": "PHP Version",
        "c_app": "Application", "c_distro": "Distro Package", "c_status": "Risk Status",
        "c_detail": "CVE / EOL / Finding",
        "ready": "Ready.", "scanning": "Scanning…", "scanning_deep": "Scanning… (deep)",
        "stopping": "Stopping…", "stopped": "Stopped.", "done": "Completed.",
        "summary": "Services: {n}   |   Vulnerable/likely: {v}   |   Hidden: {h}   |   Findings: {f}",
        "err_input": "Input error", "big_title": "Large scan",
        "big_msg": "{n:,} targets will be scanned (roughly ≤ {m:.0f} min).\nContinue?",
        "scan_err": "Scan error", "save_title": "Save report as", "save_err": "Save error",
        "ok": "Done", "saved": "{n} rows saved:\n{f}",
        "html_title": "Save HTML report as", "html_saved_q": "Report saved:\n{f}\n\nOpen in browser?",
        "cmp_pick": "Pick previous scan (JSON) — save one via Export → .json",
        "cmp_read_err": "Could not read JSON:\n{e}", "cmp_title": "Comparison",
        "cmp_msg": ("Previous: {o} services   →   Now: {c} services\n\n"
                    "Newly vulnerable : {nv}\nPatched          : {fx}\n"
                    "Still vulnerable : {sv}\nNew service      : {ap}\n"
                    "Disappeared      : {dp}\n\n'HTML Report' includes a change section."),
        "ft_xlsx": "Excel workbook", "ft_csv": "CSV file", "ft_json": "JSON (for comparison)",
        "ft_html": "HTML report", "ft_all": "All files",
        "err_subnet_empty": "Enter at least one subnet (CIDR).",
        "err_subnet_bad": "Invalid subnet {tok!r}: {e}",
        "err_port_bad": "Invalid port: {p!r}", "err_port_empty": "Enter at least one port.",
        "err_num": "Workers/timeouts must be numeric.", "err_workers": "Workers must be at least 1.",
        "err_timeouts": "Timeouts must be positive.",
        "no_targets": "No addresses to scan (block too small).",
        "too_big": ("Scan too large: {n:,} targets (cap {cap:,}).\n\n"
                    "Blocks like 0.0.0.0/0 or /8 cover the whole internet / a huge range — "
                    "impossible and unauthorized.\n\nEnter the subnet(s) you actually manage "
                    "(e.g. 192.168.1.0/24) or split the scan."),
        # status
        "s_safe": "SAFE (patched)", "s_vuln": "VULNERABLE (update needed)",
        "s_vuln_eol": "VULNERABLE (EOL - no upstream patch)",
        "s_vuln_eol_distro": " | distro package: check vendor support",
        "s_maybe": "LIKELY VULNERABLE (check distro backport)",
        "s_manual_nopatch": "Manual check (patch version not visible)",
        "s_manual_unknown": "Manual check (unknown branch)",
        "s_hidden": "PHP detected (version hidden - check on server)",
        "s_nophp": "No PHP detected (expose_php=Off?)",
        "v_hidden": "Hidden", "yes": "Yes",
        "eol_past": "EOL", "eol_future": "support ends", "cve": "CVE: ",
        "unsupported": "Unsupported version — exposed to all later CVEs",
        "f_phpinfo": "phpinfo() exposed ({p})", "f_env": ".env exposed (secret leak)",
        "f_git": ".git/config exposed", "f_composer": "composer.json exposed",
        "f_ignition": "Laravel Ignition exposed (debug mode)",
        "f_profiler": "Symfony profiler exposed (debug)",
        # report
        "r_title": "PHP Inventory &amp; Vulnerability Report", "r_scope": "Scope",
        "r_card_services": "Services", "r_card_vuln": "Vulnerable", "r_card_maybe": "Likely",
        "r_card_hidden": "Hidden/Manual", "r_card_safe": "Safe", "r_card_find": "Security findings",
        "r_dist": "Risk distribution", "r_diff": "Change vs previous scan",
        "r_new_vuln": "Newly vulnerable", "r_fixed": "Patched / fixed",
        "r_appeared": "Newly seen service", "r_disappeared": "Disappeared service",
        "r_still": "Still vulnerable", "r_more": "… +{n} more",
        "r_findings": "Security findings ({n} hosts)", "r_all": "All services ({n})",
        "r_foot": ("EOL/CVE data is from an offline table; verify against php.net release notes. "
                   "This report is for authorized internal auditing only."),
        "l_vuln": "Vulnerable", "l_maybe": "Likely", "l_warn": "Hidden/Manual",
        "l_safe": "Safe", "l_none": "No PHP",
    },
    "tr": {
        "win_title": "PHP Envanter Tarayıcı",
        "settings": "Tarama Ayarları",
        "subnet": "Alt ağ(lar):", "ports": "Portlar:", "workers": "İşçi:",
        "ctimeout": "Bağ. zaman aşımı (sn):", "htimeout": "HTTP zaman aşımı (sn):",
        "start": "▶  Taramayı Başlat", "stop": "■  Durdur", "export": "⤓  Dışa Aktar",
        "html": "🖹  HTML Rapor", "compare": "⇄  Karşılaştır…", "clear": "Temizle",
        "deep": "Derin tarama (yavaş): uygulama parmak izi + phpinfo/.env/.git/debug güvenlik bulguları",
        "hint": "Birden çok ağ için virgül/boşlukla ayırın — örn. 192.168.1.0/24, 10.0.10.0/24"
                "   ·   0.0.0.0/0 gibi devasa bloklar engellenir",
        "c_ip": "IP Adresi", "c_port": "Port", "c_proto": "Protokol", "c_code": "HTTP Kodu",
        "c_server": "Server", "c_xpb": "X-Powered-By", "c_version": "PHP Sürümü",
        "c_app": "Uygulama", "c_distro": "Distro Paketi", "c_status": "Risk Durumu",
        "c_detail": "CVE / EOL / Bulgu",
        "ready": "Hazır.", "scanning": "Taranıyor…", "scanning_deep": "Taranıyor… (derin)",
        "stopping": "Durduruluyor…", "stopped": "Durduruldu.", "done": "Tamamlandı.",
        "summary": "Servis: {n}   |   Zafiyetli/muhtemel: {v}   |   Gizli: {h}   |   Bulgu: {f}",
        "err_input": "Giriş hatası", "big_title": "Büyük tarama",
        "big_msg": "{n:,} hedef taranacak (kabaca ≤ {m:.0f} dk sürebilir).\nDevam edilsin mi?",
        "scan_err": "Tarama hatası", "save_title": "Rapor olarak kaydet", "save_err": "Kaydetme hatası",
        "ok": "Tamam", "saved": "{n} satır kaydedildi:\n{f}",
        "html_title": "HTML rapor olarak kaydet", "html_saved_q": "Rapor kaydedildi:\n{f}\n\nTarayıcıda açılsın mı?",
        "cmp_pick": "Önceki tarama (JSON) seç — Dışa Aktar → .json ile kaydedebilirsin",
        "cmp_read_err": "JSON okunamadı:\n{e}", "cmp_title": "Karşılaştırma",
        "cmp_msg": ("Önceki: {o} servis   →   Şimdi: {c} servis\n\n"
                    "Yeni zafiyetli : {nv}\nYamalanmış     : {fx}\n"
                    "Hâlâ zafiyetli : {sv}\nYeni servis    : {ap}\n"
                    "Kaybolan servis: {dp}\n\n'HTML Rapor' çıktısına değişim bölümü eklenir."),
        "ft_xlsx": "Excel çalışma kitabı", "ft_csv": "CSV dosyası", "ft_json": "JSON (karşılaştırma için)",
        "ft_html": "HTML rapor", "ft_all": "Tüm dosyalar",
        "err_subnet_empty": "En az bir alt ağ (CIDR) girin.",
        "err_subnet_bad": "Geçersiz alt ağ {tok!r}: {e}",
        "err_port_bad": "Geçersiz port: {p!r}", "err_port_empty": "En az bir port girin.",
        "err_num": "İşçi/zaman aşımı sayısal olmalı.", "err_workers": "İşçi sayısı en az 1 olmalı.",
        "err_timeouts": "Zaman aşımları pozitif olmalı.",
        "no_targets": "Taranacak adres yok (girdiğin blok çok küçük).",
        "too_big": ("Çok büyük tarama: {n:,} hedef (üst sınır {cap:,}).\n\n"
                    "0.0.0.0/0 veya /8 gibi bloklar tüm interneti ya da devasa bir alanı kapsar; "
                    "hem imkânsız hem de izinsiz tarama olur.\n\nLütfen gerçekten yönettiğin "
                    "subnet(ler)i gir (örn. 192.168.1.0/24) veya taramayı küçük parçalara böl."),
        "s_safe": "GÜVENLİ (Yamalı)", "s_vuln": "ZAFİYETLİ (Güncellenmeli)",
        "s_vuln_eol": "ZAFİYETLİ (EOL - upstream yama yok)",
        "s_vuln_eol_distro": " | distro paketi: vendor desteğini kontrol et",
        "s_maybe": "MUHTEMELEN ZAFİYETLİ (distro backport kontrol et)",
        "s_manual_nopatch": "Manuel Kontrol (patch sürümü görünmüyor)",
        "s_manual_unknown": "Manuel Kontrol (bilinmeyen branch)",
        "s_hidden": "PHP Tespit Edildi (Sürüm Gizli - Sunucuda kontrol et)",
        "s_nophp": "PHP Tespit Edilmedi (expose_php=Off olabilir)",
        "v_hidden": "Gizli", "yes": "Evet",
        "eol_past": "EOL", "eol_future": "destek sonu", "cve": "CVE: ",
        "unsupported": "Destek dışı sürüm — tüm sonraki CVE'lere açık",
        "f_phpinfo": "phpinfo() açıkta ({p})", "f_env": ".env açıkta (sır sızıntısı)",
        "f_git": ".git/config açıkta", "f_composer": "composer.json açıkta",
        "f_ignition": "Laravel Ignition açıkta (debug modu)",
        "f_profiler": "Symfony profiler açıkta (debug)",
        "r_title": "PHP Envanter &amp; Zafiyet Raporu", "r_scope": "Kapsam",
        "r_card_services": "Servis", "r_card_vuln": "Zafiyetli", "r_card_maybe": "Muhtemel",
        "r_card_hidden": "Gizli/Manuel", "r_card_safe": "Güvenli", "r_card_find": "Güvenlik bulgusu",
        "r_dist": "Risk dağılımı", "r_diff": "Önceki taramaya göre değişim",
        "r_new_vuln": "Yeni zafiyetli", "r_fixed": "Yamalanmış / düzelen",
        "r_appeared": "Yeni görünen servis", "r_disappeared": "Kaybolan servis",
        "r_still": "Hâlâ zafiyetli", "r_more": "… +{n} daha",
        "r_findings": "Güvenlik bulguları ({n} host)", "r_all": "Tüm servisler ({n})",
        "r_foot": ("EOL/CVE verileri çevrimdışı tablodandır; php.net sürüm notlarıyla doğrulanmalıdır. "
                   "Bu rapor yalnız yetkili iç ağ denetimi içindir."),
        "l_vuln": "Zafiyetli", "l_maybe": "Muhtemel", "l_warn": "Gizli/Manuel",
        "l_safe": "Güvenli", "l_none": "PHP yok",
    },
}


def tr(lang, key, **kw):
    table = T.get(lang) or T["en"]
    s = table.get(key)
    if s is None:
        s = T["en"].get(key, key)
    return s.format(**kw) if kw else s


# =============================== TARAMA ÇEKİRDEĞİ ===============================

def host_count(net):
    if net.prefixlen == net.max_prefixlen:
        return 1
    if net.prefixlen == net.max_prefixlen - 1:
        return 2
    return net.num_addresses - 2


def make_ctx():
    """Old servers should still handshake (old PHP = usually old TLS). Scanner-only."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    return ctx


CTX = make_ctx()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=CTX),
        NoRedirect(),
    )


def port_open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def fetch(opener, url, method, timeout):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def http_get(opener, url, timeout, cap=30000):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers, r.read(cap).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(cap).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, e.headers, body
    except Exception:
        return None, None, ""


def classify_code(major, minor, patch, distro):
    branch = (major, minor)
    if major < 8 or branch in EOL_BRANCHES:
        return "vuln_eol"
    if patch is None:
        return "manual_nopatch"
    if branch in SAFE_VERSIONS:
        if (major, minor, patch) >= SAFE_VERSIONS[branch]:
            return "safe"
        return "maybe" if distro else "vuln"
    return "manual_unknown"


def analyze(ip, port, proto, code, headers):
    server = headers.get("Server", "") or ""
    xpb = ", ".join(headers.get_all("X-Powered-By") or [])
    cookies = " ".join(headers.get_all("Set-Cookie") or []).lower()
    blob = f"{server} {xpb}"
    distro = bool(DISTRO_RE.search(blob))

    m = PHP_RE.search(blob)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        patch = int(m.group(3)) if m.group(3) else None
        version = f"{major}.{minor}" + (f".{patch}" if patch is not None else "") + m.group(4)
        scode = classify_code(major, minor, patch, distro)
        mmp = [major, minor, patch]
        base = 2
    elif "php" in xpb.lower() or any(c in cookies for c in PHP_COOKIES):
        version, scode, mmp, base = None, "hidden", None, 1
    else:
        version, scode, mmp, base = None, "nophp", None, 0

    return {
        "ip": ip, "port": port, "proto": proto, "code": code,
        "server": server or "-", "xpb": xpb or "-",
        "version": version, "mmp": mmp, "app": "-", "distro": distro,
        "status": scode, "findings": [],
        "_score": base * 10 + (1 if code < 400 else 0),
    }


def fingerprint_app(headers, body):
    hdr = " ".join(f"{k}: {v}" for k, v in headers.items()) if headers else ""
    cookies = " ".join(headers.get_all("Set-Cookie") or []).lower() if headers else ""
    gen = ""
    mg = GEN_RE.search(body)
    if mg:
        gen = mg.group(1)

    if "wp-content" in body or "wp-includes" in body or "wordpress" in gen.lower():
        mv = WP_VER_RE.search(gen) or WP_VER_RE.search(body)
        return "WordPress" + (f" {mv.group(1)}" if mv else "")
    if "drupal" in gen.lower() or "X-Drupal" in hdr or "X-Generator: Drupal" in hdr:
        mv = DRUPAL_VER_RE.search(gen)
        return "Drupal" + (f" {mv.group(1)}" if mv and mv.group(1) else "")
    if "joomla" in gen.lower() or "/administrator/" in body or "com_content" in body:
        mv = JOOMLA_VER_RE.search(gen)
        return "Joomla" + (f" {mv.group(1)}" if mv and mv.group(1) else "")
    if "laravel_session" in cookies:
        return "Laravel"
    if "x-debug-token" in hdr.lower() or "sf_redirect" in cookies:
        return "Symfony"
    if gen:
        return gen.split(",")[0].strip()[:40]
    return "-"


def deep_probe(ip, port, proto, opener, timeout):
    """Deep mode: fingerprint, phpinfo version, security findings.
    Returns (app, version_tuple|None, findings[[code, extra], ...])."""
    base = f"{proto}://{ip}:{port}"
    _, hdr, body = http_get(opener, base + "/", timeout, cap=40000)
    app = fingerprint_app(hdr, body) if hdr is not None else "-"
    findings, ver = [], None

    for p in ("/phpinfo.php", "/info.php", "/phpinfo"):
        c, _, b = http_get(opener, base + p, timeout, cap=20000)
        if c == 200 and ("phpinfo()" in b or "PHP Version" in b):
            findings.append(["phpinfo", p])
            mv = PHPINFO_VER_RE.search(b)
            if mv:
                ver = tuple(int(x) for x in mv.group(1).split("."))
            break

    c, _, b = http_get(opener, base + "/.env", timeout, cap=8000)
    if c == 200 and re.search(r"(?m)^\s*[A-Z][A-Z0-9_]*\s*=", b) and \
            any(k in b for k in ("APP_", "DB_", "SECRET", "PASSWORD", "KEY")):
        findings.append(["env", ""])

    c, _, b = http_get(opener, base + "/.git/config", timeout, cap=4000)
    if c == 200 and "[core]" in b:
        findings.append(["git", ""])

    c, _, b = http_get(opener, base + "/composer.json", timeout, cap=8000)
    if c == 200 and '"require"' in b:
        findings.append(["composer", ""])

    c, _, b = http_get(opener, base + "/_ignition/health-check", timeout, cap=4000)
    if c == 200 and ("can_execute" in b or '"status"' in b.lower()):
        findings.append(["ignition", ""])

    c, _, b = http_get(opener, base + "/_profiler", timeout, cap=4000)
    if c == 200 and ("symfony profiler" in b.lower() or "profiler/latest" in b.lower()):
        findings.append(["profiler", ""])

    return app, ver, findings


def check_target(ip, port, cfg, stop_event):
    if stop_event.is_set():
        return None
    ip = str(ip)
    if not port_open(ip, port, cfg["connect_timeout"]):
        return None

    opener = build_opener()
    protos = ["https", "http"] if port in (443, 8443) else ["http", "https"]
    best = None
    for proto in protos:
        if stop_event.is_set():
            break
        url = f"{proto}://{ip}:{port}/"
        for method in ("HEAD", "GET"):
            try:
                code, headers = fetch(opener, url, method, cfg["http_timeout"])
            except Exception:
                continue
            row = analyze(ip, port, proto, code, headers)
            if best is None or row["_score"] > best["_score"]:
                best = row
            if row["_score"] >= 20:
                break
        if best is not None and best["_score"] >= 20:
            break

    if best is not None and cfg.get("deep") and not stop_event.is_set():
        try:
            app, ver, findings = deep_probe(ip, port, best["proto"], opener, cfg["http_timeout"])
        except Exception:
            app, ver, findings = "-", None, []
        best["app"] = app
        if ver and best["status"] in ("hidden", "nophp"):
            major, minor = ver[0], ver[1]
            patch = ver[2] if len(ver) > 2 else None
            best["version"] = ".".join(str(x) for x in ver)
            best["mmp"] = [major, minor, patch]
            best["status"] = classify_code(major, minor, patch, best.get("distro", False))
        if findings:
            best["findings"] = findings
    return best


# ---- rendering (language-aware) ----

def status_tag(code):
    return STATUS_TAG.get(code, "none")


def is_vuln(r):
    s = r.get("status", "")
    if s in STATUS_TAG:
        return s in STATUS_VULN
    return ("ZAFİYETLİ" in s) or ("VULN" in s.upper())   # eski/metin JSON uyumu


def status_text(r, lang):
    code = r.get("status", "nophp")
    if code == "vuln_eol":
        s = tr(lang, "s_vuln_eol")
        return s + tr(lang, "s_vuln_eol_distro") if r.get("distro") else s
    return tr(lang, "s_" + code) if ("s_" + code) in T["en"] else str(code)


def version_text(r, lang):
    code = r.get("status")
    if code == "hidden":
        return tr(lang, "v_hidden")
    if code == "nophp":
        return "-"
    return r.get("version") or "-"


def distro_text(r, lang):
    return tr(lang, "yes") if r.get("distro") else "-"


def _norm_findings(findings):
    for item in findings or []:
        if isinstance(item, (list, tuple)):
            yield (item[0], item[1] if len(item) > 1 else "")
        else:
            yield (str(item), "")


def finding_text(code, extra, lang):
    key = "f_" + code
    if code == "phpinfo":
        return tr(lang, key, p=extra or "")
    return tr(lang, key) if key in T["en"] else code


def detail_text(r, lang):
    parts = []
    mmp = r.get("mmp")
    if mmp:
        major, minor = mmp[0], mmp[1]
        patch = mmp[2] if len(mmp) > 2 else None
        branch = (major, minor)
        eol = PHP_EOL.get(branch)
        if eol:
            label = tr(lang, "eol_past") if eol <= TODAY else tr(lang, "eol_future")
            parts.append(f"{major}.{minor} {label}: {eol}")
        if branch in SAFE_VERSIONS and patch is not None and (major, minor, patch) < SAFE_VERSIONS[branch]:
            parts.append(tr(lang, "cve") + ", ".join(CVE_IDS))
        elif major < 8 or branch in EOL_BRANCHES:
            parts.append(tr(lang, "unsupported"))
    fnd = list(_norm_findings(r.get("findings")))
    if fnd:
        parts.append("; ".join(finding_text(c, e, lang) for c, e in fnd))
    return " | ".join(parts)


def row_values(r, lang):
    return [r.get("ip", ""), r.get("port", ""), r.get("proto", ""), r.get("code", ""),
            r.get("server", "-"), r.get("xpb", "-"), version_text(r, lang),
            r.get("app", "-"), distro_text(r, lang), status_text(r, lang), detail_text(r, lang)]


def localized_header(lang):
    return [tr(lang, "c_" + k) for k in COL_KEYS]


def sort_results(results):
    def key(r):
        try:
            return (ipaddress.IPv4Address(str(r["ip"])), int(r["port"]))
        except Exception:
            return (ipaddress.IPv4Address("255.255.255.255"), 0)
    return sorted(results, key=key)


# ===================== XLSX YAZICI (bağımlılıksız — salt stdlib) =====================

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_XLSX_NUMERIC = {1, 3}
_XLSX_WIDTHS = [15, 7, 8, 7, 28, 20, 18, 16, 8, 38, 46]
TAG_TO_XF = {"vuln": 2, "maybe": 3, "warn": 4, "safe": 5, "none": 6}

_CONTENT_TYPES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    '</Types>')
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    '</Relationships>')
_WORKBOOK = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<sheets><sheet name="PHP" sheetId="1" r:id="rId1"/></sheets></workbook>')
_WB_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    '</Relationships>')
_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
    '<fills count="8">'
    '<fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF305496"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFD4D4"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFE3C2"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF6C2"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFD7F5DD"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFEEF0F2"/></patternFill></fill>'
    '</fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="7">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'
    '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="6" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="7" borderId="0" xfId="0" applyFill="1"/>'
    '</cellXfs>'
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    '</styleSheet>')


def _xlsx_escape(s):
    s = str(s)
    s = "".join(ch for ch in s if ch in "\t\n\r" or ord(ch) >= 0x20)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xlsx_cell(ref, xf, value, numeric):
    if numeric:
        try:
            return f'<c r="{ref}" s="{xf}"><v>{int(value)}</v></c>'
        except (TypeError, ValueError):
            pass
    return (f'<c r="{ref}" s="{xf}" t="inlineStr"><is>'
            f'<t xml:space="preserve">{_xlsx_escape(value)}</t></is></c>')


def write_xlsx(path, rows, lang):
    header = localized_header(lang)
    ncol = len(header)
    last = _ALPHA[ncol - 1]
    n = len(rows) + 1
    cols_xml = "".join(f'<col min="{i+1}" max="{i+1}" width="{w}" customWidth="1"/>'
                       for i, w in enumerate(_XLSX_WIDTHS[:ncol]))
    head_xml = "".join(
        f'<c r="{_ALPHA[i]}1" s="1" t="inlineStr"><is>'
        f'<t xml:space="preserve">{_xlsx_escape(h)}</t></is></c>'
        for i, h in enumerate(header))

    body = []
    for ridx, r in enumerate(rows, start=2):
        xf = TAG_TO_XF.get(status_tag(r.get("status", "")), 6)
        cells = "".join(_xlsx_cell(f"{_ALPHA[ci]}{ridx}", xf, v, ci in _XLSX_NUMERIC)
                        for ci, v in enumerate(row_values(r, lang)))
        body.append(f'<row r="{ridx}">{cells}</row>')

    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<dimension ref="A1:{last}{n}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'<cols>{cols_xml}</cols>'
        f'<sheetData><row r="1">{head_xml}</row>{"".join(body)}</sheetData>'
        f'<autoFilter ref="A1:{last}{n}"/>'
        '</worksheet>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("xl/workbook.xml", _WORKBOOK)
        z.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        z.writestr("xl/styles.xml", _STYLES)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


# ===================== DIFF =====================

def compute_diff(old_results, new_results):
    def key(r):
        return (str(r["ip"]), int(r["port"]))
    old = {key(r): r for r in old_results}
    new = {key(r): r for r in new_results}
    out = {"new_vuln": [], "fixed": [], "disappeared": [], "appeared": [], "still_vuln": []}
    for k, r in new.items():
        o = old.get(k)
        if o is None:
            out["appeared"].append(r)
            if is_vuln(r):
                out["new_vuln"].append(r)
        elif is_vuln(r) and not is_vuln(o):
            out["new_vuln"].append(r)
        elif is_vuln(r) and is_vuln(o):
            out["still_vuln"].append(r)
        elif is_vuln(o) and not is_vuln(r):
            out["fixed"].append(r)
    for k, o in old.items():
        if k not in new:
            out["disappeared"].append(o)
    return out


# ===================== HTML RAPOR =====================

def _h(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_HTML_STYLE = """
:root{--bg:#f4f6f8;--card:#fff;--ink:#1f2933;--mut:#6b7280;--line:#e3e7eb;--accent:#305496}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Segoe UI,Arial,sans-serif;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px;border-bottom:2px solid var(--line);padding-bottom:6px}
.sub{color:var(--mut);margin:0 0 18px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0 4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.bar{display:flex;height:26px;border-radius:7px;overflow:hidden;border:1px solid var(--line);margin:6px 0}
.bar .seg{display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;min-width:0}
.legend{display:flex;flex-wrap:wrap;gap:14px;color:var(--mut);font-size:12px;margin-top:4px}
.legend span{display:inline-flex;align-items:center;gap:6px}.dot{width:12px;height:12px;border-radius:3px;display:inline-block}
table{border-collapse:collapse;width:100%;background:var(--card);font-size:12.5px;margin-top:6px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--accent);color:#fff;position:sticky;top:0}
ul.find{margin:6px 0;padding-left:20px}ul.find li{margin:3px 0}
.diffgrid{display:flex;flex-wrap:wrap;gap:12px}
.diffbox{flex:1;min-width:200px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.diffbox h3{margin:0 0 6px;font-size:14px}.diffbox .big{font-size:22px;font-weight:700}
.diffbox small{color:var(--mut);display:block;word-break:break-all}
.foot{color:var(--mut);font-size:12px;margin-top:26px}
@media print{body{background:#fff;padding:0}.card,.diffbox,table{break-inside:avoid}}
"""


def generate_html(results, scope_text, lang, diff=None):
    rows = sort_results(results)
    tags = [status_tag(r.get("status", "")) for r in rows]
    c = Counter(tags)
    total = len(rows)
    find_hosts = [r for r in rows if r.get("findings")]

    cards = [("r_card_services", total, "var(--ink)"),
             ("r_card_vuln", c["vuln"], RISK_COLORS["vuln"][1]),
             ("r_card_maybe", c["maybe"], RISK_COLORS["maybe"][1]),
             ("r_card_hidden", c["warn"], RISK_COLORS["warn"][1]),
             ("r_card_safe", c["safe"], RISK_COLORS["safe"][1]),
             ("r_card_find", len(find_hosts), RISK_COLORS["vuln"][1])]
    cards_html = "".join(
        f'<div class="card"><div class="n" style="color:{col}">{n}</div>'
        f'<div class="l">{_h(tr(lang, k))}</div></div>' for k, n, col in cards)

    seg = ""
    for t in ("vuln", "maybe", "warn", "safe", "none"):
        n = c[t]
        if n and total:
            pct = n * 100.0 / total
            bg, fg = RISK_COLORS[t]
            seg += (f'<div class="seg" style="width:{pct:.2f}%;background:{bg};color:{fg}" '
                    f'title="{_h(tr(lang, "l_" + t))}: {n}">{n if pct > 5 else ""}</div>')
    legend = "".join(
        f'<span><i class="dot" style="background:{RISK_COLORS[t][0]};'
        f'border:1px solid {RISK_COLORS[t][1]}"></i>{_h(tr(lang, "l_" + t))} ({c[t]})</span>'
        for t in ("vuln", "maybe", "warn", "safe", "none"))

    diff_html = ""
    if diff:
        def box(title_key, items, col):
            sample = "".join(f"<small>{_h(r['ip'])}:{_h(r['port'])}</small>" for r in items[:12])
            more = f"<small>{_h(tr(lang, 'r_more', n=len(items)-12))}</small>" if len(items) > 12 else ""
            return (f'<div class="diffbox"><h3>{_h(tr(lang, title_key))}</h3>'
                    f'<div class="big" style="color:{col}">{len(items)}</div>{sample}{more}</div>')
        diff_html = (f'<h2>{_h(tr(lang, "r_diff"))}</h2><div class="diffgrid">'
                     + box("r_new_vuln", diff["new_vuln"], RISK_COLORS["vuln"][1])
                     + box("r_fixed", diff["fixed"], RISK_COLORS["safe"][1])
                     + box("r_appeared", diff["appeared"], "var(--accent)")
                     + box("r_disappeared", diff["disappeared"], "var(--mut)")
                     + box("r_still", diff["still_vuln"], RISK_COLORS["maybe"][1])
                     + '</div>')

    find_html = ""
    if find_hosts:
        lis = ""
        for r in find_hosts:
            fx = "; ".join(_h(finding_text(co, ex, lang)) for co, ex in _norm_findings(r.get("findings")))
            lis += f'<li><b>{_h(r["ip"])}:{_h(r["port"])}</b> ({_h(r.get("app", "-"))}) — {fx}</li>'
        find_html = f'<h2>{_h(tr(lang, "r_findings", n=len(find_hosts)))}</h2><ul class="find">{lis}</ul>'

    head = "".join(f"<th>{_h(x)}</th>" for x in localized_header(lang))
    trs = ""
    for r in rows:
        bg, fg = RISK_COLORS[status_tag(r.get("status", ""))]
        tds = "".join(f"<td>{_h(v)}</td>" for v in row_values(r, lang))
        trs += f'<tr style="background:{bg};color:{fg}">{tds}</tr>'

    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    return (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{tr(lang, 'r_title')}</title><style>{_HTML_STYLE}</style></head><body>"
            f"<h1>{tr(lang, 'r_title')}</h1>"
            f"<p class='sub'>{_h(tr(lang, 'r_scope'))}: <b>{_h(scope_text)}</b> &nbsp;·&nbsp; {now} &nbsp;·&nbsp; v{APP_VERSION}</p>"
            f"<div class='cards'>{cards_html}</div>"
            f"<h2>{_h(tr(lang, 'r_dist'))}</h2><div class='bar'>{seg}</div><div class='legend'>{legend}</div>"
            f"{diff_html}{find_html}"
            f"<h2>{_h(tr(lang, 'r_all', n=total))}</h2>"
            f"<table><thead><tr>{head}</tr></thead><tbody>{trs}</tbody></table>"
            f"<p class='foot'>{_h(tr(lang, 'r_foot'))}</p></body></html>")


# =============================== MASAÜSTÜ ARAYÜZ ===============================

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = "en"
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.results = []
        self.scope_text = ""
        self.diff = None
        self.total = 0
        self.done = 0
        self._state_key = ""
        self._scan_deep = False

        try:
            ttk.Style(self).theme_use("clam")
        except tk.TclError:
            pass
        self.geometry("1320x700")
        self.minsize(1000, 560)

        self._build_langbar()
        self._build_controls()
        self._build_table()
        self._build_statusbar()

        self._refresh_lang()
        self._apply_language()
        self.after(100, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _t(self, key, **kw):
        return tr(self.lang, key, **kw)

    # ----------------------------- arayüz kurulum -----------------------------

    def _build_langbar(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=(8, 0))
        seg = ttk.Frame(top)
        seg.pack(side="right")
        self.lang_lbls = {}
        for i, (code, txt) in enumerate((("en", "EN"), ("tr", "TR"))):
            lbl = tk.Label(seg, text=txt, width=4, padx=6, pady=3, cursor="hand2",
                           relief="solid", bd=1)
            lbl.grid(row=0, column=i)
            lbl.bind("<Button-1>", lambda e, c=code: self._set_lang(c))
            self.lang_lbls[code] = lbl

    def _build_controls(self):
        self.lf = ttk.LabelFrame(self, text="", padding=10)
        self.lf.pack(fill="x", padx=10, pady=(6, 6))
        f = self.lf

        self.var_subnet = tk.StringVar(value="192.168.1.0/24")
        self.var_ports = tk.StringVar(value="80,443,8080,8443")
        self.var_workers = tk.StringVar(value="50")
        self.var_ctimeout = tk.StringVar(value="1.5")
        self.var_htimeout = tk.StringVar(value="3")
        self.var_deep = tk.BooleanVar(value=False)

        self.lbls = {}

        def field(col, key, var, width):
            lab = ttk.Label(f, text="")
            lab.grid(row=0, column=col * 2, sticky="e", padx=(8, 4), pady=4)
            ttk.Entry(f, textvariable=var, width=width).grid(row=0, column=col * 2 + 1, sticky="w", pady=4)
            self.lbls[key] = lab

        field(0, "subnet", self.var_subnet, 30)
        field(1, "ports", self.var_ports, 18)
        field(2, "workers", self.var_workers, 6)
        field(3, "ctimeout", self.var_ctimeout, 6)
        field(4, "htimeout", self.var_htimeout, 6)

        btns = ttk.Frame(f)
        btns.grid(row=1, column=0, columnspan=10, sticky="w", pady=(10, 0))
        self.btn_start = ttk.Button(btns, command=self._start_scan)
        self.btn_start.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(btns, command=self._stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.btn_export = ttk.Button(btns, command=self._export, state="disabled")
        self.btn_export.pack(side="left", padx=6)
        self.btn_html = ttk.Button(btns, command=self._export_html, state="disabled")
        self.btn_html.pack(side="left", padx=6)
        self.btn_diff = ttk.Button(btns, command=self._compare, state="disabled")
        self.btn_diff.pack(side="left", padx=6)
        self.btn_clear = ttk.Button(btns, command=self._clear)
        self.btn_clear.pack(side="left", padx=6)

        self.chk_deep = ttk.Checkbutton(f, variable=self.var_deep)
        self.chk_deep.grid(row=2, column=0, columnspan=10, sticky="w", pady=(8, 0))
        self.lbl_hint = ttk.Label(f, foreground="#777")
        self.lbl_hint.grid(row=3, column=0, columnspan=10, sticky="w", pady=(6, 0))

    def _build_table(self):
        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=10, pady=6)

        self.tree = ttk.Treeview(wrap, columns=COL_KEYS, show="headings", selectmode="browse")
        for k in COL_KEYS:
            self.tree.column(k, width=COL_WIDTH[k], anchor=COL_ANCHOR.get(k, "w"),
                             stretch=(k in COL_STRETCH))
        for tag, (bg, fg) in RISK_COLORS.items():
            self.tree.tag_configure(tag, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

    def _build_statusbar(self):
        bar = ttk.Frame(self, padding=(10, 4))
        bar.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(bar, mode="determinate", length=240)
        self.progress.pack(side="left", padx=(0, 10))
        self.lbl_prog = ttk.Label(bar, text="0 / 0", width=14)
        self.lbl_prog.pack(side="left")
        self.lbl_summary = ttk.Label(bar, text="")
        self.lbl_summary.pack(side="left", padx=12)
        self.lbl_version = ttk.Label(bar, text=f"v{APP_VERSION}", foreground="#999")
        self.lbl_version.pack(side="right")
        self.lbl_state = ttk.Label(bar, text="")
        self.lbl_state.pack(side="right", padx=(0, 12))

    # ----------------------------- dil -----------------------------

    def _set_lang(self, code):
        if code == self.lang or code not in T:
            return
        self.lang = code
        self._refresh_lang()
        self._apply_language()

    def _refresh_lang(self):
        for c, lbl in self.lang_lbls.items():
            if c == self.lang:
                lbl.config(bg="#305496", fg="white")
            else:
                lbl.config(bg="white", fg="#333333")

    def _apply_language(self):
        self.title(self._t("win_title"))
        self.lf.config(text=self._t("settings"))
        for key, lab in self.lbls.items():
            lab.config(text=self._t(key))
        self.btn_start.config(text=self._t("start"))
        self.btn_stop.config(text=self._t("stop"))
        self.btn_export.config(text=self._t("export"))
        self.btn_html.config(text=self._t("html"))
        self.btn_diff.config(text=self._t("compare"))
        self.btn_clear.config(text=self._t("clear"))
        self.chk_deep.config(text=self._t("deep"))
        self.lbl_hint.config(text=self._t("hint"))
        for k, title in zip(COL_KEYS, localized_header(self.lang)):
            self.tree.heading(k, text=title)
        self._render_state()
        self._update_summary()
        self._rerender_rows()

    def _rerender_rows(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.results:
            self.tree.insert("", "end", tags=(status_tag(r.get("status", "")),),
                             values=row_values(r, self.lang))

    # ------------------------------- tarama akışı -------------------------------

    def _parse_cfg(self):
        tokens = [t for t in re.split(r"[\s,;]+", self.var_subnet.get().strip()) if t]
        if not tokens:
            raise ValueError(self._t("err_subnet_empty"))
        networks = []
        for tok in tokens:
            try:
                networks.append(ipaddress.IPv4Network(tok, strict=False))
            except ValueError as e:
                raise ValueError(self._t("err_subnet_bad", tok=tok, e=e))

        ports = []
        for p in self.var_ports.get().split(","):
            p = p.strip()
            if not p:
                continue
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                raise ValueError(self._t("err_port_bad", p=p))
            ports.append(int(p))
        if not ports:
            raise ValueError(self._t("err_port_empty"))
        try:
            workers = int(self.var_workers.get())
            ctimeout = float(self.var_ctimeout.get())
            htimeout = float(self.var_htimeout.get())
        except ValueError:
            raise ValueError(self._t("err_num"))
        if workers < 1:
            raise ValueError(self._t("err_workers"))
        if ctimeout <= 0 or htimeout <= 0:
            raise ValueError(self._t("err_timeouts"))

        total = sum(host_count(n) for n in networks) * len(ports)
        if total <= 0:
            raise ValueError(self._t("no_targets"))
        if total > HARD_CAP_TARGETS:
            raise ValueError(self._t("too_big", n=total, cap=HARD_CAP_TARGETS))

        cfg = {"workers": workers, "connect_timeout": ctimeout,
               "http_timeout": htimeout, "deep": bool(self.var_deep.get())}
        return cfg, networks, ports, total

    def _start_scan(self):
        try:
            cfg, networks, ports, total = self._parse_cfg()
        except ValueError as e:
            messagebox.showerror(self._t("err_input"), str(e))
            return
        if total > SOFT_WARN_TARGETS:
            est = total * cfg["connect_timeout"] / max(cfg["workers"], 1) / 60
            if not messagebox.askyesno(self._t("big_title"), self._t("big_msg", n=total, m=est)):
                return

        self._clear()
        self.scope_text = self.var_subnet.get().strip()
        self.stop_event.clear()
        self._scan_deep = cfg["deep"]
        self.total = total
        self.done = 0
        self.progress.configure(maximum=self.total, value=0)
        self.lbl_prog.config(text=f"0 / {self.total}")
        self._set_state("scanning")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        for b in (self.btn_export, self.btn_html):
            b.config(state="disabled")

        self.worker = threading.Thread(
            target=self._run_scan, args=(cfg, networks, ports), daemon=True)
        self.worker.start()

    def _run_scan(self, cfg, networks, ports):
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=cfg["workers"])
        try:
            futs = [ex.submit(check_target, ip, p, cfg, self.stop_event)
                    for net in networks for ip in net.hosts() for p in ports]
            for fut in concurrent.futures.as_completed(futs):
                if self.stop_event.is_set():
                    break
                try:
                    r = fut.result()
                except Exception:
                    r = None
                self.q.put(("progress",))
                if r:
                    self.q.put(("row", r))
        except Exception as e:
            self.q.put(("error", str(e)))
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
            self.q.put(("done",))

    def _stop_scan(self):
        self.stop_event.set()
        self._set_state("stopping")
        self.btn_stop.config(state="disabled")

    # ------------------------------- kuyruk / GUI -------------------------------

    def _drain_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    self.done += 1
                    self.progress["value"] = self.done
                    self.lbl_prog.config(text=f"{self.done} / {self.total}")
                elif kind == "row":
                    self._add_row(msg[1])
                elif kind == "error":
                    messagebox.showerror(self._t("scan_err"), msg[1])
                elif kind == "done":
                    self._scan_finished()
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _add_row(self, r):
        self.results.append(r)
        self.tree.insert("", "end", tags=(status_tag(r.get("status", "")),),
                         values=row_values(r, self.lang))
        self._update_summary()
        self._enable_result_buttons()

    def _update_summary(self):
        if not self.results:
            self.lbl_summary.config(text=self._t("ready"))
            return
        n = len(self.results)
        vuln = sum(1 for r in self.results if is_vuln(r))
        hidden = sum(1 for r in self.results if r.get("status") == "hidden")
        find = sum(1 for r in self.results if r.get("findings"))
        self.lbl_summary.config(text=self._t("summary", n=n, v=vuln, h=hidden, f=find))

    def _enable_result_buttons(self):
        state = "normal" if self.results else "disabled"
        for b in (self.btn_export, self.btn_html, self.btn_diff):
            b.config(state=state)

    def _set_state(self, key):
        self._state_key = key
        self._render_state()

    def _render_state(self):
        key = self._state_key
        if key == "scanning":
            txt = self._t("scanning_deep" if self._scan_deep else "scanning")
        elif key:
            txt = self._t(key)
        else:
            txt = ""
        self.lbl_state.config(text=txt)

    def _scan_finished(self):
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._enable_result_buttons()
        self._set_state("stopped" if self.stop_event.is_set() else "done")

    def _clear(self):
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.diff = None
        self.done = 0
        self.total = 0
        self.progress.configure(value=0, maximum=100)
        self.lbl_prog.config(text="0 / 0")
        self._set_state("")
        self._update_summary()
        for b in (self.btn_export, self.btn_html, self.btn_diff):
            b.config(state="disabled")

    # ------------------------------- dışa aktarma -------------------------------

    def _export(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title=self._t("save_title"), defaultextension=".xlsx",
            initialfile="php_inventory_report.xlsx",
            filetypes=[(self._t("ft_xlsx"), "*.xlsx"), (self._t("ft_csv"), "*.csv"),
                       (self._t("ft_json"), "*.json")])
        if not path:
            return
        rows = sort_results(self.results)
        low = path.lower()
        try:
            if low.endswith(".csv"):
                with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                    w = csv.writer(fh, delimiter=";")
                    w.writerow(localized_header(self.lang))
                    for r in rows:
                        w.writerow(row_values(r, self.lang))
            elif low.endswith(".json"):
                data = [{k: r.get(k) for k in PUBLIC_FIELDS} for r in rows]
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=2)
            else:
                write_xlsx(path, rows, self.lang)
        except OSError as e:
            messagebox.showerror(self._t("save_err"), str(e))
            return
        messagebox.showinfo(self._t("ok"), self._t("saved", n=len(rows), f=os.path.basename(path)))

    def _export_html(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title=self._t("html_title"), defaultextension=".html",
            initialfile="php_inventory_report.html",
            filetypes=[(self._t("ft_html"), "*.html")])
        if not path:
            return
        try:
            html = generate_html(self.results, self.scope_text or "-", self.lang, self.diff)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html)
        except OSError as e:
            messagebox.showerror(self._t("save_err"), str(e))
            return
        if messagebox.askyesno(self._t("ok"), self._t("html_saved_q", f=os.path.basename(path))):
            try:
                os.startfile(path)
            except Exception:
                pass

    def _compare(self):
        if not self.results:
            return
        path = filedialog.askopenfilename(
            title=self._t("cmp_pick"),
            filetypes=[(self._t("ft_json"), "*.json"), (self._t("ft_all"), "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
            if not isinstance(old, list):
                raise ValueError("expected a JSON list")
        except (OSError, ValueError, json.JSONDecodeError) as e:
            messagebox.showerror(self._t("save_err"), self._t("cmp_read_err", e=e))
            return
        self.diff = compute_diff(old, self.results)
        d = self.diff
        messagebox.showinfo(self._t("cmp_title"), self._t(
            "cmp_msg", o=len(old), c=len(self.results),
            nv=len(d["new_vuln"]), fx=len(d["fixed"]), sv=len(d["still_vuln"]),
            ap=len(d["appeared"]), dp=len(d["disappeared"])))

    def _on_close(self):
        self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    ScannerApp().mainloop()

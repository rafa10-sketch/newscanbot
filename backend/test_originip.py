"""
Test script untuk menjalankan OriginIPStage secara manual.
Jalankan dari folder backend/:
    python test_originip.py <domain>

Contoh:
    python test_originip.py api.paybo.io
    python test_originip.py octopay.asia
"""

import asyncio
import sys
from pathlib import Path

# Tambahkan folder backend ke path agar import bisa berjalan
sys.path.insert(0, str(Path(__file__).parent))

from pipeline.originip import OriginIPStage
from utils.logger import get_logger


async def main(target: str):
    logger = get_logger("test_originip")

    print(f"\n{'='*65}")
    print(f"  🔍 Origin IP Discovery Test - ScanBot v2")
    print(f"  Target : {target}")
    print(f"{'='*65}\n")

    # Load konfigurasi dari environment/.env
    from config import load_config
    config = load_config(require_secrets=False)

    # Buat context minimal seperti yang digunakan pipeline asli
    work_dir = Path("/tmp/test_originip")
    work_dir.mkdir(parents=True, exist_ok=True)

    ctx = {
        "scan_id":     "test-manual",
        "target":      target,
        "work_dir":    work_dir,
        "config":      config.scan,
        "scan_mode":   "fast",
        "logger":      logger,
        "tool_errors": [],
        "stage_errors": {},
    }

    # Jalankan OriginIPStage
    print("  [*] Memulai 10-method discovery...\n")
    stage = OriginIPStage(ctx)
    await stage.run()

    # ── Tampilkan Hasil ────────────────────────────────────────────────────────
    origin_data    = ctx.get("origin_data", {})
    all_ips        = origin_data.get("all_ips", [])
    details        = origin_data.get("details", {})
    cdn_ips        = origin_data.get("cdn_ips", [])
    cloudfront_ips = origin_data.get("cloudfront_ips", [])
    candidates     = ctx.get("origin_candidates", [])

    print(f"\n{'='*65}")
    print(f"  📊 HASIL LENGKAP")
    print(f"{'='*65}")
    print(f"  CDN Detected     : {ctx.get('cdn_detected', False)}")
    print(f"  Total IP Found   : {len(all_ips)}")
    print(f"  Cloudflare IPs   : {len(cdn_ips)}")
    print(f"  CloudFront IPs   : {len(cloudfront_ips)}")
    print(f"  Origin Candidates: {len(candidates)}")

    # ── Detail per IP ──────────────────────────────────────────────────────────
    print(f"\n{'─'*65}")
    print(f"  Detail per IP:")
    print(f"{'─'*65}")

    for ip in all_ips:
        info = details.get(ip, {})
        is_cdn        = info.get("is_cdn", False)
        is_cloudfront = info.get("is_cloudfront", False)
        methods       = ", ".join(info.get("methods", []))
        ptr           = info.get("ptr", "") or "-"

        if is_cloudfront:
            status = "☁️  CLOUDFRONT"
        elif is_cdn:
            status = "⚠️  CLOUDFLARE "
        else:
            status = "✅ ORIGIN     "

        print(f"\n  [{status}] {ip}")
        print(f"    PTR     : {ptr}")
        print(f"    Methods : {methods}")

    # ── Ringkasan Kandidat Origin ──────────────────────────────────────────────
    print(f"\n{'='*65}")
    if candidates:
        print(f"  🎯 ORIGIN IP CANDIDATES (Terbaik → Terakhir):")
        print(f"{'─'*65}")
        for i, ip in enumerate(candidates, 1):
            methods = ", ".join(details.get(ip, {}).get("methods", []))
            ptr     = details.get(ip, {}).get("ptr", "") or "-"
            print(f"  {i}. {ip}")
            print(f"     PTR     : {ptr}")
            print(f"     Methods : {methods}")
            print()

        best = candidates[0]
        print(f"{'='*65}")
        print(f"  ✅ Gunakan IP ini sebagai target scan berikutnya:")
        print(f"     → Input di Dashboard : {best}")
        print(f"     → Test manual Nmap   : nmap -sV -sC {best}")
        print(f"     → Test curl          : curl -H \"Host: {target}\" http://{best}")
    else:
        print(f"  ❌ Tidak ditemukan Origin IP.")
        print(f"     Target kemungkinan sangat terlindungi atau")
        print(f"     semua subdomains sudah di-proxy oleh CDN.")

    # ── CDN & CloudFront Summary ───────────────────────────────────────────────
    if cdn_ips:
        print(f"\n  ⚠️  Cloudflare IPs (diabaikan): {', '.join(cdn_ips)}")
    if cloudfront_ips:
        print(f"  ☁️  CloudFront IPs (diabaikan) : {', '.join(cloudfront_ips)}")

    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage  : python test_originip.py <domain>")
        print("Contoh : python test_originip.py octopay.asia")
        print("         python test_originip.py api.paybo.io\n")
        sys.exit(1)

    target = sys.argv[1].strip()
    # Bersihkan http:// atau https://
    if "://" in target:
        target = target.split("://")[1]
    if "/" in target:
        target = target.split("/")[0]

    asyncio.run(main(target))

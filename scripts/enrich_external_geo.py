#!/usr/bin/env python3
"""
Standalone script to bulk-enrich missing public external IPs with geo data.

Usage:
    cd /path/to/logsentinel
    python scripts/enrich_external_geo.py

Optional:
    Set IPINFO_TOKEN environment variable for much better results:
        export IPINFO_TOKEN=your_token_here
        python scripts/enrich_external_geo.py

This script is safe to run periodically. It only looks up public IPs
that are missing geo data and caches the results locally.
"""

import os
import sys
from pathlib import Path

# Make sure we can import the package when running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from logsentinel.geo import get_geo_enricher
from logsentinel.storage import Storage


def main():
    db_path = Path("data/logsentinel.db")
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("Please run this script from the root of your LogSentinel installation.")
        sys.exit(1)

    print("=== LogSentinel External IP Geo Enrichment ===")
    print(f"Using database: {db_path}")

    # Initialize storage and geo
    storage = Storage(str(db_path))
    geo = get_geo_enricher()

    if not geo.available:
        print("\nWarning: Local GeoLite2 database is not available.")
        print("Online lookup will still work for public IPs (if requests is installed).")

    # Get IPs that need geo data
    print("\nLooking for public IPs missing geo data (from threats + cache + outbound destinations)...")
    missing_ips = storage.get_ips_missing_geo(limit=2000)

    # Also include outbound destinations from device baselines
    try:
        outbound = storage.get_all_external_destinations(limit=500)
        for ip in outbound:
            if ip not in missing_ips:
                missing_ips.append(ip)
    except Exception:
        pass

    print(f"Found {len(missing_ips)} candidate IPs.")

    if not missing_ips:
        print("Nothing to enrich. You're all caught up!")
        return

    enriched = 0
    skipped_private = 0
    failed = 0

    print("\nStarting enrichment (this may take a while for large numbers of IPs)...\n")

    for i, ip in enumerate(missing_ips, 1):
        if i % 50 == 0:
            print(f"  Processed {i}/{len(missing_ips)}...")

        try:
            if geo._is_private_ip(ip):
                skipped_private += 1
                continue

            result = geo.enrich(ip)
            if result and result.get("lat") is not None:
                storage.cache_ip_geo(ip, result)
                enriched += 1
                source = result.get("source", "unknown")
                if i <= 20:  # Show first few for feedback
                    print(f"  ✓ {ip} -> {result.get('city')}, {result.get('country')} ({source})")
            else:
                failed += 1
        except Exception as e:
            failed += 1
            if i <= 5:
                print(f"  ! Error enriching {ip}: {e}")

    print("\n=== Enrichment Complete ===")
    print(f"  Enriched:        {enriched}")
    print(f"  Skipped private: {skipped_private}")
    print(f"  Failed / no data:{failed}")
    print(f"  Total processed: {len(missing_ips)}")

    if enriched > 0:
        print("\nYou can now refresh the Maps page. New locations should appear.")
    else:
        print("\nNo new locations were added this run.")
        print("This usually means either:")
        print("  - Most external IPs you've seen are already enriched, or")
        print("  - The online service is rate-limiting you (try again later).")

    if not os.environ.get("IPINFO_TOKEN"):
        print("\nTip: For significantly better results and higher limits,")
        print("     sign up for a free token at https://ipinfo.io and set:")
        print("     export IPINFO_TOKEN=your_token_here")


if __name__ == "__main__":
    main()

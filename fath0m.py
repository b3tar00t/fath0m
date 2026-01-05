#!/usr/bin/env python3

import argparse

from core.scanner import ServiceScanner
from core.nvd_client import NVDClient
from core.reporter import display_results
from utils.logger import logger


def main():
    parser = argparse.ArgumentParser(
        description="fath0m — Service Enumeration & CVE Correlation Tool"
    )

    parser.add_argument(
        "target",
        help="Target IP address or domain"
    )

    parser.add_argument(
        "-p", "--ports",
        default="22,80,443,8080",
        help="Comma-separated ports to scan (default: 22,80,443,8080)"
    )

    parser.add_argument(
        "-m", "--mode",
        choices=["stealth", "normal", "aggressive", "insane"],
        default="aggressive",
        help="Nmap scan intensity profile"
    )

    args = parser.parse_args()

    # ---------- Initialize ----------
    scanner = ServiceScanner()
    nvd = NVDClient()

    # ---------- Step 1: Service Scan ----------
    logger.info(f"[fath0m] Starting scan against {args.target}")
    services = scanner.scan(args.target, args.ports, mode=args.mode)

    if not services:
        logger.warning("[fath0m] No services detected")
        return

    # ---------- Step 2: CVE Correlation ----------
    for svc in services:
        product = svc.get("product")
        version = svc.get("version")

        if not product or not version:
            svc["vulnerabilities"] = []
            continue

        svc["vulnerabilities"] = nvd.fetch_cves(
            product=product,
            version=version
        )

    # ---------- Step 3: Reporting ----------
    display_results(services)


if __name__ == "__main__":
    main()

import nmap
import os
from utils.logger import logger


class ServiceScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

        self.SCAN_PROFILES = {
            "stealth": "-T1 -sV --version-intensity 3",
            "normal": "-T3 -sV --version-intensity 5 -sC",
            "aggressive": "-T4 -sV --version-intensity 9 -A",
            "aggressive-nonroot": "-T4 -sV --version-intensity 9 -sC",
            "insane": "-T5 -sV --version-intensity 9 -A"
        }

    def scan(self, target, ports, mode="aggressive"):
        """
        Perform service discovery and extract clean service metadata.
        """

        scan_flags = self.SCAN_PROFILES.get(mode, self.SCAN_PROFILES["aggressive"])

        # Root privilege handling
        if "-A" in scan_flags and os.geteuid() != 0:
            logger.warning(
                "[fath0m] Root not detected. Falling back to non-root aggressive scan."
            )
            scan_flags = self.SCAN_PROFILES["aggressive-nonroot"]

        logger.info(f"[fath0m] Mode selected: {mode.upper()}")
        logger.info(f"[fath0m] Command: nmap {scan_flags} -p {ports} {target}")

        try:
            self.nm.scan(
                hosts=target,
                ports=ports,
                arguments=scan_flags
            )

            results = []

            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port, svc in self.nm[host][proto].items():

                        product = svc.get("product", "").strip()
                        version = svc.get("version", "").strip()

                        # Skip useless services (prevents API waste)
                        if not product and not svc.get("cpe"):
                            continue

                        cpe = self._extract_cpe(svc.get("cpe"))

                        results.append({
                            "port": port,
                            "name": svc.get("name", ""),
                            "product": product,
                            "version": version,
                            "cpe": cpe,
                            "extrainfo": svc.get("extrainfo", "")
                        })

            return results

        except Exception as e:
            logger.error(f"[fath0m] Nmap scan failed: {e}")
            return []

    @staticmethod
    def _extract_cpe(cpe_data):
        """
        Normalize CPE extraction:
        - list → first valid CPE
        - string → returned directly
        """
        if isinstance(cpe_data, list) and cpe_data:
            return cpe_data[0]
        if isinstance(cpe_data, str):
            return cpe_data
        return None

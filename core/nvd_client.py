import requests
from packaging.version import Version, InvalidVersion
from utils.logger import logger


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_cves(self, product: str, version: str, limit: int = 25):
        if not product or not version:
            return []

        raw = self._query_nvd(product, limit)
        if not raw:
            return []

        return self._filter_by_version(raw, product, version)

    # --------------------------------------------------

    def _query_nvd(self, product: str, limit: int):
        params = {
            "keywordSearch": product,
            "resultsPerPage": limit
        }

        try:
            r = requests.get(self.BASE_URL, params=params, timeout=20)
            if r.status_code != 200:
                logger.warning(f"[NVD] HTTP {r.status_code}")
                return []

            return r.json().get("vulnerabilities", [])

        except Exception as e:
            logger.error(f"[NVD] Request failed: {e}")
            return []

    # --------------------------------------------------

    def _filter_by_version(self, cves, product: str, target_version: str):
        results = []

        for item in cves:
            cve = item.get("cve", {})
            configs = cve.get("configurations", [])

            confidence = self._cve_affects_version(configs, product, target_version)
            if not confidence:
                continue

            normalized = self._normalize_cve(cve)
            normalized["confidence"] = confidence
            results.append(normalized)

        return results

    # --------------------------------------------------

    def _cve_affects_version(self, configs, product: str, target_v: str):
        for conf in configs:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue

                    cpe = match.get("criteria", "").lower()
                    if product.lower() not in cpe:
                        continue

                    if self._version_match(match, target_v):
                        # Version-bounded → HIGH confidence
                        if any(k in match for k in (
                            "versionStartIncluding",
                            "versionEndIncluding",
                            "versionStartExcluding",
                            "versionEndExcluding"
                        )):
                            return "HIGH"

                        # Product match only → MEDIUM
                        return "MEDIUM"

        return None

    # --------------------------------------------------

    def _version_match(self, cpe_match: dict, target_v: str):
        try:
            target_v = Version(target_v)
        except (InvalidVersion, TypeError):
            return True  # fail-open

        def safe(v):
            if not v:
                return None
            try:
                return Version(v)
            except (InvalidVersion, TypeError):
                return None

        start_incl = safe(cpe_match.get("versionStartIncluding"))
        start_excl = safe(cpe_match.get("versionStartExcluding"))
        end_incl = safe(cpe_match.get("versionEndIncluding"))
        end_excl = safe(cpe_match.get("versionEndExcluding"))

        if start_incl and target_v < start_incl:
            return False
        if start_excl and target_v <= start_excl:
            return False
        if end_incl and target_v > end_incl:
            return False
        if end_excl and target_v >= end_excl:
            return False

        return True

    # --------------------------------------------------

    def _normalize_cve(self, cve: dict):
        metrics = cve.get("metrics", {})
        cvss = {}

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]

        exploit = False
        exploit_refs = []

        for ref in cve.get("references", []):
            url = ref.get("url", "").lower()
            tags = ref.get("tags", [])

            if (
                "exploit" in tags
                or "exploit-db" in url
                or "packetstormsecurity" in url
                or "metasploit" in url
                or "github.com" in url
            ):
                exploit = True
                exploit_refs.append(ref.get("url"))

        return {
            "id": cve.get("id"),
            "cvss": {
                "score": cvss.get("baseScore", 0.0),
                "vector": cvss.get("vectorString", "")
            },
            "exploit": exploit,
            "exploit_refs": exploit_refs
        }

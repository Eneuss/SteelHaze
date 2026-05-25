import requests

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def lookup_cve(port, service=None, product=None, version=None, max_results=3):
    #build keyword: first word of product + version when version is known,
    #otherwise full product name, then service name
    version_known = version and version.strip() and version.strip().lower() != "unknown"
    if product and product.strip():
        if version_known:
            first_word = product.strip().split()[0]
            keyword = f"{first_word} {version.strip()}"
        else:
            keyword = product.strip()
    elif service and service.strip() and service.strip() not in ("unknown", "tcpwrapped"):
        keyword = service.strip()
    else:
        return []
    results = []
    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&noRejected",
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        for item in items[:20]:
            cve = item["cve"]
            cve_id = cve["id"]
            desc = (
                cve["descriptions"][0]["value"]
                if cve.get("descriptions")
                else "No description"
            )
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            if metrics.get("cvssMetricV31"):
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif metrics.get("cvssMetricV2"):
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
            results.append({"id": cve_id, "severity": severity, "description": desc, "service": keyword})
        results.sort(key=lambda c: _SEVERITY_ORDER.get(c["severity"], 4))
        results = results[:max_results]
    except Exception:
        pass
    return results

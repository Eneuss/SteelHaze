import requests


def lookup_cve(port, service=None, product=None, max_results=3):
    #product name > service name > skip unknowns
    if product and product.strip():
        keyword = product.strip()
    elif service and service.strip() and service.strip() not in ("unknown", "tcpwrapped"):
        keyword = service.strip()
    else:
        return []
    results = []
    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}",
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        for item in items[:max_results]:
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
    except Exception:
        pass
    return results

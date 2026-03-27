#!/usr/bin/env python3
import requests

PORT_SERVICE_MAP = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    143:  "imap",
    443:  "ssl",
    445:  "smb",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http",
    8443: "https",
}


def lookup_cve(port, max_results=3):
    """
    Query the NVD API for CVEs related to the service on the given port.
    Returns a list of dicts with id, severity, description.
    """
    service = PORT_SERVICE_MAP.get(port, f"port{port}")
    results = []
    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}",
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
            results.append({"id": cve_id, "severity": severity, "description": desc, "service": service})
    except Exception:
        pass
    return results

import json
from datetime import datetime

def extract_affected_products(cve_item):
    """Extract affected systems from NVD JSON structure"""
    affected = set()
    for vendor in cve_item.get("affects", {}).get("vendor", {}).get("vendor_data", []):
        for product in vendor.get("product", {}).get("product_data", []):
            affected.add(product["product_name"])
    return list(affected) if affected else ["All"]

def classify_vuln_type(cve_item):
    """Classify as 'network' or 'os' based on attackVector"""
    attack_vector = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackVector", "")
    return "network" if "NETWORK" in attack_vector.upper() else "os"

def convert_nvd_to_structure(nvd_path, output_path="cve_dataset.json"):
    """
    Converts official NVD JSON to our project's structured format
    Args:
        nvd_path: Path to NVD JSON file (e.g. "nvdcve-1.1-2023.json")
        output_path: Output file path
    """
    with open(nvd_path) as f:
        nvd_data = json.load(f)
    
    structured_data = {
        "metadata": {
            "source": "National Vulnerability Database",
            "url": "https://nvd.nist.gov/",
            "conversion_date": datetime.now().isoformat(),
            "converter_version": "1.0"
        },
        "vulnerabilities": []
    }
    
    for item in nvd_data["CVE_Items"]:
        cve = {
            "id": item["cve"]["CVE_data_meta"]["ID"],
            "title": item["cve"]["description"]["description_data"][0]["value"],
            "description": "\n".join([desc["value"] for desc in item["cve"]["description"]["description_data"]]),
            "cvss_score": item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0.0),
            "attack_vector": item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackVector", ""),
            "affected_systems": extract_affected_products(item),
            "type": classify_vuln_type(item),
            "references": [ref["url"] for ref in item["cve"]["references"]["reference_data"]]
        }
        structured_data["vulnerabilities"].append(cve)
    
    with open(output_path, 'w') as f:
        json.dump(structured_data, f, indent=2)
    print(f"Converted {len(structured_data['vulnerabilities'])} CVEs to {output_path}")
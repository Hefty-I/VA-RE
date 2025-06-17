import requests
import json
import os
import gzip
import io
import time
import datetime
from typing import List, Dict, Any, Optional, Tuple

# Base URLs for NVD feeds
NVD_FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
META_FILES = [
    "nvdcve-1.1-modified.meta",
    "nvdcve-1.1-recent.meta",
    "nvdcve-1.1-2025.meta",
    "nvdcve-1.1-2024.meta",
    "nvdcve-1.1-2023.meta"
]
DATA_FILES = [
    "nvdcve-1.1-modified.json.gz",
    "nvdcve-1.1-recent.json.gz",
    "nvdcve-1.1-2025.json.gz",
    "nvdcve-1.1-2024.json.gz",
    "nvdcve-1.1-2023.json.gz"
]

# Directory to store cached NVD data
CACHE_DIR = "data/nvd_cache"

def get_meta_data(meta_file: str) -> Dict[str, str]:
    """
    Get metadata for an NVD feed file
    
    Args:
        meta_file (str): Name of the metadata file
        
    Returns:
        dict: Metadata dictionary with keys like "lastModifiedDate", "size", etc.
    """
    url = f"{NVD_FEED_BASE_URL}{meta_file}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        meta_data = {}
        for line in response.text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                meta_data[key.strip()] = value.strip()
        
        return meta_data
    except Exception as e:
        print(f"Error fetching metadata from {url}: {e}")
        return {}

def should_download_feed(data_file: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """
    Determine if a feed file should be downloaded based on cache status
    
    Args:
        data_file (str): Name of the data file
        
    Returns:
        tuple: (should_download, meta_data)
    """
    # Get corresponding meta file
    meta_file = data_file.replace(".json.gz", ".meta")
    meta_data = get_meta_data(meta_file)
    
    if not meta_data:
        return False, None
    
    # Check if we have a cached version
    cached_file_path = os.path.join(CACHE_DIR, data_file)
    cached_meta_path = os.path.join(CACHE_DIR, "meta", f"{data_file}.meta.json")
    
    # If files don't exist, download
    if not os.path.exists(cached_file_path) or not os.path.exists(cached_meta_path):
        return True, meta_data
    
    # Compare last modified dates
    try:
        with open(cached_meta_path, 'r') as f:
            cached_meta = json.load(f)
        
        cached_date = cached_meta.get("lastModifiedDate", "")
        current_date = meta_data.get("lastModifiedDate", "")
        
        if cached_date != current_date:
            return True, meta_data
    except Exception as e:
        print(f"Error reading cached metadata: {e}")
        return True, meta_data
    
    # No need to download
    return False, meta_data

def download_and_cache_feed(data_file: str, meta_data: Optional[Dict[str, str]] = None) -> str:
    """
    Download an NVD feed file and cache it
    
    Args:
        data_file (str): Name of the data file
        meta_data (dict, optional): Metadata for the file
        
    Returns:
        str: Path to the cached file
    """
    url = f"{NVD_FEED_BASE_URL}{data_file}"
    cached_file_path = os.path.join(CACHE_DIR, data_file)
    
    # Create cache directories if they don't exist
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(os.path.join(CACHE_DIR, "meta"), exist_ok=True)
    
    try:
        print(f"Downloading {url}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Save the compressed file
        with open(cached_file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Save metadata
        if meta_data:
            meta_path = os.path.join(CACHE_DIR, "meta", f"{data_file}.meta.json")
            with open(meta_path, 'w') as f:
                json.dump(meta_data, f)
        
        print(f"Successfully downloaded and cached {data_file}")
        return cached_file_path
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return ""

def load_nvd_feed(data_file: str) -> List[Dict[str, Any]]:
    """
    Load and parse an NVD feed file
    
    Args:
        data_file (str): Name of the data file or path to cached file
        
    Returns:
        list: List of CVE dictionaries
    """
    if os.path.exists(data_file):
        file_path = data_file  # Using provided path
    else:
        file_path = os.path.join(CACHE_DIR, data_file)
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []
    
    try:
        with gzip.open(file_path, 'rb') as f:
            data = json.loads(f.read().decode('utf-8'))
            return data.get("CVE_Items", [])
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []

def extract_cve_info(cve_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract relevant information from a CVE item
    
    Args:
        cve_item (dict): CVE item dictionary
        
    Returns:
        dict: Simplified CVE dictionary
    """
    cve_info = {}
    
    try:
        # Get CVE ID
        cve_info["id"] = cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown")
        
        # Get description
        descriptions = cve_item.get("cve", {}).get("description", {}).get("description_data", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                cve_info["description"] = desc.get("value", "No description available")
                break
        
        # Create a title
        cve_info["title"] = f"Vulnerability: {cve_info['id']}"
        
        # Get CVSS scores
        impact = cve_item.get("impact", {})
        cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
        cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
        
        if cvss_v3:
            cve_info["cvss_score"] = cvss_v3.get("baseScore", 0.0)
            cve_info["cvss_vector"] = cvss_v3.get("vectorString", "")
            cve_info["attack_vector"] = cvss_v3.get("attackVector", "Unknown")
        elif cvss_v2:
            cve_info["cvss_score"] = cvss_v2.get("baseScore", 0.0)
            cve_info["cvss_vector"] = cvss_v2.get("vectorString", "")
            cve_info["attack_vector"] = cvss_v2.get("accessVector", "Unknown")
        else:
            cve_info["cvss_score"] = 0.0
            cve_info["cvss_vector"] = ""
            cve_info["attack_vector"] = "Unknown"
        
        # Get references
        references = cve_item.get("cve", {}).get("references", {}).get("reference_data", [])
        cve_info["references"] = [ref.get("url", "") for ref in references if "url" in ref]
        
        # Get published and last modified dates
        cve_info["published_date"] = cve_item.get("publishedDate", "")
        cve_info["last_modified_date"] = cve_item.get("lastModifiedDate", "")
        
        # Determine vulnerability type (network or local)
        if cve_info["attack_vector"].lower() in ["network", "adjacent_network", "adjacent"]:
            cve_info["type"] = "network"
        else:
            cve_info["type"] = "os"
        
        # Initialize status and history
        cve_info["status"] = "Open"
        cve_info["history"] = []
        
        # Determine affected systems
        cpe_data = cve_item.get("configurations", {}).get("nodes", [])
        affected_systems = set()
        
        for node in cpe_data:
            for cpe_match in node.get("cpe_match", []):
                cpe_uri = cpe_match.get("cpe23Uri", "")
                if "windows" in cpe_uri.lower():
                    affected_systems.add("Windows")
                elif "linux" in cpe_uri.lower():
                    affected_systems.add("Linux")
                elif "mac_os" in cpe_uri.lower() or "macos" in cpe_uri.lower():
                    affected_systems.add("macOS")
        
        if not affected_systems:
            affected_systems.add("All")
        
        cve_info["affected_systems"] = list(affected_systems)
        
        return cve_info
    except Exception as e:
        print(f"Error extracting CVE info: {e}")
        return {
            "id": cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown"),
            "title": "Error processing vulnerability",
            "description": "An error occurred while processing this vulnerability",
            "cvss_score": 0.0,
            "references": [],
            "type": "unknown",
            "affected_systems": ["Unknown"],
            "status": "Open",
            "history": []
        }

def fetch_nvd_data(years=None, include_recent=True, include_modified=True) -> List[Dict[str, Any]]:
    """
    Fetch NVD data for specified years and options
    
    Args:
        years (list, optional): List of years to fetch (e.g., [2023, 2024])
        include_recent (bool): Whether to include recent CVEs
        include_modified (bool): Whether to include modified CVEs
        
    Returns:
        list: List of CVE dictionaries
    """
    if years is None:
        years = [2023, 2024, 2025]
    
    files_to_process = []
    
    # Add requested year files
    for year in years:
        files_to_process.append(f"nvdcve-1.1-{year}.json.gz")
    
    # Add recent and modified files if requested
    if include_recent:
        files_to_process.append("nvdcve-1.1-recent.json.gz")
    
    if include_modified:
        files_to_process.append("nvdcve-1.1-modified.json.gz")
    
    # Download and process files
    cve_items = []
    for data_file in files_to_process:
        should_download, meta_data = should_download_feed(data_file)
        
        if should_download:
            cached_path = download_and_cache_feed(data_file, meta_data)
        else:
            cached_path = os.path.join(CACHE_DIR, data_file)
        
        if os.path.exists(cached_path):
            items = load_nvd_feed(cached_path)
            for item in items:
                cve_info = extract_cve_info(item)
                if cve_info not in cve_items:  # Avoid duplicates
                    cve_items.append(cve_info)
    
    return cve_items

def search_cve_data(keyword=None, cve_id=None, min_cvss=None, max_items=100) -> List[Dict[str, Any]]:
    """
    Search for CVEs in the cached data
    
    Args:
        keyword (str, optional): Keyword to search for in descriptions
        cve_id (str, optional): Specific CVE ID to find
        min_cvss (float, optional): Minimum CVSS score
        max_items (int): Maximum number of items to return
        
    Returns:
        list: List of matching CVE dictionaries
    """
    # Get data from all cached files
    all_cves = []
    for data_file in DATA_FILES:
        file_path = os.path.join(CACHE_DIR, data_file)
        if os.path.exists(file_path):
            items = load_nvd_feed(file_path)
            for item in items:
                cve_info = extract_cve_info(item)
                if cve_info not in all_cves:  # Avoid duplicates
                    all_cves.append(cve_info)
    
    # Apply filters
    results = []
    for cve in all_cves:
        if cve_id and cve_id.upper() == cve.get("id", "").upper():
            results.append(cve)
            continue
        
        if min_cvss is not None and cve.get("cvss_score", 0) < min_cvss:
            continue
        
        if keyword:
            keyword_lower = keyword.lower()
            description = cve.get("description", "").lower()
            id_lower = cve.get("id", "").lower()
            
            if keyword_lower in description or keyword_lower in id_lower:
                results.append(cve)
        elif not cve_id and min_cvss is None:
            # If no filters are applied, include all
            results.append(cve)
    
    # Sort by CVSS score (descending)
    results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    
    return results[:max_items]

def create_training_data_for_classifier(min_entries_per_category=20) -> Tuple[List[str], List[str]]:
    """
    Create training data for the vulnerability classifier
    
    Args:
        min_entries_per_category (int): Minimum number of entries per severity category
        
    Returns:
        tuple: (descriptions, labels) for training
    """
    # Get data from cached files
    all_cves = []
    for data_file in DATA_FILES:
        file_path = os.path.join(CACHE_DIR, data_file)
        if os.path.exists(file_path):
            items = load_nvd_feed(file_path)
            for item in items:
                cve_info = extract_cve_info(item)
                if cve_info not in all_cves:
                    all_cves.append(cve_info)
    
    # Create severity categories based on CVSS score
    critical = []
    high = []
    medium = []
    low = []
    
    for cve in all_cves:
        score = cve.get("cvss_score", 0)
        description = cve.get("description", "")
        
        if not description:
            continue
        
        if score >= 9.0:
            critical.append(description)
        elif score >= 7.0:
            high.append(description)
        elif score >= 4.0:
            medium.append(description)
        else:
            low.append(description)
    
    # Ensure we have at least min_entries_per_category for each category
    all_descriptions = []
    all_labels = []
    
    # Add critical vulnerabilities
    for desc in critical[:max(min_entries_per_category, len(critical))]:
        all_descriptions.append(desc)
        all_labels.append("Critical")
    
    # Add high vulnerabilities
    for desc in high[:max(min_entries_per_category, len(high))]:
        all_descriptions.append(desc)
        all_labels.append("High")
    
    # Add medium vulnerabilities
    for desc in medium[:max(min_entries_per_category, len(medium))]:
        all_descriptions.append(desc)
        all_labels.append("Medium")
    
    # Add low vulnerabilities
    for desc in low[:max(min_entries_per_category, len(low))]:
        all_descriptions.append(desc)
        all_labels.append("Low")
    
    return all_descriptions, all_labels

def extract_remediation_patterns(limit=500) -> Dict[str, Any]:
    """
    Extract common patterns and remediation advice from CVE descriptions
    
    Args:
        limit (int): Maximum number of CVEs to analyze
        
    Returns:
        dict: Dictionary of remediation patterns by vulnerability type
    """
    # Get data from cached files
    all_cves = []
    for data_file in DATA_FILES:
        file_path = os.path.join(CACHE_DIR, data_file)
        if os.path.exists(file_path):
            items = load_nvd_feed(file_path)
            for item in items:
                cve_info = extract_cve_info(item)
                if cve_info not in all_cves:
                    all_cves.append(cve_info)
                
                if len(all_cves) >= limit:
                    break
    
    # Define common vulnerability patterns and associated remediation advice
    pattern_data = {
        "sql_injection": {
            "keywords": ["sql injection", "sqli"],
            "remediation": """
### SQL Injection Remediation

1. **Use Parameterized Queries**
   - Use prepared statements with bound parameters
   - Avoid string concatenation for SQL commands

2. **Input Validation**
   - Implement strict input validation
   - Use allowlist approach for permitted input values

3. **Database Least Privilege**
   - Use database accounts with minimal required permissions
   - Avoid using administrative accounts for application operations

4. **Security Testing**
   - Regularly test for SQL injection vulnerabilities
   - Use automated scanning tools and manual penetration testing
"""
        },
        "cross_site_scripting": {
            "keywords": ["xss", "cross-site scripting", "cross site scripting"],
            "remediation": """
### Cross-Site Scripting (XSS) Remediation

1. **Output Encoding**
   - Implement context-appropriate output encoding
   - Use HTML entity encoding for HTML contexts
   - Use JavaScript encoding for JS contexts

2. **Content Security Policy**
   - Implement a strict Content Security Policy (CSP)
   - Disable inline scripts when possible
   - Use nonce-based CSP for necessary inline scripts

3. **Input Validation**
   - Validate and sanitize user input
   - Use allowlist validation for permitted values

4. **Framework Defense**
   - Use modern frameworks that automatically escape output
   - Keep frameworks updated to latest versions
"""
        },
        "buffer_overflow": {
            "keywords": ["buffer overflow", "buffer overrun", "stack overflow", "heap overflow"],
            "remediation": """
### Buffer Overflow Remediation

1. **Code Updates**
   - Apply vendor patches immediately
   - Update affected software to the latest version

2. **Memory Safety**
   - Use memory-safe programming languages
   - Implement bounds checking on arrays and buffers
   - Use secure string handling functions (strncpy instead of strcpy)

3. **Exploit Mitigations**
   - Enable Address Space Layout Randomization (ASLR)
   - Implement Data Execution Prevention (DEP/NX)
   - Use compiler options like stack canaries

4. **Code Review**
   - Audit code for unsafe memory operations
   - Implement automated static analysis
"""
        },
        "remote_code_execution": {
            "keywords": ["remote code execution", "rce", "code execution", "command execution", "arbitrary code"],
            "remediation": """
### Remote Code Execution Remediation

1. **Patch Management**
   - Apply security patches immediately
   - Implement an automated patch management system
   - Monitor vendor security advisories

2. **Input Validation**
   - Validate and sanitize all user inputs
   - Avoid using user input in system commands
   - Implement allowlist validation for permitted values

3. **Least Privilege**
   - Run services with minimal required privileges
   - Implement proper access controls and user permissions
   - Restrict file system and network access

4. **Network Security**
   - Implement network segmentation
   - Use firewalls to restrict incoming connections
   - Implement intrusion detection/prevention systems
"""
        },
        "authentication_bypass": {
            "keywords": ["authentication bypass", "auth bypass", "bypass authentication", "credential"],
            "remediation": """
### Authentication Bypass Remediation

1. **Authentication Hardening**
   - Implement multi-factor authentication
   - Enforce strong password policies
   - Use secure session management

2. **Access Control Checks**
   - Verify authorization on every request
   - Implement proper access control checks
   - Use role-based access control

3. **Security Headers**
   - Implement secure HTTP headers
   - Use HTTPS for all authentication
   - Set secure and HttpOnly flags on cookies

4. **Security Testing**
   - Regularly test authentication mechanisms
   - Perform credential testing
   - Conduct security code reviews
"""
        },
        "information_disclosure": {
            "keywords": ["information disclosure", "information leak", "sensitive information", "data exposure"],
            "remediation": """
### Information Disclosure Remediation

1. **Error Handling**
   - Implement generic error messages
   - Avoid exposing stack traces or system information
   - Log detailed errors server-side only

2. **Data Classification**
   - Classify sensitive data properly
   - Apply appropriate access controls to sensitive data
   - Encrypt sensitive data in transit and at rest

3. **Security Headers**
   - Implement proper security headers
   - Use Content-Security-Policy to restrict data access
   - Set X-Content-Type-Options to prevent MIME sniffing

4. **Configure Services**
   - Remove default content and documentation
   - Disable directory listing
   - Remove debugging information in production
"""
        },
        "denial_of_service": {
            "keywords": ["denial of service", "dos", "ddos", "service disruption"],
            "remediation": """
### Denial of Service Remediation

1. **Resource Limiting**
   - Implement rate limiting
   - Set connection timeouts
   - Use resource quotas for users or services

2. **Traffic Filtering**
   - Configure firewalls to block malicious traffic
   - Use DDoS protection services
   - Implement traffic anomaly detection

3. **Application Hardening**
   - Optimize application performance
   - Implement caching when possible
   - Design for graceful degradation under load

4. **Architecture**
   - Distribute services across multiple servers
   - Implement load balancing
   - Design for scalability
"""
        },
        "path_traversal": {
            "keywords": ["path traversal", "directory traversal", "file inclusion"],
            "remediation": """
### Path Traversal Remediation

1. **Input Validation**
   - Validate and sanitize file paths
   - Use allowlists for permitted file access
   - Reject requests containing path traversal sequences

2. **File System Access**
   - Use indirect file references (e.g., database keys)
   - Restrict file system access to specific directories
   - Apply proper file permissions

3. **Web Server Configuration**
   - Configure web server to prevent access to sensitive directories
   - Use web application firewalls to detect path traversal attempts
   - Implement proper access controls

4. **Application Design**
   - Avoid passing user-supplied input to file system functions
   - Use storage abstractions rather than direct file access
   - Implement proper error handling for file operations
"""
        },
        "cryptographic": {
            "keywords": ["cryptographic", "weak crypto", "weak encryption", "weak cipher", "weak key"],
            "remediation": """
### Cryptographic Weakness Remediation

1. **Update Cryptographic Implementations**
   - Replace weak algorithms (MD5, SHA-1, DES, etc.)
   - Use strong algorithms (AES-256, SHA-256 or better)
   - Implement proper key management

2. **Protocol Security**
   - Disable outdated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
   - Use TLS 1.2 or TLS 1.3
   - Configure secure cipher suites

3. **Key Management**
   - Use sufficient key lengths (RSA: 2048+ bits, ECC: 256+ bits)
   - Implement proper key rotation
   - Protect key material with appropriate access controls

4. **Testing**
   - Validate cryptographic implementations
   - Use automated scanning tools
   - Perform regular security reviews
"""
        },
        "privilege_escalation": {
            "keywords": ["privilege escalation", "privilege elevation", "privileges"],
            "remediation": """
### Privilege Escalation Remediation

1. **Patch Management**
   - Apply security patches promptly
   - Monitor vendor advisories for security updates
   - Implement automated patch management

2. **Least Privilege**
   - Run services with minimal required privileges
   - Implement proper access controls
   - Use sandboxing where appropriate

3. **Access Control**
   - Validate authorization on all privileged actions
   - Implement proper permission checks
   - Use role-based access control

4. **Security Monitoring**
   - Monitor for suspicious privilege changes
   - Implement file integrity monitoring
   - Log and alert on unauthorized access attempts
"""
        }
    }
    
    # Count occurrences of each pattern in CVE descriptions
    for cve in all_cves:
        description = cve.get("description", "").lower()
        
        for pattern_key, pattern_info in pattern_data.items():
            for keyword in pattern_info["keywords"]:
                if keyword in description:
                    if "count" not in pattern_info:
                        pattern_info["count"] = 0
                    pattern_info["count"] += 1
                    
                    if "examples" not in pattern_info:
                        pattern_info["examples"] = []
                    
                    if len(pattern_info["examples"]) < 5:  # Limit examples to 5 per pattern
                        pattern_info["examples"].append({
                            "id": cve.get("id", ""),
                            "description": cve.get("description", ""),
                            "cvss_score": cve.get("cvss_score", 0)
                        })
                    
                    break  # Count each CVE only once per pattern
    
    return pattern_data

def generate_remediation_training_data() -> Dict[str, List[Dict[str, Any]]]:
    """
    Generate training data for the remediation suggestion system
    
    Returns:
        dict: Dictionary of remediation data by type
    """
    # Extract remediation patterns from CVE descriptions
    pattern_data = extract_remediation_patterns()
    
    # Transform into format needed for remediation system
    remediation_data = {
        "network": [],
        "os": [],
        "application": [],
        "web": []
    }
    
    # Map pattern types to vulnerability types
    type_mapping = {
        "sql_injection": "web",
        "cross_site_scripting": "web",
        "buffer_overflow": "os",
        "remote_code_execution": "network",
        "authentication_bypass": "application",
        "information_disclosure": "application",
        "denial_of_service": "network",
        "path_traversal": "application",
        "cryptographic": "application",
        "privilege_escalation": "os"
    }
    
    for pattern_key, pattern_info in pattern_data.items():
        vuln_type = type_mapping.get(pattern_key, "network")
        
        # Extract data from the pattern_info dictionary
        keywords = pattern_info.get("keywords", [])
        remediation = pattern_info.get("remediation", "")
        
        remediation_entry = {
            "type": vuln_type,
            "keywords": keywords,
            "remediation": remediation,
            "title": pattern_key.replace("_", " ").title()
        }
        
        remediation_data[vuln_type].append(remediation_entry)
    
    return remediation_data

if __name__ == "__main__":
    # Example usage
    print("Fetching NVD data...")
    cves = fetch_nvd_data(years=[2023, 2024])
    print(f"Found {len(cves)} CVEs")
    
    # Show a sample
    if cves:
        sample = cves[0]
        print("\nSample CVE:")
        print(f"ID: {sample.get('id')}")
        print(f"Title: {sample.get('title')}")
        print(f"CVSS Score: {sample.get('cvss_score')}")
        print(f"Description: {sample.get('description', '')[:100]}...")
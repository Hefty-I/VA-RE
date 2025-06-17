import json
import os
import requests
import time
import datetime
import random
from utils import get_host_os_info
from nvd_converter import convert_nvd_to_structure

def fetch_from_nvd_api(days_back=30, max_entries=100, api_key=None):
    """
    Fetch vulnerability data from the NVD API
    
    Args:
        days_back (int): Number of days to look back for vulnerabilities
        max_entries (int): Maximum number of entries to return
        api_key (str): Optional NVD API key for authenticated requests
    
    Returns:
        list: List of vulnerability dictionaries
    """
    # Calculate the start date (days_back days ago)
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=days_back)
    
    # Format dates for the API
    start_date_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
    end_date_str = end_date.strftime("%Y-%m-%dT23:59:59.999")
    
    # Base URL for the NVD API
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Query parameters
    params = {
        "pubStartDate": start_date_str,
        "pubEndDate": end_date_str,
        "resultsPerPage": max_entries
    }
    
    # Headers with API key if provided
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        # Make the request to the NVD API
        response = requests.get(base_url, params=params, headers=headers)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            
            # Process each vulnerability from the API
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                
                # Get description
                descriptions = cve.get("descriptions", [])
                description = "No description available"
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "No description available")
                        break
                
                # Get CVSS score
                cvss_score = 0.0
                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v30 = metrics.get("cvssMetricV30", [])
                
                if cvss_v31:
                    cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
                elif cvss_v30:
                    cvss_score = cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)
                
                # Get references
                references = []
                for ref in cve.get("references", []):
                    url = ref.get("url", "")
                    if url:
                        references.append(url)
                
                # Create vulnerability dictionary
                vulnerability = {
                    "id": cve_id,
                    "title": cve.get("vulnStatus", "Vulnerability") + ": " + cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "attack_vector": "Unknown",
                    "affected_systems": ["All"],
                    "references": references,
                    "type": "network" if "network" in description.lower() else "os",
                    "status": "Open",
                    "history": []
                }
                
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
        else:
            print(f"Error fetching from NVD API: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"Exception when fetching from NVD API: {e}")
        return []
def fetch_real_nvd_data():
    """
    Fetch real vulnerability data from NVD and convert to structured format
    
    Returns:
        list: List of vulnerability dictionaries
    """
    # Path to the NVD JSON file
    nvd_path = "data/nvdcve-1.1-2023.json"
    
    # Convert NVD JSON to structured format
    convert_nvd_to_structure(nvd_path)
    
    # Load the structured data
    with open("cve_dataset.json", 'r') as f:
        vulnerabilities = json.load(f).get("vulnerabilities", [])
    
    return vulnerabilities
    

def fetch_nvd_data(days_back=30, max_entries=100, use_api=False, api_key=None):
    """
    Fetch vulnerability data from NVD or load from sample data
    
    Args:
        days_back (int): Number of days to look back for vulnerabilities
        max_entries (int): Maximum number of entries to return
        use_api (bool): Whether to use the NVD API (requires api_key)
        api_key (str): Optional NVD API key for authenticated requests
    
    Returns:
        list: List of vulnerability dictionaries
    """
    # Path to sample data
    sample_data_path = "data/nvd_sample.json"
    history_data_path = "data/vulnerability_history.json"
    
    # Try to fetch from NVD API if requested
    if use_api:
        try:
            vulnerabilities = fetch_from_nvd_api(days_back, max_entries, api_key)
            if vulnerabilities:
                # Save the fetched data for offline use
                os.makedirs("data", exist_ok=True)
                with open(sample_data_path, 'w') as f:
                    json.dump(vulnerabilities, f, indent=2)
                return vulnerabilities
        except Exception as e:
            print(f"Error fetching from NVD API: {e}")
    
    # Load from sample file if API fetch failed or not requested
    if os.path.exists(sample_data_path):
        try:
            with open(sample_data_path, 'r') as f:
                sample_data = json.load(f)
                # If we have history data, merge with sample data
                if os.path.exists(history_data_path):
                    try:
                        with open(history_data_path, 'r') as hf:
                            history_data = json.load(hf)
                            # Add status field to sample data from history data if available
                            for vuln in sample_data:
                                vuln_id = vuln.get("id")
                                if vuln_id in history_data:
                                    vuln["status"] = history_data[vuln_id].get("status", "Open")
                                    vuln["history"] = history_data[vuln_id].get("history", [])
                                else:
                                    vuln["status"] = "Open"
                                    vuln["history"] = []
                    except Exception as e:
                        print(f"Error loading history data: {e}")
                return sample_data
        except Exception as e:
            print(f"Error loading sample data: {e}")
    
    # If we can't load from file, generate some sample data
    vulnerabilities = []
    
    # OS info to generate relevant vulnerabilities
    os_info = get_host_os_info()
    os_type = os_info.get("type", "Unknown").lower()
    os_version = os_info.get("version", "Unknown")
    
    # Network vulnerabilities
    network_vulns = [
        {
            "id": "CVE-2021-44228",
            "title": "Log4j Remote Code Execution Vulnerability (Log4Shell)",
            "description": "A critical vulnerability in Apache Log4j allows attackers to execute arbitrary code by submitting a specially crafted request that enables LDAP JNDI injection.",
            "cvss_score": 10.0,
            "attack_vector": "Network",
            "affected_systems": ["All"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "type": "network"
        },
        {
            "id": "CVE-2023-23397",
            "title": "Microsoft Outlook Elevation of Privilege Vulnerability",
            "description": "A vulnerability in Microsoft Outlook allows attackers to leak Net-NTLMv2 hash information to an attacker-controlled SMB server when a specially crafted email is processed.",
            "cvss_score": 9.8,
            "attack_vector": "Network",
            "affected_systems": ["Windows"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"],
            "type": "network"
        },
        {
            "id": "CVE-2022-22965",
            "title": "Spring Framework RCE Vulnerability (Spring4Shell)",
            "description": "A vulnerability in the Spring Framework allows attackers to execute arbitrary remote code on the target system.",
            "cvss_score": 9.8,
            "attack_vector": "Network",
            "affected_systems": ["All"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            "type": "network"
        },
        {
            "id": "CVE-2021-1675",
            "title": "Windows Print Spooler Elevation of Privilege Vulnerability (PrintNightmare)",
            "description": "A remote code execution vulnerability in the Windows Print Spooler service allows attackers to execute arbitrary code with SYSTEM privileges.",
            "cvss_score": 8.8,
            "attack_vector": "Network",
            "affected_systems": ["Windows"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1675"],
            "type": "network"
        },
        {
            "id": "CVE-2022-47986",
            "title": "IBM Db2 SQL Injection Vulnerability",
            "description": "A vulnerability in IBM Db2 allows remote attackers to execute arbitrary SQL statements on the affected system.",
            "cvss_score": 7.2,
            "attack_vector": "Network",
            "affected_systems": ["All"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-47986"],
            "type": "network"
        },
        {
            "id": "CVE-2023-0215",
            "title": "OpenSSL X.509 Name Constraints Buffer Overflow",
            "description": "A vulnerability in OpenSSL's X.509 certificate verification allows remote attackers to trigger a buffer overflow, potentially enabling arbitrary code execution.",
            "cvss_score": 6.5,
            "attack_vector": "Network",
            "affected_systems": ["All"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0215"],
            "type": "network"
        }
    ]
    
    # OS vulnerabilities
    windows_vulns = [
        {
            "id": "CVE-2023-35311",
            "title": "Windows NTLM EoP Vulnerability",
            "description": "A vulnerability in Windows NTLM authentication allows local attackers to elevate privileges.",
            "cvss_score": 7.8,
            "attack_vector": "Local",
            "affected_systems": ["Windows"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-35311"],
            "type": "os"
        },
        {
            "id": "CVE-2023-21768",
            "title": "Windows Graphics Component Remote Code Execution Vulnerability",
            "description": "A vulnerability in the Windows Graphics Component allows remote attackers to execute arbitrary code with SYSTEM privileges.",
            "cvss_score": 8.5,
            "attack_vector": "Local",
            "affected_systems": ["Windows"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-21768"],
            "type": "os"
        }
    ]
    
    linux_vulns = [
        {
            "id": "CVE-2022-0847",
            "title": "Linux Kernel 'Dirty Pipe' Vulnerability",
            "description": "A vulnerability in the Linux kernel allows local attackers to overwrite data in read-only files and potentially elevate privileges.",
            "cvss_score": 7.8,
            "attack_vector": "Local",
            "affected_systems": ["Linux"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
            "type": "os"
        },
        {
            "id": "CVE-2022-3786",
            "title": "OpenSSL X.509 Email Address Buffer Overflow",
            "description": "A vulnerability in OpenSSL's X.509 email address verification allows remote attackers to trigger a buffer overflow.",
            "cvss_score": 6.5,
            "attack_vector": "Network",
            "affected_systems": ["Linux"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3786"],
            "type": "os"
        }
    ]
    
    macos_vulns = [
        {
            "id": "CVE-2023-32434",
            "title": "macOS Kernel Privilege Escalation Vulnerability",
            "description": "A vulnerability in the macOS kernel allows local attackers to elevate privileges to root.",
            "cvss_score": 7.8,
            "attack_vector": "Local",
            "affected_systems": ["macOS"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32434"],
            "type": "os"
        },
        {
            "id": "CVE-2023-32435",
            "title": "macOS Safari WebKit Remote Code Execution",
            "description": "A vulnerability in WebKit allows remote attackers to execute arbitrary code when processing specially crafted web content.",
            "cvss_score": 8.2,
            "attack_vector": "Network",
            "affected_systems": ["macOS"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32435"],
            "type": "os"
        }
    ]
    
    # Add all network vulnerabilities
    vulnerabilities.extend(network_vulns)
    
    # Add OS-specific vulnerabilities
    if "windows" in os_type:
        vulnerabilities.extend(windows_vulns)
    elif "linux" in os_type:
        vulnerabilities.extend(linux_vulns)
    elif "mac" in os_type or "darwin" in os_type:
        vulnerabilities.extend(macos_vulns)
    
    # Add some random generic vulnerabilities to reach max_entries
    while len(vulnerabilities) < max_entries:
        # Create a generic vulnerability
        cve_year = random.randint(2020, 2023)
        cve_number = random.randint(10000, 99999)
        cve_id = f"CVE-{cve_year}-{cve_number}"
        
        # Random CVSS score
        cvss_score = round(random.uniform(4.0, 10.0), 1)
        
        # Random vulnerability type
        vuln_type = random.choice(["os", "network"])
        
        # Create vulnerability
        vulnerability = {
            "id": cve_id,
            "title": f"Generic {vuln_type.upper()} Vulnerability",
            "description": f"This is a simulated vulnerability for {os_type} systems.",
            "cvss_score": cvss_score,
            "attack_vector": "Network" if vuln_type == "network" else "Local",
            "affected_systems": ["All"] if vuln_type == "network" else [os_type.capitalize()],
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            "type": vuln_type
        }
        
        vulnerabilities.append(vulnerability)
    
    # Return limited number of vulnerabilities
    return vulnerabilities[:max_entries]

def update_vulnerability_status(vulnerability_id, new_status, notes=None):
    """
    Update the status of a vulnerability and add an entry to its history
    
    Args:
        vulnerability_id (str): ID of the vulnerability to update
        new_status (str): New status (Open, In Progress, Mitigated, Resolved, False Positive)
        notes (str, optional): Additional notes about the status change
    
    Returns:
        bool: True if successful, False otherwise
    """
    history_data_path = "data/vulnerability_history.json"
    
    # Load existing history data if available
    history_data = {}
    if os.path.exists(history_data_path):
        try:
            with open(history_data_path, 'r') as f:
                history_data = json.load(f)
        except Exception as e:
            print(f"Error loading history data: {e}")
            # Create a new history data file if there was an error
    
    # Create timestamp for the status change
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a history entry
    history_entry = {
        "status": new_status,
        "timestamp": timestamp,
        "notes": notes if notes else f"Status changed to {new_status}"
    }
    
    # Update or create the vulnerability entry in history
    if vulnerability_id in history_data:
        history_data[vulnerability_id]["status"] = new_status
        history_data[vulnerability_id]["history"].append(history_entry)
    else:
        history_data[vulnerability_id] = {
            "status": new_status,
            "history": [history_entry]
        }
    
    # Save the updated history data
    try:
        os.makedirs("data", exist_ok=True)
        with open(history_data_path, 'w') as f:
            json.dump(history_data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving history data: {e}")
        return False

def get_vulnerability_history(vulnerability_id=None):
    """
    Get the history of status changes for vulnerabilities
    
    Args:
        vulnerability_id (str, optional): ID of a specific vulnerability to get history for
                                          If None, returns all vulnerability histories
    
    Returns:
        dict: Dictionary of vulnerability histories or a specific vulnerability's history
    """
    history_data_path = "data/vulnerability_history.json"
    
    if not os.path.exists(history_data_path):
        return {} if vulnerability_id is None else None
    
    try:
        with open(history_data_path, 'r') as f:
            history_data = json.load(f)
            
        if vulnerability_id is not None:
            return history_data.get(vulnerability_id)
        return history_data
    except Exception as e:
        print(f"Error loading vulnerability history: {e}")
        return {} if vulnerability_id is None else None

def process_vulnerability_data(vulnerabilities, os_info, network_info):
    """
    Process raw vulnerability data to match system characteristics
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        os_info (dict): Information about the operating system
        network_info (dict): Information about the network
    
    Returns:
        list: List of relevant vulnerability dictionaries
    """
    relevant_vulnerabilities = []
    os_type = os_info.get("type", "Unknown").lower()
    
    # Load history data to add status and history to found vulnerabilities
    history_data = get_vulnerability_history()
    
    for vuln in vulnerabilities:
        # Check if the vulnerability applies to the current OS
        affects_current_os = False
        
        if "All" in vuln.get("affected_systems", []):
            affects_current_os = True
        elif "Windows" in vuln.get("affected_systems", []) and "windows" in os_type:
            affects_current_os = True
        elif "Linux" in vuln.get("affected_systems", []) and "linux" in os_type:
            affects_current_os = True
        elif "macOS" in vuln.get("affected_systems", []) and ("mac" in os_type or "darwin" in os_type):
            affects_current_os = True
        
        # Check if this is a network vulnerability and if the relevant ports are open
        is_network_vuln = vuln.get("type") == "network"
        open_ports = network_info.get("open_ports", [])
        
        # Apply some filtering to simulate relevance
        if affects_current_os:
            if is_network_vuln:
                # For network vulnerabilities, include with a probability
                if random.random() < 0.7:  # 70% chance to include network vulnerabilities
                    # Add status and history from history data if available
                    vuln_id = vuln.get("id")
                    if vuln_id in history_data:
                        vuln["status"] = history_data[vuln_id].get("status", "Open")
                        vuln["history"] = history_data[vuln_id].get("history", [])
                    else:
                        vuln["status"] = "Open"
                        vuln["history"] = []
                    
                    relevant_vulnerabilities.append(vuln)
            else:
                # For OS vulnerabilities, include with a higher probability
                if random.random() < 0.9:  # 90% chance to include OS vulnerabilities
                    # Add status and history from history data if available
                    vuln_id = vuln.get("id")
                    if vuln_id in history_data:
                        vuln["status"] = history_data[vuln_id].get("status", "Open")
                        vuln["history"] = history_data[vuln_id].get("history", [])
                    else:
                        vuln["status"] = "Open"
                        vuln["history"] = []
                    
                    relevant_vulnerabilities.append(vuln)
    
    return relevant_vulnerabilities

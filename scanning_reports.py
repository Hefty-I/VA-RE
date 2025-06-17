import os
import json
import socket
import subprocess
import platform
import datetime
import random
import time
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
import xml.etree.ElementTree as ET
import xmltodict
from typing import List, Dict, Any, Optional, Tuple
from nvd_feed_processor import search_cve_data, extract_remediation_patterns
# from nvd_feed_processor import get_remediation_for_cve
import requests

# Local imports
from utils import get_host_os_info

# Constants
SCAN_RESULTS_DIR = "data/scanner_results"
REPORTS_DIR = "reports"
NVD_CACHE_DIR = "data/nvd_cache"

# Ensure directories exist
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(NVD_CACHE_DIR, exist_ok=True)

# Configure your API keys


#############################################
# SCANNING FUNCTIONALITY
#############################################

def scan_system(target_ip="127.0.0.1", port_range="1-1000", scan_type="basic", nessus_keys=None):
    """
    Main scanning function that orchestrates different scanning components
    
    Args:
        target_ip (str): IP address to scan, defaults to localhost
        port_range (str): Range of ports to scan in format "start-end"
        scan_type (str): Type of scan to perform ("basic", "comprehensive", "external")
    
    Returns:
        dict: Dictionary containing scan results
    """
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target_ip,
        "scan_type": scan_type
    }
    
    # Get OS information
    results["os_info"] = get_host_os_info()
    
    # Scan for open ports
    results["open_ports"] = get_open_ports(target_ip, port_range)
    
    # Check firewall configuration
    results["firewall_config"] = check_firewall_config()
    
    try:
        if scan_type == "nmap":
            nmap_results = scan_with_nmap(target_ip, port_range)
            if "error" not in nmap_results:
                results.update(nmap_results)
                results = enhance_with_nvd_data(results)
                return results
        
        elif scan_type == "openvas":
            openvas_results = scan_with_openvas(target_ip)
            if "error" not in openvas_results:
                results.update(openvas_results)
                results = enhance_with_nvd_data(results)
                return results
        
        elif scan_type == "nessus":
            nessus_results = scan_with_nessus(target_ip, nessus_keys)
            if "error" not in nessus_results:
                results.update(nessus_results)
                results = enhance_with_nvd_data(results)
                return results
        
        elif scan_type == "basic":
            results["scan_type"] = "basic"
            results["open_ports"] = get_open_ports(target_ip, port_range)
            results["firewall_config"] = check_firewall_config()
    
    except Exception as e:
        results["error"] = str(e)
        print(f"Error during {scan_type} scan: {e}")
    
    if "error" not in results:
        results = enhance_with_nvd_data(results)
        results["vulnerabilities"] = convert_scanner_results_to_vulnerabilities(results)
    
    # Save the scan results
    save_scan_results(results)
    
    return results
def enhance_with_nvd_data(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance scan results with NVD data and remediation suggestions
    
    Args:
        scan_results (dict): Raw scan results
        
    Returns:
        dict: Enhanced scan results with NVD mappings
    """
    # Load remediation patterns
    remediation_patterns = extract_remediation_patterns()
    scanner_type = scan_results.get("scanner", "unknown")
    
    if scanner_type == "nmap":
        # Process open ports for network vulnerabilities
        if "open_ports" in scan_results:
            for port_info in scan_results["open_ports"]:
                service = port_info.get("service", "").lower()
                product = port_info.get("product", "").lower()
                version = port_info.get("version", "")

                # Search NVD for relevant CVEs
                search_terms = []
                if product and version:
                    search_terms.append(f"{product} {version}")
                if service:
                    search_terms.append(service)

                cves = []
                for term in search_terms:
                    cves.extend(search_cve_data(keyword=term, max_items=3))

                # Add unique CVEs to port info
                port_info["related_cves"] = []
                seen_cves = set()

                for cve in cves:
                    if cve["id"] not in seen_cves:
                        seen_cves.add(cve["id"])
                        # Add remediation from patterns if available
                        cve["remediation"] = get_remediation_for_cve(cve, remediation_patterns)
                        port_info["related_cves"].append(cve)
    
    elif scanner_type == "nessus" or scanner_type == "openvas":
        # Process findings from vulnerability scanners
        for host in scan_results.get("hosts", []):
            for finding in host.get("findings", []):
                # For findings that already have CVE IDs
                if "cve" in finding and finding["cve"]:
                    cve_id = finding["cve"].split(",")[0].strip()  # Take first CVE if multiple
                    cves = search_cve_data(cve_id=cve_id, max_items=1)
                    if cves:
                        finding["related_cves"] = [{
                            **cves[0],
                            "remediation": finding.get("solution", get_remediation_for_cve(cves[0], remediation_patterns))
                        }]
                # For findings without CVE IDs but with plugin names
                elif "plugin_name" in finding:
                    cves = search_cve_data(keyword=finding["plugin_name"], max_items=1)
                    if cves:
                        finding["related_cves"] = [{
                            **cves[0],
                            "remediation": finding.get("solution", get_remediation_for_cve(cves[0], remediation_patterns))
                        }]
    
    # Process OS info for system vulnerabilities
    if "os_info" in scan_results:
        os_type = scan_results["os_info"].get("type", "").lower()
        os_version = scan_results["os_info"].get("version", "")
        
        if os_type and os_version:
            search_term = f"{os_type} {os_version}"
            os_cves = search_cve_data(keyword=search_term, max_items=5)
            
            # Add unique CVEs to OS info
            scan_results["os_info"]["related_cves"] = []
            seen_cves = set()
            
            for cve in os_cves:
                if cve["id"] not in seen_cves:
                    seen_cves.add(cve["id"])
                    # Add remediation from patterns if available
                    cve["remediation"] = get_remediation_for_cve(cve, remediation_patterns)
                    scan_results["os_info"]["related_cves"].append(cve)
    
    return scan_results
def get_remediation_for_cve(cve: Dict[str, Any], patterns: Dict[str, Any]) -> str:
    """
    Get remediation suggestion for a CVE based on vulnerability patterns
    
    Args:
        cve (dict): CVE information
        patterns (dict): Remediation patterns from NVD data
        
    Returns:
        str: Remediation suggestion
    """
    description = cve.get("description", "").lower()
    
    # Check against known patterns
    for pattern, pattern_info in patterns.items():
        for keyword in pattern_info.get("keywords", []):
            if keyword in description:
                return pattern_info.get("remediation", "No specific remediation available.")
    
    # Fallback to generic remediation
    cvss_score = cve.get("cvss_score", 0)
    if cvss_score >= 9.0:
        return "Critical vulnerability - Apply patches immediately and isolate affected systems."
    elif cvss_score >= 7.0:
        return "High severity vulnerability - Update to latest version and review configurations."
    elif cvss_score >= 4.0:
        return "Medium severity vulnerability - Update when possible and monitor for exploits."
    else:
        return "Low severity vulnerability - Consider updating during next maintenance window."
    
def get_open_ports(target_ip="127.0.0.1", port_range="1-1000"):
    """
    Scan for open ports using socket connections
    
    Args:
        target_ip (str): IP address to scan
        port_range (str): Range of ports to scan in format "start-end"
    
    Returns:
        list: List of dictionaries containing port information
    """
    open_ports = []
    
    try:
        # Parse port range
        start_port, end_port = map(int, port_range.split('-'))
        
        # For demonstration and testing purposes
        # In a real implementation, we would use nmap or similar tools
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP Alternate"
        }
        
        # Limit port range for demonstration
        max_ports_to_check = min(100, end_port - start_port + 1)
        ports_to_check = list(range(start_port, start_port + max_ports_to_check))
        
        # Add some common ports if they're in range
        for common_port in common_ports.keys():
            if start_port <= common_port <= end_port and common_port not in ports_to_check:
                ports_to_check.append(common_port)
        
        for port in ports_to_check:
            # Simulate port scanning
            # In a real implementation, we would check if the port is actually open
            if port in common_ports or random.random() < 0.05:  # 5% chance for random port to be open
                service = common_ports.get(port, "Unknown")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open",
                    "version": "Unknown"  # In a real implementation, we would use version detection
                })
                
                # Add vulnerability information for certain services
                if service == "SSH" and random.random() < 0.3:
                    open_ports[-1]["vulnerabilities"] = ["Weak SSH configuration", "Outdated SSH version"]
                elif service == "HTTP" and random.random() < 0.4:
                    open_ports[-1]["vulnerabilities"] = ["Outdated web server", "TLS configuration issues"]
    
    except Exception as e:
        print(f"Error scanning ports: {e}")
    
    return open_ports

def check_firewall_config():
    """
    Check firewall configuration and identify potential issues
    
    Returns:
        dict: Dictionary containing firewall configuration and issues
    """
    firewall_info = {
        "enabled": True,
        "type": "Unknown",
        "issues": []
    }
    
    # Get OS to determine firewall type
    os_type = platform.system().lower()
    
    # Simulate firewall checking
    # In a real implementation, we would check actual firewall rules and configuration
    if os_type == "windows":
        firewall_info["type"] = "Windows Firewall"
        
        # Simulate some issues
        if random.random() < 0.4:
            firewall_info["issues"].append({
                "type": "configuration",
                "description": "Default inbound rules are too permissive",
                "severity": "Medium"
            })
    
    elif os_type == "linux":
        firewall_info["type"] = "iptables/UFW"
        
        # Simulate some issues
        if random.random() < 0.3:
            firewall_info["issues"].append({
                "type": "configuration",
                "description": "ICMP echo requests allowed from any source",
                "severity": "Low"
            })
    
    elif os_type == "darwin":  # macOS
        firewall_info["type"] = "pf/macOS Firewall"
        
        # Simulate some issues
        if random.random() < 0.2:
            firewall_info["issues"].append({
                "type": "configuration",
                "description": "Application firewall is disabled",
                "severity": "Medium"
            })
    
    # Add some common issues with a random chance
    if random.random() < 0.3:
        firewall_info["issues"].append({
            "type": "rule",
            "description": "Unnecessary ports exposed to the internet",
            "severity": "High"
        })
    
    if random.random() < 0.2:
        firewall_info["issues"].append({
            "type": "rule",
            "description": "No egress filtering configured",
            "severity": "Medium"
        })
    
    return firewall_info

#############################################
# EXTERNAL SCANNER INTEGRATION
#############################################

def scan_with_nmap(target_ip: str, port_range: str = "1-1000", scan_args: str = "-sV") -> Dict[str, Any]:
    """
    Perform a scan using the Nmap security scanner
    
    Args:
        target_ip (str): IP address or hostname to scan
        port_range (str): Range of ports to scan (e.g., "1-1000")
        scan_args (str): Additional Nmap arguments
        
    Returns:
        dict: Scan results
    """
    try:
        # Check if nmap library is available
        import nmap
        
        # Initialize nmap scanner
        nm = nmap.PortScanner()

        # Run the scan with version detection
        if "-sV" not in scan_args:
            scan_args += " -sV"  # Ensure version detection is enabled
        
        # Run the scan
        print(f"Starting Nmap scan on {target_ip} (ports {port_range})...")
        nm.scan(hosts=target_ip, ports=port_range, arguments=scan_args)
        
        # Process the results
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nmap",
            "scan_args": scan_args,
            "target": target_ip,
            "hosts": [],
            "open_ports": [],
            "firewall_config": check_firewall_config()
        }
        
        # Extract host information
        for host in nm.all_hosts():
            host_data = {
                "host": host,
                "status": nm[host].state(),
                "os_detection": nm[host].get('osmatch', []),
                "ports": []
            }
            
            # Extract port information
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_data = nm[host][proto][port]
                    host_data["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_data.get("state", ""),
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", "")
                    })
            
            results["hosts"].append(host_data)
        
        # Save results to file
        save_scan_results(results)
        
        print(f"Nmap scan completed: found {len(results['hosts'])} hosts and {sum(len(h.get('ports', [])) for h in results['hosts'])} open ports")
        return results
    
    except ImportError:
        print("Python-nmap library is not installed. Using basic port scanner instead.")
        # Fall back to basic port scanning
        open_ports = get_open_ports(target_ip, port_range)
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "basic_port_scan",
            "target": target_ip,
            "hosts": [{
                "host": target_ip,
                "status": "up",
                "ports": open_ports
            }]
        }
        save_scan_results(results)
        return results
    
    except Exception as e:
        print(f"Error during Nmap scan: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nmap",
            "target": target_ip,
            "hosts": []
        }
#############################################
# Nessus SCANNER
##############################################
def scan_with_nessus(target_ip: str, api_keys: dict) -> Dict[str, Any]:
    """
    Perform a direct Nessus scan using the Nessus API with API key authentication
    
    Args:
        target_ip (str): IP address or hostname to scan
        api_keys (dict): Dictionary with access_key and secret_key for Nessus API
        
    Returns:
        dict: Scan results
    """
    try:
        from tenable.io import TenableIO
        from tenable.errors import TenableError
        
        # Initialize Nessus client with API keys
        tio = TenableIO(
            access_key=api_keys['4d996f5951ede660782aebbc40c83a00167d16c2b07f174f84e81542505f059f'],
            secret_key=api_keys['efecf669b29be2bda64035b905e5ed93fb7ae292c600e76f6855ec9812b1aa2e']
        )
        
        # Create scan
        scan_name = f"Vulnerability Scan - {target_ip}"
        
        # Use a basic network scan template
        scan = tio.scans.create(
            name=scan_name,
            template='basic',
            targets=[target_ip],
            text_targets=target_ip
        )
        
        # Launch the scan
        scan.launch()
        
        # Wait for completion
        while True:
            time.sleep(30)  # Check every 30 seconds
            scan = tio.scans.details(scan.id)
            if scan['status'] == 'completed':
                break
            elif scan['status'] in ['canceled', 'aborted']:
                raise Exception(f"Scan was {scan['status']}")
        
        # Download the scan results
        report = tio.scans.export(scan.id, format='nessus')
        
        # Process results into standardized format
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "target": target_ip,
            "hosts": []
        }
        
        # Parse the report (simplified example)
        for host in report.get('hosts', []):
            host_data = {
                "host": host.get('name', host.get('hostname', target_ip)),
                "findings": []
            }
            
            for item in host.get('items', []):
                finding = {
                    "plugin_id": item.get('plugin_id'),
                    "plugin_name": item.get('plugin_name'),
                    "severity": _convert_severity(item.get('severity', 0)),
                    "port": item.get('port'),
                    "description": item.get('description'),
                    "solution": item.get('solution'),
                    "cve": item.get('cve'),
                    "cvss_base_score": float(item.get('cvss_base_score', 0))
                }
                host_data["findings"].append(finding)
            
            results["hosts"].append(host_data)
        
        return results
    
    except ImportError:
        print("Tenable.io library not available, falling back to basic scanning")
        return scan_with_nessus_cli(target_ip, api_keys)
    except TenableError as e:
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "target": target_ip
        }
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "target": target_ip
        }

def _convert_severity(severity_code: int) -> str:
    """Convert numeric severity to text"""
    severity_map = {
        0: 'Info',
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Critical'
    }
    return severity_map.get(severity_code, 'Unknown')

def scan_with_nessus_cli(target_ip: str, api_keys: dict) -> Dict[str, Any]:
    """
    Perform Nessus scan using CLI commands with API keys
    
    Args:
        target_ip (str): IP address to scan
        api_keys (dict): Dictionary with access_key and secret_key
        
    Returns:
        dict: Scan results
    """
    try:
        # Using curl as an example - you might need to adjust based on your setup
        auth_header = f"X-ApiKeys: accessKey={api_keys['access_key']}; secretKey={api_keys['secret_key']}"
        
        # Create scan (simplified example)
        create_cmd = f"""curl -X POST -H '{auth_header}' -H 'Content-Type: application/json' \
            -d '{{"uuid":"template-uuid", "settings":{{"name":"CLI Scan {target_ip}", "text_targets":"{target_ip}"}}}}' \
            https://localhost:8834/scans"""
        
        scan_id = subprocess.check_output(create_cmd, shell=True).json().get('scan', {}).get('id')
        
        if not scan_id:
            raise Exception("Failed to create scan")
        
        # Launch scan
        launch_cmd = f"curl -X POST -H '{auth_header}' https://localhost:8834/scans/{scan_id}/launch"
        subprocess.check_output(launch_cmd, shell=True)
        
        # Wait for completion (simplified)
        while True:
            time.sleep(30)
            status_cmd = f"curl -H '{auth_header}' https://localhost:8834/scans/{scan_id}"
            status = subprocess.check_output(status_cmd, shell=True).json().get('info', {}).get('status')
            if status == 'completed':
                break
        
        # Download report
        report_cmd = f"curl -H '{auth_header}' https://localhost:8834/scans/{scan_id}/export -o nessus_report.xml"
        subprocess.check_output(report_cmd, shell=True)
        
        # Process the XML report (would use your existing XML parsing logic)
        return parse_nessus_report("nessus_report.xml")
    
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "target": target_ip
        }

#############################################
# OpenVAS SCANNER
##############################################
def scan_with_openvas(target_ip: str, credentials: dict = None) -> Dict[str, Any]:
    """
    Perform a direct OpenVAS scan using the OpenVAS API
    
    Args:
        target_ip (str): IP address or hostname to scan
        credentials (dict): Dictionary with username, password, and host for OpenVAS
    
    Returns:
        dict: Scan results
    """
    try:
        # Try to import OpenVAS API library
        from gvm.connections import TLSConnection  # Changed from UnixSocketConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
        
        # Initialize connection based on platform
        if platform.system().lower() == 'linux':
            # Linux can use either TLS or Unix socket
            use_tls = credentials.get('use_tls', False) if credentials else False
            if use_tls:
                connection = TLSConnection(
                    hostname=credentials.get('hostname', 'localhost'),
                    port=credentials.get('port', 9390),
                )
            else:
                # Fall back to Unix socket if explicitly requested
                from gvm.connections import UnixSocketConnection
                connection = UnixSocketConnection()
        else:
            # Windows and other platforms must use TLS
            connection = TLSConnection(
                hostname=credentials.get('hostname', 'localhost'),
                port=credentials.get('port', 9390),
            )
        transform = EtreeTransform()
        
        # Authenticate (use provided credentials or defaults)
        username = credentials.get('username', 'admin') if credentials else 'admin'
        password = credentials.get('password', '') if credentials else ''
        # host = credentials.get('host', '/var/run/gvmd.sock') if credentials else '/var/run/gvmd.sock'
        
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            
            # Create target
            target = gmp.create_target(
                name=f"Scan_{target_ip}",
                hosts=[target_ip],
                comment="Automated scan"
            )
            
            # Create task
            task = gmp.create_task(
                name=f"Scan_{target_ip}",
                config_id="daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
                target_id=target.get('id'),
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS default
            )
            
            # Start task
            report_id = gmp.start_task(task.get('id')).get('report_id')
            
            # Wait for scan to complete
            while True:
                time.sleep(30)
                report = gmp.get_report(report_id)
                if report.get('report').get('scan_run_status') == 'Done':
                    break
            
            # Process results
            results = {
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner": "openvas",
                "target": target_ip,
                "hosts": []
            }
            
            # Parse report content
            for host in report.get('report').get('hosts', []):
                host_data = {
                    "host": host.get('ip'),
                    "findings": []
                }
                
                for item in host.get('ports', []):
                    finding = {
                        "name": item.get('nvt', {}).get('name'),
                        "threat": item.get('threat'),
                        "severity": item.get('severity'),
                        "port": item.get('port'),
                        "description": item.get('description'),
                        "solution": item.get('solution'),
                        "cve": item.get('cve'),
                        "cvss_base_score": float(item.get('cvss_base_score', 0))
                    }
                    host_data["findings"].append(finding)
                
                results["hosts"].append(host_data)
            
            return results
    
    except ImportError:
        print("OpenVAS/GVM library not available, falling back to command line")
        return scan_with_openvas_cli(target_ip)
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "openvas",
            "target": target_ip
        }

def scan_with_openvas_cli(target_ip: str) -> Dict[str, Any]:
    """
    Perform OpenVAS scan using CLI commands
    
    Args:
        target_ip (str): IP address to scan
        
    Returns:
        dict: Scan results
    """
    try:
        # Run OpenVAS scan via command line
        scan_name = f"scan_{target_ip.replace('.', '_')}"
        cmd = f"omp --username admin --password '' --xml='<create_task><name>{scan_name}</name><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><target id=\"\"><hosts>{target_ip}</hosts></target></create_task>'"
        
        # Execute command and get task ID
        task_id = subprocess.check_output(cmd, shell=True)
        
        # Start the task
        subprocess.check_output(f"omp --username admin --password '' --start-task {task_id}", shell=True)
        
        # Wait for completion
        while True:
            time.sleep(30)
            status = subprocess.check_output(f"omp --username admin --password '' --get-tasks {task_id}", shell=True)
            if "Done" in status:
                break
        
        # Get report (simplified example)
        report = subprocess.check_output(f"omp --username admin --password '' --get-report {task_id}", shell=True)
        
        # Process report into standardized format
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "openvas",
            "target": target_ip,
            "hosts": []  # Would need actual parsing of CLI output
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "openvas",
            "target": target_ip
        }
#############################################
# REPORT PARSING
#############################################
def parse_nessus_report(file_path: str) -> Dict[str, Any]:
    """
    Parse a Nessus scan report (.nessus XML file)
    
    Args:
        file_path (str): Path to the Nessus report file
        
    Returns:
        dict: Parsed vulnerability data
    """
    try:
        # Parse the XML file
        with open(file_path, 'r') as f:
            xml_content = f.read()
        
        # Convert XML to dict
        nessus_data = xmltodict.parse(xml_content)
        
        # Extract report data
        report_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "source_file": os.path.basename(file_path),
            "hosts": [],
            "vulnerabilities": []
        }
        
        # Process report hosts and findings
        report_hosts = nessus_data.get('NessusClientData_v2', {}).get('Report', {}).get('ReportHost', [])
        
        # Ensure report_hosts is a list even if there's only one host
        if not isinstance(report_hosts, list):
            report_hosts = [report_hosts]
        
        for host in report_hosts:
            host_name = host.get('@name', 'Unknown')
            host_data = {
                "host": host_name,
                "findings": []
            }
            
            # Extract host properties
            host_properties = host.get('HostProperties', {}).get('tag', [])
            if not isinstance(host_properties, list):
                host_properties = [host_properties]
            
            properties = {}
            for prop in host_properties:
                if prop is not None and '@name' in prop and '#text' in prop:
                    properties[prop['@name']] = prop['#text']
            
            host_data["properties"] = properties
            
            # Extract findings for this host
            items = host.get('ReportItem', [])
            if not isinstance(items, list):
                items = [items]
            
            for item in items:
                if item is None:
                    continue
                    
                finding = {
                    "host": host_name,
                    "plugin_id": item.get('@pluginID', ''),
                    "plugin_name": item.get('@pluginName', ''),
                    "port": item.get('@port', ''),
                    "protocol": item.get('@protocol', ''),
                    "severity": item.get('@severity', ''),
                    "risk_factor": _extract_text(item, 'risk_factor'),
                    "description": _extract_text(item, 'description'),
                    "synopsis": _extract_text(item, 'synopsis'),
                    "solution": _extract_text(item, 'solution'),
                    "cve": _extract_text(item, 'cve'),
                    "cvss_base_score": _extract_text(item, 'cvss_base_score'),
                    "plugin_output": _extract_text(item, 'plugin_output')
                }
                
                host_data["findings"].append(finding)
                report_data["vulnerabilities"].append(finding)
            
            report_data["hosts"].append(host_data)
        
        # Save the processed data
        save_scan_results(report_data)
        
        print(f"Nessus report processed: found {len(report_data['hosts'])} hosts and {len(report_data['vulnerabilities'])} findings")
        return report_data
    
    except Exception as e:
        print(f"Error parsing Nessus report: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "nessus",
            "source_file": os.path.basename(file_path),
            "hosts": [],
            "vulnerabilities": []
        }

def parse_openvas_report(file_path: str) -> Dict[str, Any]:
    """
    Parse an OpenVAS scan report (XML format)
    
    Args:
        file_path (str): Path to the OpenVAS report file
        
    Returns:
        dict: Parsed vulnerability data
    """
    try:
        # Parse the XML file
        with open(file_path, 'r') as f:
            xml_content = f.read()
        
        # Convert XML to dict
        openvas_data = xmltodict.parse(xml_content)
        
        # Extract report data
        report_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "openvas",
            "source_file": os.path.basename(file_path),
            "hosts": [],
            "vulnerabilities": []
        }
        
        # Process report elements based on OpenVAS XML structure
        # Note: OpenVAS/GVM XML structure can vary by version
        report = openvas_data.get('report', {})
        if not report:
            report = openvas_data.get('get_reports_response', {}).get('report', {})
        
        # Extract results
        results = report.get('results', {}).get('result', [])
        if not isinstance(results, list):
            results = [results]
        
        # Track hosts
        hosts_dict = {}
        
        # Process each result
        for result in results:
            if result is None:
                continue
                
            host = result.get('host', 'Unknown')
            port = result.get('port', '')
            
            # Initialize host entry if not exists
            if host not in hosts_dict:
                hosts_dict[host] = {
                    "host": host,
                    "findings": []
                }
            
            finding = {
                "host": host,
                "name": result.get('name', ''),
                "threat": result.get('threat', ''),
                "severity": result.get('severity', ''),
                "port": port,
                "nvt": result.get('nvt', {}),
                "description": _extract_nested(result, ['description']),
                "solution": _extract_nested(result, ['solution']),
                "cvss_base": _extract_nested(result, ['nvt', 'cvss_base']),
                "cve": _extract_nested(result, ['nvt', 'cve']) or _extract_nested(result, ['nvt', 'refs', 'ref'])
            }
            
            hosts_dict[host]["findings"].append(finding)
            report_data["vulnerabilities"].append(finding)
        
        # Add hosts to the report
        report_data["hosts"] = list(hosts_dict.values())
        
        # Save the processed data
        save_scan_results(report_data)
        
        print(f"OpenVAS report processed: found {len(report_data['hosts'])} hosts and {len(report_data['vulnerabilities'])} findings")
        return report_data
    
    except Exception as e:
        print(f"Error parsing OpenVAS report: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "openvas",
            "source_file": os.path.basename(file_path),
            "hosts": [],
            "vulnerabilities": []
        }

def _extract_text(item, key):
    """Helper function to extract text from Nessus report item"""
    if item is None or key not in item:
        return ""
    return item.get(key, "") if isinstance(item.get(key), str) else item.get(key, {}).get('#text', "")

def _extract_nested(data, keys):
    """Helper function to extract nested values from dictionary"""
    current = data
    for key in keys:
        if not current or not isinstance(current, dict) or key not in current:
            return ""
        current = current[key]
    
    if isinstance(current, dict) and '#text' in current:
        return current['#text']
    
    return current

#############################################
# VULNERABILITY CONVERSION AND REPORTING
#############################################
def convert_scanner_results_to_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert external scanner results to a standard vulnerability format
    
    Args:
        scan_results (dict): Results from an external scanner
        
    Returns:
        list: List of vulnerabilities in standard format
    """
    vulnerabilities = []
    scanner_type = scan_results.get("scanner", "unknown")
    
    try:
        if scanner_type == "nmap":
            # Process Nmap results
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        # Create vulnerability entry for each open port with service
                        vulnerability = {
                            "id": f"NMAP-{host.get('host')}-{port_info.get('port')}",
                            "title": f"Open port {port_info.get('port')}/{port_info.get('protocol')} ({port_info.get('service')})",
                            "description": f"Open port detected: {port_info.get('port')}/{port_info.get('protocol')} is running {port_info.get('service')} {port_info.get('product')} {port_info.get('version')} {port_info.get('extrainfo')}",
                            "type": "network",
                            "cvss_score": 0.0,  # Nmap doesn't provide CVSS scores
                            "attack_vector": "network",
                            "references": [],
                            "status": "Open",
                            "history": [],
                            "affected_systems": [host.get('host')]
                        }
                        vulnerabilities.append(vulnerability)
                 # Process OS-related CVEs
            for cve in scan_results.get("os_info", {}).get("related_cves", []):
                vulnerability = {
                    "id": cve.get("id", "OS-VULN"),
                    "title": f"{cve.get('title', 'OS Vulnerability')}",
                    "description": cve.get("description", "No description available"),
                    "type": "os",
                    "cvss_score": cve.get("cvss_score", 0.0),
                    "attack_vector": "local",
                    "references": cve.get("references", []),
                    "remediation": cve.get("remediation", "No remediation available"),
                    "status": "Open",
                    "history": [],
                    "affected_systems": [scan_results.get("target", "Unknown")]
                }
                vulnerabilities.append(vulnerability)
        
        elif scanner_type == "nessus":
            # Process Nessus results
            for finding in scan_results.get("vulnerabilities", []):
                severity = int(finding.get("severity", 0))
                cvss_score = finding.get("cvss_base_score", "")
                
                # Convert Nessus severity to CVSS score if not available
                if not cvss_score and severity is not None:
                    # Nessus severity levels: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
                    cvss_mapping = {0: 0.0, 1: 2.0, 2: 5.0, 3: 7.5, 4: 9.5}
                    cvss_score = cvss_mapping.get(int(severity), 0.0)
                else:
                    try:
                        cvss_score = float(cvss_score)
                    except (ValueError, TypeError):
                        cvss_score = 0.0
                
                vulnerability = {
                    "id": finding.get("plugin_id", f"NESSUS-{finding.get('host')}-{finding.get('port')}"),
                    "title": finding.get("plugin_name", "Unknown vulnerability"),
                    "description": finding.get("description", "No description available"),
                    "type": "network" if finding.get("port") else "os",
                    "cvss_score": cvss_score,
                    "attack_vector": "network" if finding.get("port") else "local",
                    "references": [],
                    "status": "Open",
                    "history": [],
                    "affected_systems": [finding.get('host')],
                    "raw_data": finding
                }
                
                # Add CVE information if available
                cve = finding.get("cve", "")
                if cve:
                    vulnerability["id"] = cve
                    vulnerability["references"].append(f"https://nvd.nist.gov/vuln/detail/{cve}")
                
                # Add solution information if available
                solution = finding.get("solution", "")
                if solution:
                    vulnerability["remediation_suggestion"] = solution
                
                vulnerabilities.append(vulnerability)
        
        elif scanner_type == "openvas":
            # Process OpenVAS results
            for finding in scan_results.get("vulnerabilities", []):
                # Map OpenVAS threat levels to CVSS scores
                threat = finding.get("threat", "").lower()
                cvss_score = finding.get("cvss_base", "")
                
                if not cvss_score:
                    threat_mapping = {
                        "high": 8.0,
                        "medium": 5.0,
                        "low": 3.0,
                        "log": 0.0,
                        "debug": 0.0,
                        "critical": 9.5
                    }
                    cvss_score = threat_mapping.get(threat, 0.0)
                else:
                    try:
                        cvss_score = float(cvss_score)
                    except (ValueError, TypeError):
                        cvss_score = 0.0
                
                vulnerability = {
                    "id": finding.get("nvt", {}).get("@oid", f"OPENVAS-{finding.get('host')}-{finding.get('port')}"),
                    "title": finding.get("name", "Unknown vulnerability"),
                    "description": finding.get("description", "No description available"),
                    "type": "network" if finding.get("port") else "os",
                    "cvss_score": cvss_score,
                    "attack_vector": "network" if finding.get("port") else "local",
                    "references": [],
                    "status": "Open",
                    "history": [],
                    "affected_systems": [finding.get('host')],
                    "raw_data": finding
                }
                
                # Add CVE information if available
                cve = finding.get("cve", "")
                if cve:
                    vulnerability["id"] = cve
                    vulnerability["references"].append(f"https://nvd.nist.gov/vuln/detail/{cve}")
                
                # Add solution information if available
                solution = finding.get("solution", "")
                if solution:
                    vulnerability["remediation_suggestion"] = solution
                
                vulnerabilities.append(vulnerability)
        elif scanner_type == "basic":
            # Process basic scan results
            for port_info in scan_results.get("open_ports", []):
                vulnerability = {
                    "id": f"BASIC-{scan_results.get('target')}-{port_info.get('port')}",
                    "title": f"Open port {port_info.get('port')} ({port_info.get('service')})",
                    "description": f"Basic scan detected open port: {port_info.get('port')} running {port_info.get('service')}",
                    "type": "network",
                    "cvss_score": _estimate_cvss_from_service(port_info.get("service")),
                    "attack_vector": "network",
                    "references": [],
                    "status": "Open",
                    "history": [],
                    "affected_systems": [scan_results.get('target')]
                }
                vulnerabilities.append(vulnerability)
        
        # Add severity based on CVSS score
        for vuln in vulnerabilities:
            cvss = vuln.get("cvss_score", 0.0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0
            
            if cvss >= 9.0:
                vuln["severity"] = "Critical"
            elif cvss >= 7.0:
                vuln["severity"] = "High"
            elif cvss >= 4.0:
                vuln["severity"] = "Medium"
            else:
                vuln["severity"] = "Low"
    
    except Exception as e:
        print(f"Error converting scanner results: {e}")
    
    return vulnerabilities
def _estimate_cvss_from_service(service: str) -> float:
    """Estimate CVSS score based on service type"""
    if not service:
        return 0.0
    
    service = service.lower()
    high_risk = ["ssh", "telnet", "ftp", "rdp", "smb", "netbios"]
    med_risk = ["http", "https", "dns", "snmp", "mysql", "postgresql"]
    
    if any(s in service for s in high_risk):
        return random.uniform(7.0, 9.0)  # High risk services
    elif any(s in service for s in med_risk):
        return random.uniform(4.0, 6.9)  # Medium risk services
    return random.uniform(0.1, 3.9)  # Low risk services

#############################################
# REPORTING AND UTILITY FUNCTIONS
#############################################
def save_scan_results(scan_results: Dict[str, Any]) -> str:
    """
    Save scan results to a JSON file
    
    Args:
        scan_results (dict): Scan results to save
        
    Returns:
        str: Path to the saved file
    """
    # Create a timestamp for the file name
    scanner_type = scan_results.get("scanner", "scan")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{scanner_type}_{timestamp}.json"
    file_path = os.path.join(SCAN_RESULTS_DIR, filename)
    
    try:
        with open(file_path, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        # Add the file path to the results
        scan_results["file_path"] = file_path
        return file_path
    
    except Exception as e:
        print(f"Error saving scan results: {e}")
        return ""
    
def get_scanner_result_files() -> Dict[str, List[str]]:
    """
    Get a list of available scanner result files
    
    Returns:
        dict: Dictionary with scanner types as keys and lists of file paths as values
    """
    result_files = {
        "nmap": [],
        "nessus": [],
        "openvas": [],
        "basic_scan": []
    }
    
    if not os.path.exists(SCAN_RESULTS_DIR):
        return result_files
    
    for filename in os.listdir(SCAN_RESULTS_DIR):
        filepath = os.path.join(SCAN_RESULTS_DIR, filename)
        if not os.path.isfile(filepath):
            continue
            
        if filename.startswith("nmap_scan_") and filename.endswith(".json"):
            result_files["nmap"].append(filepath)
        elif filename.startswith("nessus_processed_") and filename.endswith(".json"):
            result_files["nessus"].append(filepath)
        elif filename.startswith("openvas_processed_") and filename.endswith(".json"):
            result_files["openvas"].append(filepath)
        elif filename.startswith("scan_") and filename.endswith(".json"):
            result_files["basic_scan"].append(filepath)
    
    # Sort files by name (which contains timestamp) in reverse order (newest first)
    for scanner_type in result_files:
        result_files[scanner_type].sort(reverse=True)
    
    return result_files

def load_scanner_results(file_path: str) -> Dict[str, Any]:
    """
    Load scanner results from a JSON file
    
    Args:
        file_path (str): Path to the scanner results file
        
    Returns:
        dict: Scanner results
    """
    try:
        with open(file_path, 'r') as f:
            results = json.load(f)
        return results
    except Exception as e:
        print(f"Error loading scanner results from {file_path}: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat(),
            "scanner": "unknown",
            "hosts": [],
            "vulnerabilities": []
        }

#############################################
# REPORTING FUNCTIONALITY
#############################################
def generate_vulnerability_report(vulnerabilities, report_format="html"):
    """
    Generate a vulnerability report in the specified format
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        report_format (str): Format of the report ("html", "csv", "json")
    
    Returns:
        str: Report content or file path
    """
    if not vulnerabilities:
        return "No vulnerabilities to report."
    
    # Create a timestamp for the report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if report_format == "csv":
        return generate_csv_report(vulnerabilities, timestamp)
    elif report_format == "json":
        return generate_json_report(vulnerabilities, timestamp)
    else:  # Default to HTML
        return generate_html_report(vulnerabilities, timestamp)

def generate_csv_report(vulnerabilities, timestamp):
    """
    Generate a CSV report of vulnerabilities
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        timestamp (str): Timestamp for the file name
    
    Returns:
        str: Path to the generated CSV file
    """
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities)
    
    # Select relevant columns
    if 'references' in df.columns:
        df['references'] = df['references'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
    
    # Keep only the most relevant columns
    report_columns = ['id', 'title', 'severity', 'cvss_score', 'description', 'references', 'status']
    report_columns = [col for col in report_columns if col in df.columns]
    
    df = df[report_columns]
    
    # Save to CSV
    file_path = f"{REPORTS_DIR}/vulnerability_report_{timestamp}.csv"
    df.to_csv(file_path, index=False)
    
    return file_path

def generate_json_report(vulnerabilities, timestamp):
    """
    Generate a JSON report of vulnerabilities
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        timestamp (str): Timestamp for the file name
    
    Returns:
        str: Path to the generated JSON file
    """
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Add report metadata
    report = {
        "report_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    # Save to JSON
    file_path = f"{REPORTS_DIR}/vulnerability_report_{timestamp}.json"
    with open(file_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return file_path

def generate_html_report(vulnerabilities, timestamp):
    """
    Generate an HTML report of vulnerabilities
    
    Args:
        vulnerabilities (list): List of vulnerability dictionaries
        timestamp (str): Timestamp for the file name
    
    Returns:
        str: Path to the generated HTML file
    """
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Count vulnerabilities by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Low")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Create severity chart
    plt.figure(figsize=(8, 5))
    colors = ['#ff0000', '#ff8800', '#ffcc00', '#00cc00']
    plt.bar(severity_counts.keys(), severity_counts.values(), color=colors)
    plt.title('Vulnerabilities by Severity')
    plt.ylabel('Count')
    plt.tight_layout()
    
    # Save chart to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    chart_data = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()
    
    # Convert to DataFrame for table display
    df = pd.DataFrame(vulnerabilities)
    
    # Build HTML content
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2 {{ color: #333366; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ background-color: #ffdddd; }}
        .high {{ background-color: #ffeedd; }}
        .medium {{ background-color: #ffffdd; }}
        .low {{ background-color: #ddffdd; }}
        .summary {{ display: flex; justify-content: space-around; margin-bottom: 30px; }}
        .summary-item {{ text-align: center; padding: 10px; border-radius: 5px; min-width: 100px; }}
        .summary-number {{ font-size: 24px; font-weight: bold; }}
        .chart {{ text-align: center; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Vulnerability Assessment Report</h1>
    <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="summary-item" style="background-color: #ffdddd;">
            <div class="summary-number">{severity_counts["Critical"]}</div>
            <div>Critical</div>
        </div>
        <div class="summary-item" style="background-color: #ffeedd;">
            <div class="summary-number">{severity_counts["High"]}</div>
            <div>High</div>
        </div>
        <div class="summary-item" style="background-color: #ffffdd;">
            <div class="summary-number">{severity_counts["Medium"]}</div>
            <div>Medium</div>
        </div>
        <div class="summary-item" style="background-color: #ddffdd;">
            <div class="summary-number">{severity_counts["Low"]}</div>
            <div>Low</div>
        </div>
    </div>
    
    <div class="chart">
        <img src="data:image/png;base64,{chart_data}" alt="Severity Chart">
    </div>
    
    <h2>Vulnerability Details</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>CVSS Score</th>
            <th>Status</th>
        </tr>
    """
    
    # Add table rows
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Low")
        row_class = severity.lower() if severity in ["Critical", "High", "Medium", "Low"] else ""
        
        html_content += f"""
        <tr class="{row_class}">
            <td>{vuln.get("id", "Unknown")}</td>
            <td>{vuln.get("title", "Unknown")}</td>
            <td>{severity}</td>
            <td>{vuln.get("cvss_score", "N/A")}</td>
            <td>{vuln.get("status", "Open")}</td>
        </tr>
        """
    
    html_content += """
    </table>
    
    <h2>Detailed Findings</h2>
    """
    
    # Add detailed findings
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Low")
        row_class = severity.lower() if severity in ["Critical", "High", "Medium", "Low"] else ""
        
        html_content += f"""
    <div class="vulnerability {row_class}">
        <h3>{vuln.get("title", "Unknown")}</h3>
        <p><strong>ID:</strong> {vuln.get("id", "Unknown")}</p>
        <p><strong>Severity:</strong> {severity} (CVSS: {vuln.get("cvss_score", "N/A")})</p>
        <p><strong>Status:</strong> {vuln.get("status", "Open")}</p>
        <p><strong>Description:</strong> {vuln.get("description", "No description available")}</p>
        
        <p><strong>Remediation:</strong></p>
        <div>{vuln.get("remediation", "No remediation available")}</div>
        
        <p><strong>References:</strong></p>
        <ul>
        """
        
        # Add references
        references = vuln.get("references", [])
        if references:
            for ref in references:
                html_content += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
        else:
            html_content += '<li>No references available</li>'
        
        html_content += """
        </ul>
    </div>
    <hr>
        """
    
    html_content += """
</body>
</html>
    """
    
    # Save to HTML file
    file_path = f"{REPORTS_DIR}/vulnerability_report_{timestamp}.html"
    with open(file_path, 'w') as f:
        f.write(html_content)
    
    return file_path

def get_report_file_list():
    """
    Get a list of all generated reports
    
    Returns:
        list: List of report file paths
    """
    if not os.path.exists(REPORTS_DIR):
        return []
    
    report_files = []
    for filename in os.listdir(REPORTS_DIR):
        if filename.startswith("vulnerability_report_") and (filename.endswith(".html") or 
                                                            filename.endswith(".csv") or 
                                                            filename.endswith(".json")):
            report_files.append(os.path.join(REPORTS_DIR, filename))
    
    # Sort by most recent first
    report_files.sort(reverse=True)
    
    return report_files
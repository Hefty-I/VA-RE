import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
import time
import json
import os
import datetime
import platform
import time
import numpy as np
from typing import Dict, Optional
from scanning_reports import ( 
    scan_system,
    scan_with_nessus, 
    scan_with_openvas, 
    scan_with_nmap,
    get_open_ports, 
    check_firewall_config, 
    convert_scanner_results_to_vulnerabilities,
    get_scanner_result_files, 
    load_scanner_results,
    get_open_ports,
    check_firewall_config)

from data_processor import (
    process_vulnerability_data, 
    fetch_nvd_data, 
    update_vulnerability_status, 
    get_vulnerability_history
)
# Import improved modules
import nvd_feed_processor
import improved_classifier
import improved_remediation
from utils import get_host_os_info
from scanning_reports import generate_vulnerability_report, get_report_file_list

# Use the core project implementations as specified in the requirements
# Use SBERT for similarity-based retrieval from a remediation corpus
generate_remediation_suggestion = improved_remediation.generate_remediation_suggestion

# Use the improved classifier for vulnerability severity assessment
classify_vulnerability_severity = improved_classifier.classify_vulnerability_severity

# Set page configuration
st.set_page_config(
    page_title="Vulnerability Assessment & Remediation",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)
# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Choose a page", ["Home", "Scan", "Vulnerabilities", "Remediation", "Reports", "Data Sources", "AI Settings", "Model Evaluation"])

# Initialize session state for storing scan results
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False
if 'vulnerabilities' not in st.session_state:
    st.session_state.vulnerabilities = []
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}
if 'os_info' not in st.session_state:
    st.session_state.os_info = {}
if 'network_info' not in st.session_state:
    st.session_state.network_info = {}
# Initialize AI settings
if 'use_advanced_classifier' not in st.session_state:
    st.session_state.use_advanced_classifier = True
# Add this to your session state initialization
if 'nessus_keys' not in st.session_state:
    st.session_state.nessus_keys = {
        'access_key': os.getenv('NESSUS_ACCESS_KEY', ''),
        'secret_key': os.getenv('NESSUS_SECRET_KEY', '')
    }

# --- Main Application Logic ---
# Home page
if page == "Home":
    st.title("AI-Driven Vulnerability Assessment & Remediation System")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ## Welcome to the Vulnerability Assessment & Remediation System
        
        This application helps you:
        
        - 🔍 **Scan** your system for network and OS vulnerabilities
        - 🧠 **Analyze** and classify vulnerabilities by severity using machine learning
        - 🛡️ **Remediate** by providing actionable suggestions to fix issues
        - 📊 **Visualize** your security posture with intuitive dashboards
        
        ### Getting Started
        
        Navigate to the **Scan** page to begin assessing your system for vulnerabilities.
        
        ### Scope
        This tool focuses on:
        - **Network layer:** Open ports, weak encryption protocols, firewall misconfigurations
        - **Operating System layer:** Outdated OS components, unpatched vulnerabilities, known CVEs
        """)
    
    with col2:
        st.markdown("### System Status")
        if st.session_state.scan_completed:
            st.success("Scan Completed")
            st.metric("Total Vulnerabilities", len(st.session_state.vulnerabilities))
            
            # Count vulnerabilities by severity
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for vuln in st.session_state.vulnerabilities:
                severity_counts[vuln["severity"]] += 1
            
            # Display vulnerability counts
            st.markdown("#### Vulnerability Severity")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical", severity_counts["Critical"], delta_color="inverse")
            with col2:
                st.metric("High", severity_counts["High"], delta_color="inverse")
            with col3:
                st.metric("Medium", severity_counts["Medium"], delta_color="inverse")
            with col4:
                st.metric("Low", severity_counts["Low"], delta_color="inverse")
        else:
            st.warning("No scan has been performed yet")
            st.button("Go to Scan", on_click=lambda: st.session_state.update({"_page": "Scan"}))

# Scan page
elif page == "Scan":
    st.title("Vulnerability Scanning & Assessment")
       
    # Create directory for scanner results if it doesn't exist
    os.makedirs("data/scanner_results", exist_ok=True)
    
    # Initialize session state for scanner results
    if 'external_scan_results' not in st.session_state:
        st.session_state.external_scan_results = None
    
    # Create tabs for different scanning methods
    tabs = st.tabs(["Basic Scan", "Nmap Scan", "OpenVAS Scan", "Nessus Scan", "View Previous Scans"])
    
    # Tab 1: Basic Scan
    with tabs[0]:
        col1, col2 = st.columns([3, 2])
        
        with col1:
            st.markdown("""
            ## System Scan
            
            This page allows you to scan your system for vulnerabilities. 
            The scanner will check for:
            
            - Open ports and services
            - Firewall configuration
            - Operating system information
            - Known vulnerabilities based on installed software
            """)
            
            scan_type = st.selectbox("Select scan type", ["Quick Scan", "Full Scan", "Custom Scan"])
            
            if scan_type == "Custom Scan":
                st.markdown("### Scan Options")
                scan_col1, scan_col2 = st.columns(2)
                with scan_col1:
                    scan_ports = st.checkbox("Scan for open ports", value=True)
                    scan_os = st.checkbox("Check OS vulnerabilities", value=True)
                with scan_col2:
                    scan_firewall = st.checkbox("Check firewall configuration", value=True)
                    scan_services = st.checkbox("Identify running services", value=True)
            
            target_ip = st.text_input("Target IP (leave blank for localhost)", "127.0.0.1")
            port_range = st.text_input("Port range (e.g., 1-1000)", "1-1000")
            
            # Add data source options
            st.markdown("### Data Source")
            data_source = st.radio(
                "Choose vulnerability data source",
                ["Local database", "NVD API (real-time)"]
            )

            use_api = data_source == "NVD API (real-time)"
            
            if use_api:
                st.info("Using the NVD API allows access to the most up-to-date vulnerability information.")
                api_key = st.text_input("NVD API Key (optional, leave blank for unauthenticated requests)", type="password")
                days_back = st.slider("Days to look back for vulnerabilities", min_value=1, max_value=90, value=30)
                max_entries = st.slider("Maximum entries to fetch", min_value=10, max_value=200, value=100)
            else:
                api_key = None
                days_back = 30
                max_entries = 100
            
            # Create scan button
            scan_button = st.button("Start Scan")
            
            if scan_button:
                with st.spinner("Scanning system for vulnerabilities..."):
                    # Run the scan
                    progress_bar = st.progress(0)
                    status_text = st.empty()

                    for i, port in enumerate(range(int(port_range.split('-')[0]), int(port_range.split('-')[1]) + 1)):
                        status_text.text(f"Scanning port {port}...")
                        progress_bar.progress((i + 1) / len(range(int(port_range.split('-')[0]), int(port_range.split('-')[1]) + 1)))
                        # ... scanning logic ...
                    
                    # Step 1: Get OS information
                    progress_bar.progress(10)
                    st.session_state.os_info = get_host_os_info()
                    time.sleep(0.5)
                    
                    # Step 2: Scan for open ports
                    progress_bar.progress(30)
                    st.session_state.network_info["open_ports"] = get_open_ports(target_ip, port_range)
                    time.sleep(0.5)
                    
                    # Step 3: Check firewall configuration
                    progress_bar.progress(50)
                    st.session_state.network_info["firewall_config"] = check_firewall_config()
                    time.sleep(0.5)
                    
                    # Step 4: Process vulnerability data
                    progress_bar.progress(70)
                    raw_vulnerabilities = fetch_nvd_data(
                        days_back=days_back,
                        max_entries=max_entries,
                        use_api=use_api,
                        api_key=api_key if api_key else None
                    )
                    processed_vulnerabilities = process_vulnerability_data(
                        raw_vulnerabilities, 
                        st.session_state.os_info, 
                        st.session_state.network_info
                    )
                    time.sleep(0.5)
                    
                    # Step 5: Classify vulnerabilities and generate remediation
                    progress_bar.progress(90)
                    vulnerabilities = []
                    for vuln in processed_vulnerabilities:
                        # Classify severity
                        severity = classify_vulnerability_severity(vuln)
                        
                        # Generate remediation
                        remediation = generate_remediation_suggestion(vuln)
                        
                        # Add to list
                        vulnerability_entry = {
                            "id": vuln.get("id", "Unknown"),
                            "title": vuln.get("title", "Unknown vulnerability"),
                            "description": vuln.get("description", "No description available"),
                            "severity": severity,
                            "cvss_score": vuln.get("cvss_score", 0),
                            "remediation": remediation,
                            "references": vuln.get("references", []),
                            "status": vuln.get("status", "Open"),
                            "history": vuln.get("history", [])
                        }
                        vulnerabilities.append(vulnerability_entry)
                    
                    progress_bar.progress(100)
                    
                    # Store results in session state
                    st.session_state.vulnerabilities = vulnerabilities
                    st.session_state.scan_completed = True
                    
                    st.success(f"Scan completed! Found {len(vulnerabilities)} potential vulnerabilities.")
        
        with col2:
            st.markdown("### Scan Results")
            if st.session_state.scan_completed:
                st.success("Scan Completed")
                
                # Display OS information
                if st.session_state.os_info:
                    st.markdown("#### System Information")
                    st.json(st.session_state.os_info)
                
                # Display network information
                if st.session_state.network_info:
                    st.markdown("#### Network Information")
                    if "open_ports" in st.session_state.network_info:
                        st.markdown(f"**Open Ports:** {len(st.session_state.network_info['open_ports'])}")
                        if len(st.session_state.network_info['open_ports']) > 0:
                            port_data = pd.DataFrame(st.session_state.network_info['open_ports'])
                            st.dataframe(port_data, use_container_width=True)
                
                # Display vulnerability summary
                st.markdown("#### Vulnerability Summary")
                severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                for vuln in st.session_state.vulnerabilities:
                    severity_counts[vuln["severity"]] += 1
                
                # Create pie chart of severity distribution
                fig = px.pie(
                    values=list(severity_counts.values()), 
                    names=list(severity_counts.keys()),
                    color=list(severity_counts.keys()),
                    color_discrete_map={
                        'Critical': '#ff0000',
                        'High': '#ff8800', 
                        'Medium': '#ffcc00',
                        'Low': '#00cc00'
                    },
                    title="Vulnerability Severity Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
                
            else:
                st.info("Run a scan to see results here")
    
    # Tab 2: Nmap Scan
    with tabs[1]:
        st.markdown("""
        ## Nmap Network Scanner
        
        Use the powerful Nmap network scanning tool to discover open ports, services, and potential vulnerabilities.
        """)
        
        col1, col2 = st.columns([3, 2])
        
        with col1:
            target_ip = st.text_input("Target IP or hostname", "127.0.0.1", key="nmap_target_ip")
            port_range = st.text_input("Port range", "1-1000", key="nmap_port_range")
            
            scan_options = st.multiselect(
                "Scan options",
                options=["Service detection", "OS detection", "Script scanning", "Version detection"],
                default=["Service detection"],
                key="nmap_options"
            )
            
            # Map options to Nmap arguments
            scan_args = "-sV" # Default - service detection
            if "OS detection" in scan_options:
                scan_args += " -O"
            if "Script scanning" in scan_options:
                scan_args += " -sC"
            if "Version detection" in scan_options:
                scan_args += " -sV"
            
            if st.button("Run Nmap Scan", key="run_nmap_scan"):
                with st.spinner("Running Nmap scan..."):
                    try:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        results_placeholder = st.empty()
                        # Run the scan
                        results = scan_with_nmap(target_ip, port_range, scan_args)

                        
                        # Update progress bar
                        for i in range(1, 101):
                            time.sleep(0.05)  # Simulate work being done
                            progress_bar.progress(i)
                            status_text.text(f"Scanning... {i}%")
                        # Process results and add to vulnerabilities
                        if "error" not in results:
                            # Convert scan results to vulnerability format
                            new_vulnerabilities = convert_scanner_results_to_vulnerabilities(results)
                            
                            # Add nmap-specific tag
                            for vuln in new_vulnerabilities:
                                # Mark the origin
                                vuln["origin"] = "nmap"
                                
                                # Classify severity based on port risk
                                service = vuln.get("title", "").lower()
                                if any(s in service for s in ["ssh", "telnet", "ftp", "rdp", "smb", "netbios"]):
                                    vuln["severity"] = "High"
                                    vuln["cvss_score"] = 7.5
                                elif any(s in service for s in ["http", "https", "dns", "snmp"]):
                                    vuln["severity"] = "Medium"
                                    vuln["cvss_score"] = 5.0
                                else:
                                    vuln["severity"] = "Low"
                                    vuln["cvss_score"] = 3.0
                                
                                # Generate remediation
                                remediation = generate_remediation_suggestion(vuln)
                                vuln["remediation"] = remediation
                            
                            # Store results
                            st.session_state.external_scan_results = results
                            
                            # Update main vulnerabilities list if it exists
                            if hasattr(st.session_state, "vulnerabilities"):
                                st.session_state.vulnerabilities.extend(new_vulnerabilities)
                                st.session_state.scan_completed = True
                            else:
                                st.session_state.vulnerabilities = new_vulnerabilities
                                st.session_state.scan_completed = True
                            
                            # Display results
                            st.success(f"Nmap scan completed! Found {len(new_vulnerabilities)} potential vulnerabilities.")
                        else:
                            st.error(f"Error running Nmap scan: {results.get('error')}")
                    except Exception as e:
                        st.error(f"Error running Nmap scan: {str(e)}")
        
        with col2:
            st.markdown("### Nmap Scan Details")
            st.markdown("""
            **Common Nmap Scan Options:**
            
            - **Service detection (-sV)**: Determines service/version info
            - **OS detection (-O)**: Tries to identify the operating system
            - **Script scanning (-sC)**: Runs default scripts for more info
            - **Version detection (-sV)**: Tries to determine service versions
            
            **Note:** Some scan options may require root/administrator privileges.
            """)
    # Tab 3: OpenVAS Scan
    with tabs[2]:
        st.markdown("""
        ## OpenVAS Vulnerability Scan
        
        Perform a comprehensive vulnerability scan using OpenVAS.
        """)
        
        col1, col2 = st.columns([3, 2])
        
        with col1:
            target_ip = st.text_input("Target IP (leave blank for localhost)", "127.0.0.1", key="openvas_target")
            
            # # OpenVAS credentials configuration
            # with st.expander("OpenVAS Configuration (optional)"):
            #     openvas_host = st.text_input("OpenVAS Host", "localhost")
            #     openvas_port = st.text_input("OpenVAS Port", "9390")
            #     openvas_user = st.text_input("Username", "admin")
            #     openvas_pass = st.text_input("Password", type="password")
            #     use_tls = st.checkbox("Use TLS", value=True)
             # Connection configuration
            st.markdown("### OpenVAS Connection")
            use_tls = st.checkbox("Use TLS Connection", value=(platform.system().lower() != 'linux'))
            hostname = st.text_input("Hostname", "localhost")
            port = st.number_input("Port", value=9390, min_value=1, max_value=65535)
        
            # Authentication
            st.markdown("### Authentication")
            username = st.text_input("Username", "admin")
            password = st.text_input("Password", type="password")
            if st.button("Run OpenVAS Scan"):
                credentials = {
                    'use_tls': use_tls,
                    'hostname': hostname,
                    'port': port,
                    'username': username,
                    'password': password
                }
            
                try:
                    with st.spinner("Running OpenVAS scan..."):
                        # Run the scan
                        results = scan_with_openvas(target_ip, credentials)
                        if "error" not in results:
                            # Convert scan results to vulnerability format
                            new_vulnerabilities = convert_scanner_results_to_vulnerabilities(results)
                            
                            # Add openvas-specific tag
                            for vuln in new_vulnerabilities:
                                vuln["origin"] = "openvas"
                                if "remediation" not in vuln or not vuln["remediation"]:
                                    vuln["remediation"] = generate_remediation_suggestion(vuln)
                            
                            # Store results
                            st.session_state.external_scan_results = results
                            
                            # Update main vulnerabilities list
                            if hasattr(st.session_state, "vulnerabilities"):
                                existing_ids = {v["id"] for v in st.session_state.vulnerabilities}
                                new_vulns = [v for v in new_vulnerabilities if v["id"] not in existing_ids]
                                st.session_state.vulnerabilities.extend(new_vulns)
                            else:
                                st.session_state.vulnerabilities = new_vulnerabilities
                            
                            st.session_state.scan_completed = True
                            st.success(f"OpenVAS scan completed! Found {len(new_vulnerabilities)} vulnerabilities.")
                        else:
                            st.error(f"Error running OpenVAS scan: {results.get('error')}")
                except Exception as e:
                    st.error(f"Error running OpenVAS scan: {str(e)}")
        
        with col2:
            st.markdown("### OpenVAS Scan Details")
            st.markdown("""
            **OpenVAS provides comprehensive vulnerability scanning:**
            
            - Tests for thousands of known vulnerabilities
            - Includes configuration checks and patch verification
            - Provides detailed remediation advice
            
            **Note:** Requires OpenVAS/GVM to be installed and running.
            """)
    
    # Tab 4: Nessus Scan
    with tabs[3]:
        st.markdown("""
        ## Nessus Vulnerability Scan
        
        Perform an in-depth vulnerability assessment using Nessus.
        """)
        
        col1, col2 = st.columns([3, 2])
        
        with col1:
            target_ip = st.text_input("Target IP (leave blank for localhost)", "127.0.0.1", key="nessus_target_ip")
            
            # API Key Configuration
            st.markdown("### Nessus API Configuration")
            access_key = st.text_input("Access Key", 
                                     value=st.session_state.nessus_keys['access_key'],
                                     type="password",
                                     key="nessus_access_key")
            secret_key = st.text_input("Secret Key", 
                                     value=st.session_state.nessus_keys['secret_key'],
                                     type="password",
                                     key="nessus_secret_key")
            
            # Save keys to session state
            if access_key and secret_key:
                st.session_state.nessus_keys = {
                    'access_key': access_key,
                    'secret_key': secret_key
                }
            
            scan_button = st.button("Run Nessus Scan", key="run_nessus_scan")
            
            if scan_button:
                if not access_key or not secret_key:
                    st.error("Please provide both Access Key and Secret Key")
                else:
                    with st.spinner("Running Nessus scan..."):
                        try:
                            # Run the scan with API keys
                            results = scan_system(
                                target_ip=target_ip,
                                scan_type="nessus",
                                nessus_keys={
                                    'access_key': access_key,
                                    'secret_key': secret_key
                                }
                            )
                            
                            if "error" in results:
                                st.error(f"Nessus scan failed: {results.get('error')}")
                            else:
                                # Update session state with results
                                new_vulnerabilities = convert_scanner_results_to_vulnerabilities(results)
                                
                                # Process each vulnerability
                                for vuln in new_vulnerabilities:
                                    vuln["origin"] = "nessus"
                                    
                                    # Classify severity if not already done
                                    if "severity" not in vuln or not vuln["severity"]:
                                        severity = classify_vulnerability_severity(vuln)
                                        vuln["severity"] = severity
                                    
                                    # Generate remediation if not provided
                                    if "remediation" not in vuln or not vuln["remediation"]:
                                        remediation = generate_remediation_suggestion(vuln)
                                        vuln["remediation"] = remediation
                                
                                # Update main vulnerabilities list
                                if hasattr(st.session_state, "vulnerabilities"):
                                    existing_ids = {v["id"] for v in st.session_state.vulnerabilities}
                                    new_vulns = [v for v in new_vulnerabilities if v["id"] not in existing_ids]
                                    st.session_state.vulnerabilities.extend(new_vulns)
                                    st.success(f"Nessus scan completed! Added {len(new_vulns)} new vulnerabilities.")
                                else:
                                    st.session_state.vulnerabilities = new_vulnerabilities
                                    st.success(f"Nessus scan completed! Found {len(new_vulnerabilities)} vulnerabilities.")
                                
                                st.session_state.scan_completed = True
                                st.session_state.external_scan_results = results
                        
                        except Exception as e:
                            st.error(f"Error running Nessus scan: {str(e)}")
        
        with col2:
            st.markdown("### Nessus Scan Details")
            st.markdown("""
            **Nessus Scan Features:**
            
            - Comprehensive vulnerability detection
            - Authenticated scanning when credentials are provided
            - Detailed vulnerability information
            - Remediation suggestions
            
            **Note:** 
            - You need valid Nessus API keys
            - Scans may take several minutes to complete
            - Ensure your Nessus instance is reachable
            """)

    # Tab 5: View Previous Scans
    with tabs[4]:
        st.markdown("""
        ## View Previous Scan Results
        
        Load saved scan results from previous scanning sessions.
        """)
        
        # Get saved result files
        saved_files = get_scanner_result_files()
        
        if saved_files:
            selected_file = st.selectbox("Select saved scan result", saved_files, key="saved_result_file")
            
            if st.button("Load Selected Scan", key="load_saved_scan"):
                with st.spinner("Loading scan results..."):
                    results = load_scanner_results(selected_file)
                    
                    if "error" not in results:
                        # Convert to vulnerability format and update session state
                        new_vulnerabilities = convert_scanner_results_to_vulnerabilities(results)
                        
                        # Update main vulnerabilities list
                        if st.button("Replace Current Results", key="replace_current"):
                            st.session_state.vulnerabilities = new_vulnerabilities
                        elif st.button("Merge with Current Results", key="merge_current"):
                            if hasattr(st.session_state, "vulnerabilities") and st.session_state.vulnerabilities:
                                st.session_state.vulnerabilities.extend(new_vulnerabilities)
                            else:
                                st.session_state.vulnerabilities = new_vulnerabilities
                        
                        st.session_state.scan_completed = True
                        st.session_state.external_scan_results = results
                        
                        st.success(f"Successfully loaded {len(new_vulnerabilities)} vulnerabilities from {selected_file}.")
                    else:
                        st.error(f"Error loading scan results: {results.get('error')}")
        else:
            st.info("No saved scan results found. Run a scan first.")

# Vulnerabilities page
elif page == "Vulnerabilities":
    st.title("Vulnerabilities Analysis")
    
    if not st.session_state.scan_completed:
        st.warning("Please run a scan first to see vulnerabilities")
        st.button("Go to Scan", on_click=lambda: st.session_state.update({"_page": "Scan"}))
    else:
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        
        # Convert vulnerabilities to DataFrame for easier filtering and display
        df = pd.DataFrame(st.session_state.vulnerabilities)
        if "severity" not in df.columns:
            df["severity"] = "Low"
        # Apply filters
        filtered_df = df[df["severity"].isin(severity_filter)]
                # In app.py where the error occurs
        if not filtered_df.empty and "severity" in filtered_df.columns:
            # proceed with filtering
            df
        else:
            st.warning("No severity data available in scan results")
        
        # Display summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total", len(filtered_df))
        with col2:
            critical_count = len(filtered_df[filtered_df["severity"] == "Critical"])
            st.metric("Critical", critical_count, delta_color="inverse")
        with col3:
            high_count = len(filtered_df[filtered_df["severity"] == "High"])
            st.metric("High", high_count, delta_color="inverse")
        with col4:
            medium_count = len(filtered_df[filtered_df["severity"] == "Medium"])
            st.metric("Medium", medium_count, delta_color="inverse")
        
        # Display vulnerability table
        st.markdown("## Vulnerability List")
        
        # Create a table with the filtered vulnerabilities
        if not filtered_df.empty:
            # Simplify the display table
            display_df = filtered_df[["id", "title", "severity", "cvss_score"]]
            st.dataframe(display_df, use_container_width=True)
            
            # Detailed view for selected vulnerability
            st.markdown("## Vulnerability Details")
            selected_vuln_id = st.selectbox("Select vulnerability to view details", filtered_df["id"].tolist())
            
            if selected_vuln_id:
                selected_vuln = filtered_df[filtered_df["id"] == selected_vuln_id].iloc[0]
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"### {selected_vuln['title']}")
                    st.markdown(f"**ID:** {selected_vuln['id']}")
                    st.markdown(f"**Description:**")
                    st.markdown(selected_vuln['description'])
                    
                    if selected_vuln['references']:
                        st.markdown("**References:**")
                        for ref in selected_vuln['references']:
                            st.markdown(f"- [{ref}]({ref})")
                
                with col2:
                    # Severity indicator
                    severity_color = {
                        "Critical": "red",
                        "High": "orange",
                        "Medium": "yellow",
                        "Low": "green"
                    }
                    st.markdown(f"""
                    <div style="background-color: {severity_color[selected_vuln['severity']]}; 
                                padding: 10px; border-radius: 5px; text-align: center; 
                                color: white; font-weight: bold;">
                        Severity: {selected_vuln['severity']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(f"**CVSS Score:** {selected_vuln['cvss_score']}")
                    
                    # Status section
                    current_status = selected_vuln.get('status', 'Open')
                    st.markdown(f"**Status:** {current_status}")
                    
                    # Status update section
                    new_status = st.selectbox(
                        "Update Status",
                        ["Open", "In Progress", "Mitigated", "Resolved", "False Positive"],
                        index=["Open", "In Progress", "Mitigated", "Resolved", "False Positive"].index(current_status)
                    )
                    
                    notes = st.text_area("Add Notes (optional)", 
                                         placeholder="Add any relevant notes about this vulnerability or status change")
                    
                    if st.button("Update Status"):
                        if update_vulnerability_status(selected_vuln_id, new_status, notes):
                            st.success(f"Status updated to {new_status}")
                            
                            # Update session state to reflect the change
                            for i, vuln in enumerate(st.session_state.vulnerabilities):
                                if vuln["id"] == selected_vuln_id:
                                    st.session_state.vulnerabilities[i]["status"] = new_status
                                    
                                    # Add to history if it doesn't exist
                                    if "history" not in st.session_state.vulnerabilities[i]:
                                        st.session_state.vulnerabilities[i]["history"] = []
                                    
                                    # Add new history entry
                                    st.session_state.vulnerabilities[i]["history"].append({
                                        "status": new_status,
                                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "notes": notes if notes else f"Status changed to {new_status}"
                                    })
                                    break
                        else:
                            st.error("Failed to update status")
                
                # History section if available
                if "history" in selected_vuln and selected_vuln["history"]:
                    st.markdown("### Status History")
                    history = selected_vuln["history"]
                    
                    # Convert to DataFrame for display
                    history_df = pd.DataFrame(history)
                    if not history_df.empty:
                        # Reorder columns for better display
                        if "timestamp" in history_df.columns and "status" in history_df.columns:
                            col_order = ["timestamp", "status"]
                            if "notes" in history_df.columns:
                                col_order.append("notes")
                            history_df = history_df[col_order]
                        
                        st.dataframe(history_df, use_container_width=True)
                
                # Remediation section
                st.markdown("### Recommended Remediation")
                st.markdown(selected_vuln['remediation'])
        else:
            st.info("No vulnerabilities match the selected filters")

# Remediation page
elif page == "Remediation":
    st.title("Vulnerability Remediation")
    
    if not st.session_state.scan_completed:
        st.warning("Please run a scan first to see remediation suggestions")
        st.button("Go to Scan", on_click=lambda: st.session_state.update({"_page": "Scan"}))
    else:
        # Convert vulnerabilities to DataFrame for easier filtering and display
        df = pd.DataFrame(st.session_state.vulnerabilities)
        
        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        df["severity_order"] = df["severity"].map(severity_order)
        df = df.sort_values("severity_order")
        
        # Create tabs for different severity levels
        tabs = st.tabs(["All", "Critical", "High", "Medium", "Low"])
        
        with tabs[0]:
            st.markdown("## All Vulnerabilities")
            for i, vuln in df.iterrows():
                with st.expander(f"{vuln['severity']} - {vuln['title']}"):
                    st.markdown(f"**ID:** {vuln['id']}")
                    st.markdown(f"**Description:** {vuln['description']}")
                    st.markdown("### Remediation Steps")
                    st.markdown(vuln['remediation'])
        
        with tabs[1]:
            critical_df = df[df["severity"] == "Critical"]
            if not critical_df.empty:
                for i, vuln in critical_df.iterrows():
                    with st.expander(f"{vuln['title']}"):
                        st.markdown(f"**ID:** {vuln['id']}")
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown("### Remediation Steps")
                        st.markdown(vuln['remediation'])
            else:
                st.info("No critical vulnerabilities found")
        
        with tabs[2]:
            high_df = df[df["severity"] == "High"]
            if not high_df.empty:
                for i, vuln in high_df.iterrows():
                    with st.expander(f"{vuln['title']}"):
                        st.markdown(f"**ID:** {vuln['id']}")
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown("### Remediation Steps")
                        st.markdown(vuln['remediation'])
            else:
                st.info("No high severity vulnerabilities found")
        
        with tabs[3]:
            medium_df = df[df["severity"] == "Medium"]
            if not medium_df.empty:
                for i, vuln in medium_df.iterrows():
                    with st.expander(f"{vuln['title']}"):
                        st.markdown(f"**ID:** {vuln['id']}")
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown("### Remediation Steps")
                        st.markdown(vuln['remediation'])
            else:
                st.info("No medium severity vulnerabilities found")
        
        with tabs[4]:
            low_df = df[df["severity"] == "Low"]
            if not low_df.empty:
                for i, vuln in low_df.iterrows():
                    with st.expander(f"{vuln['title']}"):
                        st.markdown(f"**ID:** {vuln['id']}")
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown("### Remediation Steps")
                        st.markdown(vuln['remediation'])
            else:
                st.info("No low severity vulnerabilities found")
        
        # Summary of remediation efforts
        st.markdown("## Remediation Summary")
        st.markdown("""
        ### Prioritization Strategy
        
        1. **Critical vulnerabilities** should be addressed immediately
        2. **High severity vulnerabilities** should be addressed within 7 days
        3. **Medium severity vulnerabilities** should be addressed within 30 days
        4. **Low severity vulnerabilities** can be addressed during scheduled maintenance
        
        ### Common Remediation Steps
        
        - Update and patch systems regularly
        - Close unnecessary open ports
        - Configure firewalls properly
        - Follow the principle of least privilege
        - Implement network segmentation
        """)

# Reports page
elif page == "Reports":
    st.title("Vulnerability Reports")
    
    if not st.session_state.scan_completed:
        st.warning("Please run a scan first to generate reports")
        st.button("Go to Scan", on_click=lambda: st.session_state.update({"_page": "Scan"}))
    else:
        st.markdown("""
        ## Report Generation
        
        Generate comprehensive reports of the vulnerability assessment results in various formats.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Report generation section
            st.markdown("### Create a New Report")
            
            report_format = st.selectbox(
                "Report Format",
                options=["HTML", "CSV", "JSON"],
                index=0
            )
            
            generate_report = st.button("Generate Report")
            
            if generate_report:
                with st.spinner("Generating report..."):
                    # Generate the report
                    report_path = generate_vulnerability_report(
                        st.session_state.vulnerabilities,
                        report_format.lower()
                    )
                    
                    if report_path and os.path.exists(report_path):
                        st.success(f"Report generated successfully: {report_path}")
                        
                        # Allow downloading the report
                        with open(report_path, 'rb') as f:
                            file_content = f.read()
                            
                            st.download_button(
                                label="Download Report",
                                data=file_content,
                                file_name=os.path.basename(report_path),
                                mime=(
                                    "text/html" if report_format.lower() == "html" else
                                    "text/csv" if report_format.lower() == "csv" else
                                    "application/json"
                                )
                            )
                    else:
                        st.error("Failed to generate report")
        
        with col2:
            # Previous reports section
            st.markdown("### Previous Reports")
            
            report_files = get_report_file_list()
            
            if report_files:
                for report_file in report_files:
                    report_name = os.path.basename(report_file)
                    report_format = report_name.split('.')[-1].upper()
                    report_date = ' '.join(report_name.split('_')[2:3])
                    
                    with st.expander(f"{report_format} Report - {report_date}"):
                        st.text(f"Path: {report_file}")
                        
                        # Allow downloading the report
                        with open(report_file, 'rb') as f:
                            file_content = f.read()
                            
                            st.download_button(
                                label=f"Download {report_format} Report",
                                data=file_content,
                                file_name=report_name,
                                mime=(
                                    "text/html" if report_format.lower() == "html" else
                                    "text/csv" if report_format.lower() == "csv" else
                                    "application/json"
                                )
                            )
                            
                        # Option to view HTML reports in the browser
                        if report_format.lower() == "html":
                            if st.button(f"View in Browser", key=f"view_{report_name}"):
                                with open(report_file, 'r') as f:
                                    html_content = f.read()
                                    st.components.v1.html(html_content, height=500)
            else:
                st.info("No previous reports available")

# AI Settings page
elif page == "AI Settings":
    st.title("AI Enhancement Settings")
    
    # Create tabs for different AI settings
    tabs = st.tabs(["SBERT Similarity System", "AI Models", "Model Training"])
    
    # SBERT Integration Tab
    with tabs[0]:
        st.markdown("""
        ## SBERT Similarity-Based Remediation
        
        This application uses SBERT (Sentence-BERT) for similarity-based retrieval from a remediation corpus,
        as specified in the project requirements.
        """)
        
        # Check if SBERT model exists
        sbert_model_path = "data/models/sbert_emulator.pkl"
        if os.path.exists(sbert_model_path):
            st.success("SBERT emulator model is available and configured")
        else:
            st.warning("SBERT emulator model will be created on first use")
            if st.button("Initialize SBERT Model"):
                with st.spinner("Initializing SBERT emulator model... This may take a few minutes"):
                    try:
                        # Import the module and initialize the model
                        import sbert_embedding
                        sample_sentences = [
                            "Remote code execution vulnerability in the web server",
                            "SQL injection vulnerability in the login form",
                            "Cross-site scripting vulnerability in the comment system",
                            "Buffer overflow vulnerability in the network driver",
                            "Information disclosure vulnerability in the API"
                        ]
                        embeddings = sbert_embedding.get_sentence_embeddings(sample_sentences)
                        st.success(f"SBERT emulator model initialized successfully! Created {len(embeddings)} embeddings.")
                    except Exception as e:
                        st.error(f"Error initializing SBERT model: {e}")
    
    # AI Models Tab
    with tabs[1]:
        st.markdown("""
        ## AI Model Settings
        
        Configure the AI models used for vulnerability classification and analysis.
        """)
        
        st.session_state.use_advanced_classifier = st.toggle(
            "Use Advanced Classifier", 
            value=st.session_state.use_advanced_classifier,
            help="When enabled, the system will use the ensemble classifier which combines multiple ML techniques"
        )
        
        # Check if models are available
        models_available = False
        try:
            if os.path.exists("data/models/ensemble_classifier.pkl"):
                models_available = True
                model_info = "Ensemble classifier model is available."
            elif os.path.exists("data/models/vulnerability_classifier.pkl"):
                models_available = True
                model_info = "Basic vulnerability classifier model is available."
            else:
                model_info = "No trained models found. Please train models first."
        except Exception as e:
            model_info = f"Error checking models: {str(e)}"
        
        st.info(model_info)
        
        # Model details
        if models_available:
            with st.expander("Model Details"):
                try:
                    # Try to load models and show metrics
                    if os.path.exists("data/models/ensemble_classifier.pkl"):
                        from models.ensemble_classifier import EnsembleClassifier
                        ensemble = EnsembleClassifier.load_model("data/models/ensemble_classifier.pkl")
                        
                        st.subheader("Ensemble Classifier Metrics")
                        metrics_df = pd.DataFrame({
                            "Metric": list(ensemble.metrics.keys()),
                            "Value": list(ensemble.metrics.values())
                        })
                        st.dataframe(metrics_df, use_container_width=True)
                    
                    # Show basic model metrics too if available
                    if os.path.exists("data/models/vulnerability_classifier.pkl"):
                        from models.vulnerability_classifier import VulnerabilityClassifier
                        basic_model = VulnerabilityClassifier.load_model("data/models/vulnerability_classifier.pkl")
                        
                        st.subheader("Basic Classifier Metrics")
                        metrics_df = pd.DataFrame({
                            "Metric": list(basic_model.metrics.keys()),
                            "Value": list(basic_model.metrics.values())
                        })
                        st.dataframe(metrics_df, use_container_width=True)
                except Exception as e:
                    st.error(f"Error loading model details: {str(e)}")
    
    # Training Tab
    with tabs[2]:
        st.markdown("""
        ## Model Training
        
        Train AI models using the National Vulnerability Database (NVD) data to improve classification and remediation suggestions.
        """)
        
        train_options = st.multiselect(
            "Select models to train",
            options=[
                "Basic Vulnerability Classifier", 
                "Embedding Classifier", 
                "Ensemble Classifier"
            ],
            default=["Basic Vulnerability Classifier", "Ensemble Classifier"]
        )
        
        col1, col2 = st.columns(2)
        with col1:
            min_entries = st.slider("Min entries per category", 10, 100, 20)
        with col2:
            max_entries = st.slider("Max total entries", 500, 10000, 2000)
        
        if st.button("Start Training"):
            with st.spinner("Training models... This may take several minutes."):
                try:
                    # Import the training module
                    import train_ai_models
                    
                    # Create log area
                    log_area = st.empty()
                    
                    # Run training based on selected options
                    if "Basic Vulnerability Classifier" in train_options:
                        log_area.info("Training basic vulnerability classifier...")
                        train_ai_models.train_individual_models()
                    
                    if "Ensemble Classifier" in train_options:
                        log_area.info("Training ensemble classifier...")
                        train_ai_models.train_ensemble_model()
                    
                    # Evaluate models
                    log_area.info("Evaluating models...")
                    metrics = train_ai_models.evaluate_models()
                    
                    # Show results
                    st.success("Training completed successfully!")
                    
                    # Display metrics
                    for model_name, model_metrics in metrics.items():
                        st.subheader(f"{model_name} Metrics")
                        metrics_df = pd.DataFrame({
                            "Metric": list(model_metrics.keys()),
                            "Value": list(model_metrics.values())
                        })
                        st.dataframe(metrics_df, use_container_width=True)
                except Exception as e:
                    st.error(f"Error during model training: {str(e)}")
                    st.error("Check that all required packages are installed (pandas, sklearn, nltk).")

# Data Sources page
elif page == "Data Sources":
    st.title("Data Sources & ML Model Training")
    
    st.markdown("""
    ## Real-time NVD Data Integration
    
    This application integrates with the National Vulnerability Database (NVD) to provide up-to-date, authentic vulnerability information. 
    NVD is the U.S. government repository of standards-based vulnerability management data.
    
    ### NVD Data Feeds Used
    
    The system uses the following official NVD data feeds:
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        - **Recent vulnerabilities:** `nvdcve-1.1-recent.json.gz`
        - **Modified vulnerabilities:** `nvdcve-1.1-modified.json.gz`
        - **2023 vulnerabilities:** `nvdcve-1.1-2023.json.gz`
        - **2024 vulnerabilities:** `nvdcve-1.1-2024.json.gz`
        - **2025 vulnerabilities:** `nvdcve-1.1-2025.json.gz`
        """)
        
        st.markdown("""
        ### Benefits of Using Real NVD Data
        
        - **Up-to-date Information:** Regular updates ensure you have the latest vulnerability data
        - **Comprehensive Details:** Complete CVE descriptions, CVSS scores, and reference links
        - **Higher Accuracy:** Machine learning models trained on authentic data provide better results
        - **Tailored Remediation:** Remediation suggestions based on actual vulnerability patterns
        """)
    
    with col2:
        st.markdown("### Data Feed Status")
        
        # Check if NVD cache exists
        feed_status = {}
        for data_file in nvd_feed_processor.DATA_FILES:
            file_path = os.path.join(nvd_feed_processor.CACHE_DIR, data_file)
            if os.path.exists(file_path):
                feed_status[data_file] = "Available"
            else:
                feed_status[data_file] = "Not downloaded"
        
        # Display status in a table
        status_df = pd.DataFrame({"Feed": list(feed_status.keys()), "Status": list(feed_status.values())})
        st.dataframe(status_df, use_container_width=True)
        
        # Add button to refresh feeds
        if st.button("Refresh Data Feeds"):
            with st.spinner("Downloading NVD data feeds..."):
                for data_file in nvd_feed_processor.DATA_FILES:
                    should_download, meta_data = nvd_feed_processor.should_download_feed(data_file)
                    if should_download:
                        nvd_feed_processor.download_and_cache_feed(data_file, meta_data)
                st.success("Data feeds refreshed successfully!")
    
    st.markdown("""
    ## Machine Learning Model Training
    
    The vulnerability classifier and remediation models are trained using real NVD data to ensure accuracy and relevance.
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Severity Classification Model")
        
        # Check if classifier model exists
        model_path = os.path.join("data", "models", "vulnerability_classifier_model.pkl")
        if os.path.exists(model_path):
            st.success("Model trained and ready")
            
            # Try to evaluate the model
            try:
                metrics = improved_classifier.evaluate_classifier_performance()
                st.metric("Model Accuracy", f"{metrics['accuracy']:.2f}")
                
                # Display class metrics
                st.markdown("#### Class-specific Performance")
                metrics_df = pd.DataFrame({
                    "Class": list(metrics["class_metrics"].keys()),
                    "Precision": [f"{m['precision']:.2f}" for m in metrics["class_metrics"].values()],
                    "Recall": [f"{m['recall']:.2f}" for m in metrics["class_metrics"].values()],
                    "F1 Score": [f"{m['f1_score']:.2f}" for m in metrics["class_metrics"].values()]
                })
                st.dataframe(metrics_df, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not evaluate model: {e}")
        else:
            st.warning("Model not yet trained")
        
        # Add button to train/retrain model
        if st.button("Train Classification Model"):
            with st.spinner("Training model on NVD data..."):
                try:
                    improved_classifier.train_classifier(force_retrain=True)
                    st.success("Model trained successfully!")
                except Exception as e:
                    st.error(f"Error training model: {e}")
    
    with col2:
        st.markdown("### Remediation Suggestion System")
        
        # Check if remediation corpus exists
        corpus_path = os.path.join("data", "remediation_corpus.json")
        if os.path.exists(corpus_path):
            st.success("Remediation corpus ready")
            
            # Show stats about remediation corpus
            try:
                with open(corpus_path, 'r') as f:
                    corpus = json.load(f)
                
                # Count by type
                type_counts = {}
                for entry in corpus:
                    vuln_type = entry.get("type", "unknown")
                    if vuln_type not in type_counts:
                        type_counts[vuln_type] = 0
                    type_counts[vuln_type] += 1
                
                st.metric("Total Remediation Patterns", len(corpus))
                
                # Display type distribution
                st.markdown("#### Remediation Type Distribution")
                type_df = pd.DataFrame({
                    "Type": list(type_counts.keys()),
                    "Count": list(type_counts.values())
                })
                st.dataframe(type_df, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not analyze remediation corpus: {e}")
        else:
            st.warning("Remediation corpus not yet generated")
        
        # Add button to generate/regenerate remediation corpus
        if st.button("Generate Remediation Corpus"):
            with st.spinner("Generating remediation corpus from NVD data..."):
                try:
                    improved_remediation.load_or_generate_remediation_corpus()
                    st.success("Remediation corpus generated successfully!")
                except Exception as e:
                    st.error(f"Error generating remediation corpus: {e}")

# Model Evaluation page
elif page == "Model Evaluation":
    st.title("AI Model Evaluation")
    
    # Import model evaluation module
    import model_evaluation
    
    # Create tabs for different evaluations
    tabs = st.tabs(["Classifier Performance", "Remediation Quality"])
    
    # Classifier Performance Tab
    with tabs[0]:
        st.markdown("""
        ## Vulnerability Classifier Performance
        
        Evaluate the performance of the vulnerability severity classifier.
        """)
        
        # Option to select classifier type
        classifier_type = st.selectbox(
            "Select classifier type",
            ["improved", "ensemble"],
            format_func=lambda x: "Ensemble Classifier" if x == "ensemble" else "Basic Classifier"
        )
        
        # Check if previous evaluations exist
        latest_eval = model_evaluation.get_latest_evaluation("classifier")
        
        if latest_eval and st.checkbox("Show previous evaluation", value=True, key="classifier_prev_eval"):
            st.info(f"Showing evaluation from {latest_eval.get('timestamp', 'unknown date')}")
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Accuracy", f"{latest_eval.get('accuracy', 0):.4f}")
            with col2:
                st.metric("Precision", f"{latest_eval.get('precision', 0):.4f}")
            with col3:
                st.metric("Recall", f"{latest_eval.get('recall', 0):.4f}")
            with col4:
                st.metric("F1 Score", f"{latest_eval.get('f1', 0):.4f}")
            
            # Display class metrics
            if "class_metrics" in latest_eval:
                st.subheader("Class-specific Metrics")
                class_df = pd.DataFrame({
                    "Severity": list(latest_eval["class_metrics"].keys()),
                    "Precision": [m["precision"] for m in latest_eval["class_metrics"].values()],
                    "Recall": [m["recall"] for m in latest_eval["class_metrics"].values()],
                    "F1 Score": [m["f1_score"] for m in latest_eval["class_metrics"].values()]
                })
                st.dataframe(class_df, use_container_width=True)
            
            # Display confusion matrix
            if "confusion_matrix" in latest_eval and "labels" in latest_eval:
                st.subheader("Confusion Matrix")
                try:
                    import matplotlib.pyplot as plt
                    import numpy as np
                    
                    cm = np.array(latest_eval["confusion_matrix"])
                    labels = latest_eval["labels"]
                    
                    fig, ax = plt.subplots(figsize=(8, 6))
                    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
                    ax.set_title("Confusion Matrix")
                    plt.colorbar(im, ax=ax)
                    tick_marks = np.arange(len(labels))
                    ax.set_xticks(tick_marks)
                    ax.set_xticklabels(labels, rotation=45)
                    ax.set_yticks(tick_marks)
                    ax.set_yticklabels(labels)
                    
                    # Add text annotations
                    thresh = cm.max() / 2
                    for i in range(len(labels)):
                        for j in range(len(labels)):
                            ax.text(j, i, format(cm[i, j], 'd'),
                                    ha="center", va="center",
                                    color="white" if cm[i, j] > thresh else "black")
                    
                    plt.tight_layout()
                    plt.ylabel('True label')
                    plt.xlabel('Predicted label')
                    
                    st.pyplot(fig)
                except Exception as e:
                    st.error(f"Error displaying confusion matrix: {e}")
                    st.json(latest_eval["confusion_matrix"])
        
        # Create a form for evaluation
        with st.form("classifier_evaluation_form"):
            st.subheader("Run New Evaluation")
            
            # Sample test data
            test_data = st.text_area(
                "Test vulnerability descriptions (one per line)",
                """Remote code execution vulnerability in web server
SQL injection vulnerability in login form
Information disclosure in API endpoint
Cross-site scripting vulnerability in comment form
Buffer overflow in system service
Authorization bypass in admin console
Path traversal vulnerability in file manager
Insecure cryptographic implementation"""
            )
            
            # Sample test labels
            test_labels = st.text_area(
                "Test labels (one per line, corresponding to descriptions)",
                """Critical
High
Medium
High
Critical
High
Medium
Medium"""
            )
            
            # Submit button
            submitted = st.form_submit_button("Run Evaluation")
        
        if submitted:
            # Process the test data and labels
            descriptions = [d.strip() for d in test_data.split("\n") if d.strip()]
            labels = [l.strip() for l in test_labels.split("\n") if l.strip()]
            
            if len(descriptions) != len(labels):
                st.error("Number of descriptions and labels must match.")
            else:
                with st.spinner("Running evaluation..."):
                    # Run the evaluation
                    metrics = model_evaluation.evaluate_classifier(
                        test_data=descriptions,
                        test_labels=labels,
                        classifier_type=classifier_type
                    )
                    
                    # Display results
                    st.success("Evaluation completed!")
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Accuracy", f"{metrics.get('accuracy', 0):.4f}")
                    with col2:
                        st.metric("Precision", f"{metrics.get('precision', 0):.4f}")
                    with col3:
                        st.metric("Recall", f"{metrics.get('recall', 0):.4f}")
                    with col4:
                        st.metric("F1 Score", f"{metrics.get('f1', 0):.4f}")
    
    # Remediation Quality Tab
    with tabs[1]:
        st.markdown("""
        ## Remediation Suggestion Quality
        
        Evaluate the quality of remediation suggestions.
        """)
        
        # Option to select remediation type
        # Only using SBERT similarity-based remediation as per project requirements
        remediation_type = "improved"
        st.info("Using SBERT similarity-based retrieval from remediation corpus as specified in the project requirements.")
        
        # Check if previous evaluations exist
        latest_eval = model_evaluation.get_latest_evaluation("remediation")
        
        if latest_eval and st.checkbox("Show previous evaluation", value=True, key="remediation_prev_eval"):
            st.info(f"Showing evaluation from {latest_eval.get('timestamp', 'unknown date')}")
            
            # Display improved metrics
            if "improved_metrics" in latest_eval:
                st.subheader("Basic Pattern-Based Remediation Metrics")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("BLEU Score", f"{latest_eval['improved_metrics'].get('avg_bleu', 0):.4f}")
                with col2:
                    st.metric("METEOR Score", f"{latest_eval['improved_metrics'].get('avg_meteor', 0):.4f}")
            
            # SBERT similarity-based retrieval is the only remediation system used
            # as per project requirements
        
        # Create a form for evaluation
        with st.form("remediation_evaluation_form"):
            st.subheader("Run New Evaluation")
            
            # We are only using the SBERT similarity-based remediation now
            # as specified in the project requirements
            
            # Submit button
            submitted = st.form_submit_button("Run Evaluation")
        
        if submitted:
            with st.spinner("Running remediation evaluation... This may take a moment."):
                try:
                    # Run the evaluation using sample data
                    metrics = model_evaluation.evaluate_remediation(
                        remediation_type=remediation_type
                    )
                    
                    # Display results
                    st.success("Evaluation completed!")
                    
                    # Display improved metrics
                    if "improved_metrics" in metrics:
                        st.subheader("Basic Pattern-Based Remediation Metrics")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("BLEU Score", f"{metrics['improved_metrics'].get('avg_bleu', 0):.4f}")
                        with col2:
                            st.metric("METEOR Score", f"{metrics['improved_metrics'].get('avg_meteor', 0):.4f}")
                    
                    # SBERT similarity-based retrieval is the only remediation system used
                    # as per project requirements
                except Exception as e:
                    st.error(f"Error during evaluation: {e}")
    
    # We are now focusing only on the SBERT-based remediation approach
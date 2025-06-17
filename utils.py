import os
import platform
import re
import random
import string
import subprocess
import socket

# Simple text preprocessing function that doesn't rely on NLTK
def preprocess_text(text):
    """
    Preprocess text for NLP tasks
    
    Args:
        text (str): Input text
    
    Returns:
        str: Preprocessed text
    """
    # Convert to lowercase
    text = text.lower()
    
    # Simple tokenization by splitting on whitespace
    tokens = text.split()
    
    # Simple stopwords list
    stopwords = ['a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what',
                'with', 'by', 'for', 'is', 'in', 'to', 'of', 'from', 'on', 'at']
    
    # Remove stopwords
    tokens = [token for token in tokens if token not in stopwords]
    
    # Remove punctuation and numbers
    cleaned_tokens = []
    for token in tokens:
        # Keep only alphabetic characters
        cleaned_token = ''.join(c for c in token if c.isalpha())
        if cleaned_token:  # Only add non-empty tokens
            cleaned_tokens.append(cleaned_token)
    
    # Rejoin tokens
    preprocessed_text = ' '.join(cleaned_tokens)
    
    return preprocessed_text

def get_host_os_info():
    """
    Get information about the host operating system
    
    Returns:
        dict: Operating system information
    """
    os_info = {
        "type": platform.system(),
        "name": platform.system(),
        "version": platform.version(),
        "release": platform.release()
    }
    
    # Get more detailed information based on the OS
    os_type = platform.system().lower()
    
    if os_type == "windows":
        try:
            os_info["edition"] = platform.win32_edition()
        except:
            os_info["edition"] = "Unknown"
    
    elif os_type == "linux":
        try:
            # If distro module is not available, use a more basic approach
            try:
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            os_info["distro"] = line.split('=')[1].strip().strip('"')
                            break
            except:
                os_info["distro"] = "Unknown Linux distribution"
        except:
            os_info["distro"] = "Unknown Linux distribution"
    
    elif os_type == "darwin":
        try:
            # For macOS, get the marketing name if possible
            mac_ver = platform.mac_ver()
            os_info["version"] = mac_ver[0]
            
            # Map macOS version to marketing name (simplified)
            macos_versions = {
                "10.15": "Catalina",
                "11.0": "Big Sur",
                "12.0": "Monterey",
                "13.0": "Ventura"
            }
            
            for ver, name in macos_versions.items():
                if mac_ver[0].startswith(ver):
                    os_info["marketing_name"] = name
                    break
        except:
            pass
    
    return os_info

def calculate_cvss_score(base_score, temporal_score=None, environmental_score=None):
    """
    Calculate CVSS score considering temporal and environmental factors
    
    Args:
        base_score (float): Base CVSS score
        temporal_score (float, optional): Temporal CVSS score
        environmental_score (float, optional): Environmental CVSS score
    
    Returns:
        float: Final CVSS score
    """
    # For simplicity, we're just using the base score in this example
    # In a real implementation, we would apply the CVSS formula
    return base_score

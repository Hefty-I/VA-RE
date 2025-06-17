import os
import json
import random
from utils import preprocess_text
import nvd_feed_processor

# File to store the remediation corpus based on real NVD data
REMEDIATION_CORPUS_FILE = "data/remediation_corpus.json"

# Global variables for remediation generator
remediation_corpus = None

def text_similarity(text1, text2):
    """
    Calculate text similarity using BERT-like semantic embeddings
    
    Args:
        text1 (str): First text
        text2 (str): Second text
    
    Returns:
        float: Similarity score between 0 and 1
    """
    try:
        # Try to use SBERT-like embeddings
        import sbert_embedding
        return sbert_embedding.semantic_similarity(text1, text2)
    except (ImportError, Exception) as e:
        # Fall back to Jaccard similarity for any error
        print(f"SBERT embeddings error, falling back to Jaccard similarity: {str(e)}")
        
        # Preprocess texts
        def simple_preprocess(text):
            if not isinstance(text, str):
                return ""
            # Convert to lowercase
            text = text.lower()
            # Remove punctuation
            import string
            text = ''.join([char for char in text if char not in string.punctuation])
            # Split into words
            return text
        
        # Use simple preprocessing if the main function fails
        words1 = set(simple_preprocess(text1).split())
        words2 = set(simple_preprocess(text2).split())
        
        # Calculate Jaccard similarity
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0

def load_or_generate_remediation_corpus():
    """
    Load remediation corpus from file or generate from NVD data
    
    Returns:
        list: List of remediation entries
    """
    global remediation_corpus
    
    # If already loaded, return the existing corpus
    if remediation_corpus is not None:
        return remediation_corpus
    
    # Check if corpus file exists
    if os.path.exists(REMEDIATION_CORPUS_FILE):
        try:
            with open(REMEDIATION_CORPUS_FILE, 'r') as f:
                remediation_corpus = json.load(f)
                return remediation_corpus
        except Exception as e:
            print(f"Error loading remediation corpus: {e}")
    
    # Generate corpus from NVD data
    print("Generating remediation corpus from NVD data...")
    
    # Get remediation data from NVD feed processor
    remediation_data = nvd_feed_processor.generate_remediation_training_data()
    
    # Flatten the dictionary into a list
    corpus = []
    
    # Ensure remediation_data is a dictionary and has content
    if not remediation_data or not isinstance(remediation_data, dict):
        remediation_data = {
            "network": [],
            "os": [],
            "application": [],
            "web": []
        }
    
    for vuln_type, entries in remediation_data.items():
        if entries and isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    corpus.append({
                        "type": vuln_type,
                        "keywords": entry.get("keywords", []),
                        "title": entry.get("title", "Vulnerability"),
                        "remediation": entry.get("remediation", "No remediation available")
                    })
    
    # Add default remediation entries for each type
    default_remediations = {
        "network": """
### Network Vulnerability Remediation

1. **Patch and Update**
   - Apply security patches immediately
   - Keep firmware and software updated
   - Subscribe to vendor security advisories

2. **Network Segmentation**
   - Implement proper network segmentation
   - Use firewalls and access control lists
   - Isolate critical systems from public networks

3. **Traffic Monitoring**
   - Implement network monitoring
   - Use intrusion detection/prevention systems
   - Monitor for unusual network activity

4. **Security Testing**
   - Conduct regular network security assessments
   - Perform vulnerability scanning
   - Test network security controls
""",
        "os": """
### Operating System Vulnerability Remediation

1. **System Updates**
   - Apply OS security patches promptly
   - Enable automatic updates where appropriate
   - Maintain a regular patching schedule

2. **System Hardening**
   - Remove unnecessary services and applications
   - Implement least privilege principles
   - Use security baselines (CIS, NIST, etc.)

3. **Access Control**
   - Implement strong authentication mechanisms
   - Use role-based access control
   - Regularly audit user accounts and permissions

4. **System Monitoring**
   - Enable comprehensive logging
   - Implement file integrity monitoring
   - Monitor for suspicious activities
""",
        "application": """
### Application Vulnerability Remediation

1. **Application Updates**
   - Keep applications updated to latest versions
   - Apply security patches promptly
   - Monitor vendor security advisories

2. **Secure Configuration**
   - Remove default credentials and sample content
   - Disable unnecessary features and services
   - Configure security settings according to best practices

3. **Input Validation**
   - Implement strict input validation
   - Sanitize all user inputs
   - Use allowlist approaches where possible

4. **Security Testing**
   - Conduct regular application security testing
   - Implement secure code review practices
   - Use static and dynamic application security testing
""",
        "web": """
### Web Application Vulnerability Remediation

1. **Security Headers**
   - Implement Content-Security-Policy
   - Use HTTP Strict Transport Security (HSTS)
   - Configure X-Content-Type-Options, X-Frame-Options

2. **Input Handling**
   - Implement proper input validation and sanitization
   - Use parameterized queries for database operations
   - Encode output based on the context

3. **Authentication & Session Management**
   - Implement secure authentication mechanisms
   - Use proper session management
   - Apply secure cookie settings

4. **Regular Testing**
   - Conduct web application penetration testing
   - Use web application scanning tools
   - Implement continuous security testing
"""
    }
    
    for vuln_type, remediation in default_remediations.items():
        corpus.append({
            "type": vuln_type,
            "keywords": [vuln_type, "general", "default"],
            "title": f"General {vuln_type.capitalize()} Vulnerability",
            "remediation": remediation
        })
    
    # Save corpus to file
    os.makedirs(os.path.dirname(REMEDIATION_CORPUS_FILE), exist_ok=True)
    with open(REMEDIATION_CORPUS_FILE, 'w') as f:
        json.dump(corpus, f, indent=2)
    
    remediation_corpus = corpus
    return corpus

def get_specific_remediation_by_cve(cve_id):
    """
    Get specific remediation advice for a known CVE
    
    Args:
        cve_id (str): CVE ID to lookup
        
    Returns:
        str: Remediation text or None if not found
    """
    # Search for the CVE in the NVD data
    cves = nvd_feed_processor.search_cve_data(cve_id=cve_id, max_items=1)
    
    if not cves:
        return None
    
    cve = cves[0]
    description = cve.get("description", "")
    
    # Patterns to look for in the description that might contain remediation advice
    remediation_indicators = [
        "update to version", "upgrade to version", "fixed in version",
        "addressed in version", "patched in", "is available",
        "has released", "has issued", "mitigated by"
    ]
    
    remediation_notes = []
    
    # Check for remediation clues in the description
    for indicator in remediation_indicators:
        if indicator in description.lower():
            # Find the sentence containing the indicator
            sentences = description.split(". ")
            for sentence in sentences:
                if indicator in sentence.lower():
                    remediation_notes.append(sentence.strip() + ".")
    
    # Check for remediation information in references
    references = cve.get("references", [])
    if references:
        remediation_notes.append(f"For detailed remediation, refer to these references:")
        for ref in references[:5]:  # Limit to first 5 references
            remediation_notes.append(f"- {ref}")
    
    # If we found specific remediation advice, return it
    if remediation_notes:
        return "\n".join([
            f"### Specific Remediation for {cve_id}",
            "",
            *remediation_notes,
            "",
            "### General Remediation Steps",
            "",
            "1. Apply the vendor-provided security patch or update",
            "2. If a patch is not available, consider implementing workarounds mentioned in advisories",
            "3. Monitor vendor security announcements for updates",
            "4. Consider additional security controls to mitigate risk"
        ])
    
    return None

def generate_remediation_suggestion(vulnerability):
    """
    Generate remediation suggestions for a vulnerability using similarity-based retrieval
    
    Args:
        vulnerability (dict): Vulnerability information
    
    Returns:
        str: Remediation suggestion text
    """
    if not vulnerability or not isinstance(vulnerability, dict):
        return "No vulnerability information provided to generate remediation."
    
    # First, check if this is a known CVE with specific remediation advice
    if "id" in vulnerability and vulnerability["id"].startswith("CVE-"):
        specific_remediation = get_specific_remediation_by_cve(vulnerability["id"])
        if specific_remediation:
            return specific_remediation
    
    # Initialize the remediation corpus if needed
    global remediation_corpus
    if remediation_corpus is None:
        remediation_corpus = load_or_generate_remediation_corpus()
    
    # Ensure we have a corpus to work with
    if not remediation_corpus or not isinstance(remediation_corpus, list) or len(remediation_corpus) == 0:
        # Return a generic remediation if corpus is not available
        return """
### General Vulnerability Remediation

1. **Keep Systems Updated**
   - Apply security patches promptly
   - Update software to the latest versions
   - Subscribe to security advisories

2. **Implement Defense in Depth**
   - Use multiple security layers
   - Apply the principle of least privilege
   - Implement network segmentation

3. **Regular Security Testing**
   - Conduct vulnerability assessments
   - Perform penetration testing
   - Use automated security scanning tools

4. **Security Monitoring**
   - Implement comprehensive logging
   - Monitor for unusual activities
   - Develop incident response procedures
"""
    
    # Extract vulnerability information
    vuln_type = vulnerability.get("type", "network")
    description = vulnerability.get("description", "")
    title = vulnerability.get("title", "")
    
    # Create a query text from the vulnerability information
    query_text = f"{title} {description} {vuln_type}"
    
    # Identify common vulnerability patterns from title/description
    common_vuln_patterns = {
        "sql injection": ["sql injection", "sql", "injection", "database", "query"],
        "xss": ["cross-site scripting", "xss", "script injection", "html injection"],
        "csrf": ["cross-site request forgery", "csrf", "request forgery"],
        "buffer overflow": ["buffer overflow", "buffer overrun", "stack overflow", "heap overflow"],
        "command injection": ["command injection", "shell injection", "os command"],
        "path traversal": ["path traversal", "directory traversal", "../", "file inclusion"],
        "authentication bypass": ["auth bypass", "authentication bypass", "login bypass"],
        "privilege escalation": ["privilege escalation", "priv esc", "elevation of privilege"],
        "remote code execution": ["remote code execution", "rce", "arbitrary code execution"],
        "insecure deserialization": ["deserialization", "serialization", "object injection"],
        "denial of service": ["denial of service", "dos", "resource exhaustion"],
        "information disclosure": ["information disclosure", "data leak", "sensitive data exposure"]
    }
    
    # Check if the vulnerability matches any common patterns
    identified_patterns = []
    lower_query = query_text.lower()
    
    for pattern_name, keywords in common_vuln_patterns.items():
        for keyword in keywords:
            if keyword.lower() in lower_query:
                identified_patterns.append(pattern_name)
                break
    
    # Find the most similar remediation entries from corpus
    candidates = []
    
    # First pass: look for exact matches with identified patterns
    if identified_patterns:
        for item in remediation_corpus:
            if not isinstance(item, dict):
                continue
                
            item_type = item.get("type", "")
            item_title = item.get("title", "").lower()
            item_keywords = item.get("keywords", [])
            
            # If the item matches any of our identified patterns
            for pattern in identified_patterns:
                if (pattern in item_title or 
                    any(pattern in keyword.lower() for keyword in item_keywords)):
                    # It's a match - calculate exact similarity
                    similarity = text_similarity(query_text, f"{item_title} {' '.join(item_keywords)}")
                    candidates.append((item, similarity))
    
    # If no matches with identified patterns, use type-based matching
    if not candidates:
        # Look for items matching the vulnerability type
        for item in remediation_corpus:
            if not isinstance(item, dict):
                continue
                
            item_type = item.get("type", "")
            if item_type == vuln_type:
                item_title = item.get("title", "")
                item_keywords = item.get("keywords", [])
                
                # Calculate similarity
                similarity = text_similarity(query_text, f"{item_type} {item_title} {' '.join(item_keywords)}")
                candidates.append((item, similarity))
    
    # If still no candidates, include all corpus items
    if not candidates:
        for item in remediation_corpus:
            if not isinstance(item, dict):
                continue
                
            item_type = item.get("type", "")
            item_title = item.get("title", "")
            item_keywords = item.get("keywords", [])
            
            # Calculate similarity
            similarity = text_similarity(query_text, f"{item_type} {item_title} {' '.join(item_keywords)}")
            candidates.append((item, similarity))
    
    # Sort candidates by similarity score
    candidates.sort(key=lambda x: x[1], reverse=True)
    
    # If no candidates or similarity too low, use generic remediation based on type
    if not candidates or candidates[0][1] < 0.1:
        # Default to generic remediation based on vulnerability type
        for item in remediation_corpus:
            if not isinstance(item, dict):
                continue
                
            item_type = item.get("type", "")
            item_keywords = item.get("keywords", [])
            
            if item_type == vuln_type and "general" in item_keywords:
                return item.get("remediation", "No specific remediation available.")
        
        # If no type match, return a very generic remediation
        generic_remediation = """
### General Vulnerability Remediation

1. **Keep Systems Updated**
   - Apply security patches promptly
   - Update software to the latest versions
   - Subscribe to security advisories

2. **Implement Defense in Depth**
   - Use multiple security layers
   - Apply the principle of least privilege
   - Implement network segmentation

3. **Regular Security Testing**
   - Conduct vulnerability assessments
   - Perform penetration testing
   - Use automated security scanning tools

4. **Security Monitoring**
   - Implement comprehensive logging
   - Monitor for unusual activities
   - Develop incident response procedures
"""
        if identified_patterns:
            # If we identified patterns but couldn't find matches, provide that info
            pattern_list = ", ".join(identified_patterns)
            return f"""
### Remediation for {pattern_list.title()} Vulnerability

{generic_remediation}
"""
        else:
            return generic_remediation
    
    # We have at least one good candidate
    best_match = candidates[0][0]
    
    # Add a custom header if we identified patterns
    remediation_text = best_match.get("remediation", "No specific remediation available.")
    
    if identified_patterns and not remediation_text.strip().startswith("###"):
        pattern_list = ", ".join(p.title() for p in identified_patterns)
        return f"### Remediation for {pattern_list} Vulnerability\n\n{remediation_text}"
    
    return remediation_text

if __name__ == "__main__":
    # Example usage
    corpus = load_or_generate_remediation_corpus()
    print(f"Loaded {len(corpus)} remediation entries")
    
    # Test with a sample vulnerability
    sample_vuln = {
        "id": "CVE-2023-12345",
        "title": "SQL Injection Vulnerability",
        "description": "A SQL injection vulnerability in the login form allows attackers to execute arbitrary SQL commands.",
        "type": "web"
    }
    
    remediation = generate_remediation_suggestion(sample_vuln)
    print("\nGenerated Remediation:")
    print(remediation)
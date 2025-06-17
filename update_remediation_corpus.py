import os
import json

# Path to remediation corpus file
REMEDIATION_CORPUS_FILE = "data/remediation_corpus.json"

# Load existing corpus
if os.path.exists(REMEDIATION_CORPUS_FILE):
    with open(REMEDIATION_CORPUS_FILE, 'r') as f:
        remediation_corpus = json.load(f)
else:
    remediation_corpus = []

# New specific remediations to add
new_remediations = [
    {
        "type": "web",
        "keywords": ["sql injection", "sqli", "sql", "database injection"],
        "title": "SQL Injection",
        "remediation": """
### SQL Injection Remediation

1. **Parameterized Queries**
   - Use prepared statements with parameterized queries
   - Avoid string concatenation for SQL statements
   - Utilize ORM frameworks when possible

2. **Input Validation**
   - Implement strict input validation
   - Use allowlist validation for user inputs
   - Validate data type, length, format, and range

3. **Database Access Controls**
   - Use least privilege database accounts
   - Create different DB users for different applications
   - Restrict database permissions to only what's necessary

4. **Error Handling**
   - Implement custom error pages
   - Avoid exposing database errors to users
   - Log errors securely for debugging
"""
    },
    {
        "type": "web",
        "keywords": ["cross-site scripting", "xss", "script injection", "html injection"],
        "title": "Cross-Site Scripting",
        "remediation": """
### Cross-Site Scripting (XSS) Remediation

1. **Output Encoding**
   - Encode user-controlled data before rendering in HTML
   - Use context-specific encoding (HTML, JavaScript, CSS, URL)
   - Utilize templating systems with automatic encoding

2. **Content Security Policy**
   - Implement a strong Content Security Policy
   - Use nonces or hashes for inline scripts
   - Set 'unsafe-inline' and 'unsafe-eval' to 'none'

3. **Input Validation**
   - Sanitize user input
   - Use allowlist approaches for HTML
   - Validate data on the server side

4. **Cookie Security**
   - Set HttpOnly flag on sensitive cookies
   - Use the Secure flag for HTTPS connections
   - Consider using the SameSite attribute
"""
    },
    {
        "type": "web",
        "keywords": ["cross-site request forgery", "csrf", "xsrf", "request forgery"],
        "title": "Cross-Site Request Forgery",
        "remediation": """
### Cross-Site Request Forgery (CSRF) Remediation

1. **CSRF Tokens**
   - Implement per-session or per-request CSRF tokens
   - Validate tokens on state-changing requests
   - Include tokens in forms, Ajax requests, and headers

2. **SameSite Cookies**
   - Set SameSite attribute to 'Lax' or 'Strict'
   - Use httpOnly and Secure flags on sensitive cookies
   - Consider cookie scope limitations

3. **Request Verification**
   - Check Referer/Origin headers (secondary defense)
   - Require re-authentication for sensitive actions
   - Implement proper CORS policies

4. **Session Management**
   - Use short session timeouts
   - Require re-authentication for sensitive operations
   - Implement logout functionality
"""
    },
    {
        "type": "web",
        "keywords": ["insecure direct object reference", "idor", "authorization bypass"],
        "title": "Insecure Direct Object Reference",
        "remediation": """
### Insecure Direct Object Reference (IDOR) Remediation

1. **Access Control Checks**
   - Verify user's authorization for each resource
   - Implement server-side validation of permissions
   - Use indirect reference maps instead of direct references

2. **Unpredictable Resource Identifiers**
   - Use random/unpredictable IDs instead of sequential ones
   - Map public IDs to internal references on the server
   - Avoid exposing database keys directly to users

3. **Contextual Access Policies**
   - Define and enforce policy-based access controls
   - Use role-based or attribute-based access control
   - Verify access in the context of the current user

4. **API Security**
   - Apply consistent access controls across all interfaces
   - Validate requests in middleware/filters
   - Log access control failures for review
"""
    },
    {
        "type": "web",
        "keywords": ["authentication bypass", "broken authentication", "login bypass"],
        "title": "Authentication Bypass",
        "remediation": """
### Authentication Bypass Remediation

1. **Strong Authentication Mechanisms**
   - Implement multi-factor authentication
   - Use strong password policies
   - Store passwords with secure hashing (bcrypt, Argon2)

2. **Session Management**
   - Generate random, unpredictable session IDs
   - Regenerate session IDs after login
   - Implement session timeouts and idle timeouts

3. **Account Recovery**
   - Secure password reset mechanisms
   - Implement rate limiting on authentication attempts
   - Use secure channels for reset credentials

4. **Authentication Workflow**
   - Verify all authentication steps server-side
   - Implement consistent error messages
   - Log authentication events for auditing
"""
    },
    {
        "type": "os",
        "keywords": ["buffer overflow", "stack overflow", "heap overflow", "memory corruption"],
        "title": "Buffer Overflow",
        "remediation": """
### Buffer Overflow Remediation

1. **Secure Coding Practices**
   - Use languages or frameworks with automatic bounds checking
   - Replace unsafe functions (strcpy, strcat, gets) with safer alternatives
   - Implement proper input validation for length and content

2. **Memory Protections**
   - Enable Address Space Layout Randomization (ASLR)
   - Implement Data Execution Prevention (DEP/NX)
   - Use stack canaries/cookies for stack protection

3. **Input Validation**
   - Validate and sanitize all inputs that could affect buffer sizes
   - Implement strict bounds checking
   - Verify array indices are within valid ranges

4. **Security Testing**
   - Perform fuzz testing to find buffer overflows
   - Use static code analysis tools
   - Conduct regular code reviews focusing on memory management
"""
    },
    {
        "type": "os",
        "keywords": ["privilege escalation", "privilege elevation", "rights escalation"],
        "title": "Privilege Escalation",
        "remediation": """
### Privilege Escalation Remediation

1. **Principle of Least Privilege**
   - Run services and applications with minimal required permissions
   - Use separate accounts for different privilege levels
   - Implement proper file and directory permissions

2. **System Hardening**
   - Remove or disable unnecessary services and features
   - Apply security patches promptly
   - Use security baselines and compliance checking

3. **Access Control**
   - Implement proper access control mechanisms
   - Validate all privilege elevation requests
   - Use mandatory access control systems where appropriate

4. **Monitoring and Auditing**
   - Enable audit logging for privilege changes
   - Monitor for unusual permission changes or access patterns
   - Regularly review privileged account usage
"""
    },
    {
        "type": "network",
        "keywords": ["remote code execution", "rce", "command execution", "arbitrary code execution"],
        "title": "Remote Code Execution",
        "remediation": """
### Remote Code Execution Remediation

1. **Input Validation**
   - Validate and sanitize all external inputs
   - Implement allowlist validation
   - Avoid using user input in command execution contexts

2. **System Hardening**
   - Apply security patches promptly
   - Remove unnecessary services and features
   - Implement principle of least privilege

3. **Defensive Programming**
   - Use safe APIs and libraries that prevent code injection
   - Implement proper error handling
   - Validate return values from functions

4. **Network Security**
   - Implement network segmentation
   - Use firewalls and access controls
   - Deploy intrusion detection/prevention systems
"""
    },
    {
        "type": "web",
        "keywords": ["path traversal", "directory traversal", "file inclusion", "../"],
        "title": "Path Traversal",
        "remediation": """
### Path Traversal Remediation

1. **Input Validation**
   - Validate file paths against an allowlist
   - Normalize all paths before validation
   - Remove or encode path traversal sequences

2. **File System Restrictions**
   - Use chroot jails or similar containment
   - Implement proper file system permissions
   - Store sensitive files outside web root

3. **Access Controls**
   - Implement proper access checks for file operations
   - Use indirect references to files (e.g., database IDs)
   - Verify user permissions for each file access

4. **Web Server Configuration**
   - Configure web server to prevent serving unauthorized files
   - Use proper MIME type handling
   - Implement file extension restrictions
"""
    },
    {
        "type": "web",
        "keywords": ["command injection", "os command injection", "shell injection", "shell command injection"],
        "title": "Command Injection",
        "remediation": """
### Command Injection Remediation

1. **API Usage**
   - Avoid shell command execution entirely if possible
   - Use language-specific APIs instead of shell commands
   - Implement libraries for specific functionality rather than system commands

2. **Input Handling**
   - Never use user input directly in system commands
   - Validate and sanitize all inputs used in command contexts
   - Use allowlist validation for permitted commands or arguments

3. **Parameter Binding**
   - Use parameterized APIs for command execution
   - Separate command from arguments clearly
   - Avoid string concatenation for building commands

4. **Restrictive Environments**
   - Run commands with limited privileges
   - Use containerization or sandboxing
   - Implement proper output handling
"""
    },
    {
        "type": "application",
        "keywords": ["insecure deserialization", "object injection", "deserialization vulnerability"],
        "title": "Insecure Deserialization",
        "remediation": """
### Insecure Deserialization Remediation

1. **Integrity Checking**
   - Implement digital signatures for serialized data
   - Use HMAC or similar to validate data hasn't been tampered with
   - Avoid accepting serialized objects from untrusted sources

2. **Safer Alternatives**
   - Use data formats without executable features (JSON, YAML)
   - Implement safe deserialization libraries
   - Consider format-specific security features

3. **Deserialization Controls**
   - Implement type constraints during deserialization
   - Use allowlist approaches for permitted classes
   - Run deserialization in lower-privileged contexts

4. **Input Validation**
   - Validate serialized data before processing
   - Implement strict schema validation
   - Monitor for abnormal serialized content
"""
    },
    {
        "type": "network",
        "keywords": ["information disclosure", "data leak", "sensitive information exposure"],
        "title": "Information Disclosure",
        "remediation": """
### Information Disclosure Remediation

1. **Data Classification**
   - Identify and classify sensitive information
   - Implement handling procedures based on sensitivity
   - Use data loss prevention mechanisms

2. **Error Handling**
   - Implement custom error pages
   - Avoid exposing system or debugging information in errors
   - Log detailed errors privately but display generic messages to users

3. **Transport Security**
   - Use TLS/HTTPS for all communications
   - Implement proper certificate validation
   - Configure secure TLS options

4. **Access Controls**
   - Implement proper authorization checks
   - Validate user permissions for each resource
   - Use principle of least privilege
"""
    }
]

# Check for duplicates and add new remediations
added_count = 0
for new_item in new_remediations:
    # Check if this item already exists in corpus
    exists = False
    for existing_item in remediation_corpus:
        if (isinstance(existing_item, dict) and 
            existing_item.get('title', '').lower() == new_item['title'].lower() and
            existing_item.get('type', '') == new_item['type']):
            # Update existing entry
            existing_item.update(new_item)
            exists = True
            break
    
    # Add if not exists
    if not exists:
        remediation_corpus.append(new_item)
        added_count += 1

# Save updated corpus
with open(REMEDIATION_CORPUS_FILE, 'w') as f:
    json.dump(remediation_corpus, f, indent=2)

print(f"Updated remediation corpus with {added_count} new entries.")
print(f"Total entries in corpus: {len(remediation_corpus)}")
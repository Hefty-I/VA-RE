import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report
from datetime import datetime
import nltk
import re

# Create a simple word tokenizer that doesn't depend on NLTK's punkt_tab
def simple_tokenize(text):
    """
    A simple word tokenizer that splits on spaces and punctuation
    without requiring NLTK's punkt_tab resource
    """
    if not isinstance(text, str):
        return []
    
    # Convert to lowercase
    text = text.lower()
    
    # Extract words (alphanumeric sequences)
    words = re.findall(r'\b[a-z0-9]+\b', text)
    
    # Generate bigrams (two consecutive words) for better feature extraction
    bigrams = []
    if len(words) >= 2:
        for i in range(len(words) - 1):
            bigrams.append(f"{words[i]}_{words[i+1]}")
    
    # Add common security terms if they appear in the text
    security_terms = [
        "vulnerability", "exploit", "attack", "remote", "execution",
        "injection", "overflow", "bypass", "disclosure", "access",
        "authentication", "authorization", "privilege", "escalation",
        "denial", "service", "malicious", "backdoor", "sensitive", 
        "command", "sql", "xss", "csrf", "session", "fixation"
    ]
    
    for term in security_terms:
        if term in text:
            words.append(f"TERM_{term}")
    
    # Combine words and bigrams for a richer feature set
    return words + bigrams

# Use this for all tokenization needs
nltk.word_tokenize = simple_tokenize

try:
    from nltk.translate.bleu_score import sentence_bleu
    from nltk.translate.meteor_score import meteor_score
    from nltk.translate.meteor_score import single_meteor_score
except ImportError:
    # Download needed NLTK resources
    nltk.download('wordnet')
    nltk.download('punkt')
    nltk.download('omw-1.4')
    from nltk.translate.bleu_score import sentence_bleu
    from nltk.translate.meteor_score import meteor_score
    from nltk.translate.meteor_score import single_meteor_score

# Local modules
import improved_classifier
import improved_remediation

# OpenAI remediation removed as per project requirements
AI_REMEDIATION_AVAILABLE = False

# Constants
EVALUATION_DIR = "data/evaluation"
os.makedirs(EVALUATION_DIR, exist_ok=True)

def evaluate_classifier(test_data=None, test_labels=None, classifier_type="improved"):
    """
    Evaluate the performance of the vulnerability classifier
    
    Args:
        test_data (list): Test data (if None, will use sample data)
        test_labels (list): Test labels (if None, will use sample data)
        classifier_type (str): Type of classifier to use ('improved' or 'ensemble')
    
    Returns:
        dict: Performance metrics
    """
    # Load or create test data
    if test_data is None or test_labels is None:
        # Sample test data
        test_data = [
            "Remote code execution vulnerability in web server",
            "SQL injection vulnerability in login form",
            "Information disclosure in API endpoint",
            "Cross-site scripting vulnerability in comment form",
            "Buffer overflow in system service",
            "Authorization bypass in admin console",
            "Path traversal vulnerability in file manager",
            "Insecure cryptographic implementation"
        ]
        test_labels = ["Critical", "High", "Medium", "High", "Critical", "High", "Medium", "Medium"]
    
    # Get classifications
    predictions = []
    for item in test_data:
        # Create a vulnerability object
        vuln = {
            "description": item,
            "title": item.split(" in ")[0] if " in " in item else item
        }
        
        # Classify using the appropriate classifier
        if classifier_type == "ensemble":
            try:
                from models.ensemble_classifier import EnsembleClassifier
                ensemble_path = "data/models/ensemble_classifier.pkl"
                if os.path.exists(ensemble_path):
                    classifier = EnsembleClassifier.load_model(ensemble_path)
                    prediction = classifier.predict([item])[0]
                else:
                    prediction = improved_classifier.classify_vulnerability_severity(vuln)
            except Exception as e:
                print(f"Error using ensemble classifier: {e}")
                prediction = improved_classifier.classify_vulnerability_severity(vuln)
        else:
            # Use the improved classifier
            prediction = improved_classifier.classify_vulnerability_severity(vuln)
        
        predictions.append(prediction)
    
    # Calculate metrics
    metrics = {
        "accuracy": accuracy_score(test_labels, predictions),
        "precision": precision_score(test_labels, predictions, average='weighted'),
        "recall": recall_score(test_labels, predictions, average='weighted'),
        "f1": f1_score(test_labels, predictions, average='weighted')
    }
    
    # Calculate per-class metrics
    report = classification_report(test_labels, predictions, output_dict=True)
    class_metrics = {}
    for label in set(test_labels):
        if label in report:
            class_metrics[label] = {
                "precision": report[label]["precision"],
                "recall": report[label]["recall"],
                "f1_score": report[label]["f1-score"]
            }
    
    metrics["class_metrics"] = class_metrics
    metrics["confusion_matrix"] = confusion_matrix(test_labels, predictions, labels=list(set(test_labels))).tolist()
    metrics["labels"] = list(set(test_labels))
    metrics["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    metrics["classifier_type"] = classifier_type
    
    # Save metrics
    save_path = os.path.join(EVALUATION_DIR, f"classifier_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(save_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    return metrics

def evaluate_remediation(test_data=None, reference_remediations=None, remediation_type="improved"):
    """
    Evaluate the performance of the remediation suggestion system
    
    Args:
        test_data (list): Test vulnerability data (if None, will use sample data)
        reference_remediations (list): Reference remediation texts
        remediation_type (str): Type of remediation to evaluate ('improved', 'ai', or 'both')
    
    Returns:
        dict: Performance metrics
    """
    # Load or create test data
    if test_data is None:
        # Sample test data
        test_data = [
            {
                "id": "CVE-2023-00001",
                "title": "SQL Injection",
                "description": "A SQL injection vulnerability in the login form allows attackers to execute arbitrary SQL commands.",
                "type": "web"
            },
            {
                "id": "CVE-2023-00002",
                "title": "Cross-Site Scripting",
                "description": "A cross-site scripting vulnerability in the comment form allows attackers to inject malicious scripts.",
                "type": "web"
            },
            {
                "id": "CVE-2023-00003", 
                "title": "Buffer Overflow",
                "description": "A buffer overflow vulnerability in the network service allows attackers to execute arbitrary code.",
                "type": "network"
            },
            {
                "id": "CVE-2023-00004",
                "title": "Path Traversal",
                "description": "A path traversal vulnerability in the file manager allows attackers to access unauthorized files.",
                "type": "application"
            }
        ]
    
    # Reference remediations (expert-written)
    if reference_remediations is None:
        reference_remediations = [
            """
            ### SQL Injection Remediation
            
            1. **Input Validation**
               - Implement strict input validation
               - Use parameterized queries or prepared statements
               - Apply allowlist validation for user inputs
               
            2. **Security Controls**
               - Use an ORM (Object-Relational Mapping) framework
               - Apply principle of least privilege to database accounts
               - Implement a web application firewall (WAF)
               
            3. **Code Review**
               - Perform code review to identify SQL injection vulnerabilities
               - Use static application security testing (SAST) tools
               - Conduct penetration testing
            """,
            
            """
            ### Cross-Site Scripting (XSS) Remediation
            
            1. **Content Security Policy**
               - Implement a strong Content Security Policy
               - Use nonces or hashes for scripts
               - Set appropriate CSP headers
               
            2. **Output Encoding**
               - Encode user input before rendering in HTML context
               - Use context-specific encoding functions
               - Sanitize HTML output
               
            3. **Input Validation**
               - Validate user inputs on the server side
               - Apply allowlist validation
               - Use XSS-aware libraries
            """,
            
            """
            ### Buffer Overflow Remediation
            
            1. **Secure Coding Practices**
               - Use safe functions that perform bounds checking
               - Avoid vulnerable functions like strcpy, strcat, sprintf
               - Replace with safer alternatives: strncpy, strncat, snprintf
               
            2. **Memory Safety**
               - Implement ASLR (Address Space Layout Randomization)
               - Use DEP (Data Execution Prevention)
               - Apply stack canaries/cookies
               
            3. **Code Review & Testing**
               - Use static analysis tools to detect buffer overflows
               - Perform fuzz testing
               - Conduct regular security code reviews
            """,
            
            """
            ### Path Traversal Remediation
            
            1. **Input Validation**
               - Sanitize and validate file paths
               - Use allowlist validation for file operations
               - Normalize paths before validation
               
            2. **Access Controls**
               - Implement proper access controls
               - Use chroot jails or similar containment
               - Apply principle of least privilege
               
            3. **Security Architecture**
               - Store sensitive files outside the web root
               - Use indirect file references (e.g., database IDs instead of paths)
               - Implement file access monitoring and logging
            """
        ]
    
    # Generate remediations
    improved_remediations = []
    ai_remediations = []
    
    for vuln in test_data:
        # Get improved remediation
        imp_remediation_text = improved_remediation.generate_remediation_suggestion(vuln)
        improved_remediations.append(imp_remediation_text)
        
        # AI remediation removed as per project requirements
        if AI_REMEDIATION_AVAILABLE and remediation_type in ["ai", "both"]:
            ai_remediation_text = "AI remediation has been removed as per project requirements"
            ai_remediations.append(ai_remediation_text)
    
    # Prepare evaluation metrics
    metrics = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "remediation_type": remediation_type,
        "improved_metrics": {},
        "ai_metrics": {}
    }
    
    # Evaluate improved remediations
    improved_metrics = evaluate_text_similarity(improved_remediations, reference_remediations)
    metrics["improved_metrics"] = improved_metrics
    
    # Evaluate AI remediations if available
    if AI_REMEDIATION_AVAILABLE and remediation_type in ["ai", "both"]:
        ai_metrics = evaluate_text_similarity(ai_remediations, reference_remediations)
        metrics["ai_metrics"] = ai_metrics
    
    # Save metrics
    save_path = os.path.join(EVALUATION_DIR, f"remediation_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(save_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    return metrics

def evaluate_text_similarity(generated_texts, reference_texts):
    """
    Evaluate text similarity using BLEU and METEOR scores
    
    Args:
        generated_texts (list): List of generated texts
        reference_texts (list): List of reference texts
    
    Returns:
        dict: Similarity metrics
    """
    metrics = {
        "bleu_scores": [],
        "meteor_scores": [],
        "avg_bleu": 0.0,
        "avg_meteor": 0.0
    }
    
    for i, (gen_text, ref_text) in enumerate(zip(generated_texts, reference_texts)):
        # Tokenize texts
        gen_tokens = nltk.word_tokenize(gen_text.lower())
        ref_tokens = nltk.word_tokenize(ref_text.lower())
        
        # Calculate BLEU score (works better with multiple references, but we'll use single ref)
        bleu_score = sentence_bleu([ref_tokens], gen_tokens)
        metrics["bleu_scores"].append(bleu_score)
        
        # Calculate METEOR score
        try:
            meteor = single_meteor_score(ref_tokens, gen_tokens)
        except Exception:
            # Fall back to simpler similarity if METEOR fails
            common_words = set(gen_tokens).intersection(set(ref_tokens))
            total_words = set(gen_tokens).union(set(ref_tokens))
            meteor = len(common_words) / len(total_words) if total_words else 0
        
        metrics["meteor_scores"].append(meteor)
    
    # Calculate averages
    metrics["avg_bleu"] = sum(metrics["bleu_scores"]) / len(metrics["bleu_scores"]) if metrics["bleu_scores"] else 0
    metrics["avg_meteor"] = sum(metrics["meteor_scores"]) / len(metrics["meteor_scores"]) if metrics["meteor_scores"] else 0
    
    return metrics

def plot_confusion_matrix(cm, labels, title='Confusion Matrix', save_path=None):
    """
    Plot a confusion matrix and optionally save it to a file
    
    Args:
        cm (list): Confusion matrix as a list of lists
        labels (list): Class labels
        title (str): Title for the plot
        save_path (str): Path to save the plot
    """
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels, rotation=45)
    plt.yticks(tick_marks, labels)
    
    # Add text annotations
    thresh = cm.max() / 2
    for i in range(len(labels)):
        for j in range(len(labels)):
            plt.text(j, i, format(cm[i, j], 'd'),
                    horizontalalignment="center",
                    color="white" if cm[i, j] > thresh else "black")
    
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    
    if save_path:
        plt.savefig(save_path)
        plt.close()
    else:
        plt.show()

def get_latest_evaluation(eval_type="classifier"):
    """
    Get the most recent evaluation results
    
    Args:
        eval_type (str): Type of evaluation ('classifier' or 'remediation')
    
    Returns:
        dict: Evaluation metrics or None if not found
    """
    prefix = f"{eval_type}_evaluation_"
    eval_files = [f for f in os.listdir(EVALUATION_DIR) if f.startswith(prefix) and f.endswith(".json")]
    
    if not eval_files:
        return None
    
    # Sort by timestamp (filename contains timestamp)
    latest_file = sorted(eval_files)[-1]
    
    with open(os.path.join(EVALUATION_DIR, latest_file), 'r') as f:
        return json.load(f)

def get_all_evaluations(eval_type="classifier"):
    """
    Get all evaluation results of a certain type
    
    Args:
        eval_type (str): Type of evaluation ('classifier' or 'remediation')
    
    Returns:
        list: List of evaluation metrics
    """
    prefix = f"{eval_type}_evaluation_"
    eval_files = [f for f in os.listdir(EVALUATION_DIR) if f.startswith(prefix) and f.endswith(".json")]
    
    if not eval_files:
        return []
    
    # Sort by timestamp (filename contains timestamp)
    eval_files = sorted(eval_files)
    
    evaluations = []
    for file in eval_files:
        with open(os.path.join(EVALUATION_DIR, file), 'r') as f:
            evaluations.append(json.load(f))
    
    return evaluations

def compare_remediation_methods():
    """
    Compare different remediation methods based on evaluations
    
    Returns:
        dict: Comparison results
    """
    evaluations = get_all_evaluations("remediation")
    
    if not evaluations:
        return None
    
    # Filter evaluations that have both improved and AI metrics
    both_evals = [e for e in evaluations if "improved_metrics" in e and "ai_metrics" in e and e["ai_metrics"]]
    
    if not both_evals:
        return None
    
    # Calculate average scores
    improved_bleu = [e["improved_metrics"]["avg_bleu"] for e in both_evals]
    improved_meteor = [e["improved_metrics"]["avg_meteor"] for e in both_evals]
    ai_bleu = [e["ai_metrics"]["avg_bleu"] for e in both_evals]
    ai_meteor = [e["ai_metrics"]["avg_meteor"] for e in both_evals]
    
    comparison = {
        "improved": {
            "avg_bleu": sum(improved_bleu) / len(improved_bleu) if improved_bleu else 0,
            "avg_meteor": sum(improved_meteor) / len(improved_meteor) if improved_meteor else 0,
        },
        "ai": {
            "avg_bleu": sum(ai_bleu) / len(ai_bleu) if ai_bleu else 0,
            "avg_meteor": sum(ai_meteor) / len(ai_meteor) if ai_meteor else 0,
        },
        "samples": len(both_evals)
    }
    
    # Calculate improvement percentage
    comparison["bleu_improvement"] = (comparison["ai"]["avg_bleu"] - comparison["improved"]["avg_bleu"]) / comparison["improved"]["avg_bleu"] * 100 if comparison["improved"]["avg_bleu"] > 0 else 0
    comparison["meteor_improvement"] = (comparison["ai"]["avg_meteor"] - comparison["improved"]["avg_meteor"]) / comparison["improved"]["avg_meteor"] * 100 if comparison["improved"]["avg_meteor"] > 0 else 0
    
    return comparison

if __name__ == "__main__":
    # Run evaluation examples
    classifier_metrics = evaluate_classifier()
    print("Classifier Evaluation:")
    print(f"Accuracy: {classifier_metrics['accuracy']:.4f}")
    print(f"Precision: {classifier_metrics['precision']:.4f}")
    print(f"Recall: {classifier_metrics['recall']:.4f}")
    print(f"F1 Score: {classifier_metrics['f1']:.4f}")
    
    print("\nRemediation Evaluation:")
    remediation_metrics = evaluate_remediation()
    print(f"BLEU Score: {remediation_metrics['improved_metrics']['avg_bleu']:.4f}")
    print(f"METEOR Score: {remediation_metrics['improved_metrics']['avg_meteor']:.4f}")
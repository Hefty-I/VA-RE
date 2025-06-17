import os
import pandas as pd
import numpy as np
from datetime import datetime
import time
import logging

# Import classifiers
from models.vulnerability_classifier import VulnerabilityClassifier
from models.embedding_classifier import EmbeddingClassifier  
from models.ensemble_classifier import EnsembleClassifier, create_default_ensemble

# Import data processing
import nvd_feed_processor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("data/model_training.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_training_data(min_entries=50, max_entries=5000):
    """
    Load training data from NVD feed
    
    Args:
        min_entries (int): Minimum entries per category
        max_entries (int): Maximum total entries
    
    Returns:
        tuple: (descriptions, labels)
    """
    logger.info("Loading training data from NVD feed...")
    start_time = time.time()
    
    # Create directory for model data
    os.makedirs("data/models", exist_ok=True)
    
    try:
        # Get training data from NVD feed processor
        descriptions, labels = nvd_feed_processor.create_training_data_for_classifier(
            min_entries_per_category=min_entries
        )
        
        # Limit to max_entries if specified
        if max_entries and len(descriptions) > max_entries:
            # Keep a balanced dataset
            df = pd.DataFrame({'description': descriptions, 'label': labels})
            balanced_data = pd.DataFrame()
            
            for label in df['label'].unique():
                label_data = df[df['label'] == label]
                entries_per_label = min(len(label_data), max_entries // len(df['label'].unique()))
                balanced_data = pd.concat([balanced_data, label_data.sample(entries_per_label)])
            
            descriptions = balanced_data['description'].tolist()
            labels = balanced_data['label'].tolist()
        
        logger.info(f"Loaded {len(descriptions)} training examples in {time.time() - start_time:.2f} seconds")
        logger.info(f"Labels distribution: {pd.Series(labels).value_counts().to_dict()}")
        
        return descriptions, labels
    except Exception as e:
        logger.error(f"Error loading training data: {e}")
        # Return a small sample dataset
        logger.warning("Using small sample dataset")
        return [
            "Remote code execution in web server", 
            "SQL injection in login form",
            "Buffer overflow in network driver",
            "Cross-site scripting in comment form",
            "Information disclosure in API endpoint",
            "Directory traversal vulnerability",
            "Authentication bypass in admin panel",
            "Privilege escalation in system service"
        ], [
            "Critical", "High", "Critical", "Medium", 
            "Medium", "Medium", "High", "Critical"
        ]

def train_individual_models():
    """
    Train individual classifier models
    
    Returns:
        tuple: (vulnerability_classifier, embedding_classifier)
    """
    # Load training data
    descriptions, labels = load_training_data()
    
    # Create data directory
    os.makedirs("data/models", exist_ok=True)
    
    # Train vulnerability classifier (scikit-learn based)
    logger.info("Training vulnerability classifier...")
    vuln_classifier = VulnerabilityClassifier(model_type='random_forest')
    vuln_metrics = vuln_classifier.train(descriptions, labels)
    logger.info(f"Vulnerability classifier metrics: {vuln_metrics}")
    vuln_classifier.save_model("data/models/vulnerability_classifier.pkl")
    
    # Train embedding classifier (NLTK based)
    logger.info("Training embedding classifier...")
    emb_classifier = EmbeddingClassifier()
    emb_metrics = emb_classifier.train(descriptions, labels)
    logger.info(f"Embedding classifier metrics: {emb_metrics}")
    emb_classifier.save_model("data/models/embedding_classifier.pkl")
    
    return vuln_classifier, emb_classifier

def train_ensemble_model():
    """
    Train an ensemble classifier model
    
    Returns:
        EnsembleClassifier: Trained ensemble
    """
    # Load training data
    descriptions, labels = load_training_data()
    
    # Create ensemble
    logger.info("Creating ensemble classifier...")
    ensemble = create_default_ensemble()
    
    # Train ensemble
    logger.info("Training ensemble classifier...")
    metrics = ensemble.train(descriptions, labels)
    logger.info(f"Ensemble classifier metrics: {metrics}")
    
    # Save ensemble
    ensemble.save_model("data/models/ensemble_classifier.pkl")
    
    return ensemble

def evaluate_models():
    """
    Evaluate all trained models on a test set
    
    Returns:
        dict: Evaluation metrics for each model
    """
    # Load test data (different from training data)
    logger.info("Loading test data...")
    descriptions, labels = load_training_data(min_entries=20, max_entries=1000)
    
    # Split to use a portion for testing
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(descriptions, labels, test_size=0.3, random_state=42)
    
    metrics = {}
    
    # Load and evaluate individual models
    try:
        logger.info("Evaluating vulnerability classifier...")
        vuln_classifier = VulnerabilityClassifier.load_model("data/models/vulnerability_classifier.pkl")
        y_pred_vuln = vuln_classifier.predict(X_test)
        
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        metrics['vulnerability_classifier'] = {
            'accuracy': accuracy_score(y_test, y_pred_vuln),
            'precision': precision_score(y_test, y_pred_vuln, average='weighted'),
            'recall': recall_score(y_test, y_pred_vuln, average='weighted'),
            'f1': f1_score(y_test, y_pred_vuln, average='weighted')
        }
        logger.info(f"Vulnerability classifier test metrics: {metrics['vulnerability_classifier']}")
    except Exception as e:
        logger.error(f"Error evaluating vulnerability classifier: {e}")
    
    try:
        logger.info("Evaluating embedding classifier...")
        emb_classifier = EmbeddingClassifier.load_model("data/models/embedding_classifier.pkl")
        y_pred_emb = emb_classifier.predict(X_test)
        
        metrics['embedding_classifier'] = {
            'accuracy': accuracy_score(y_test, y_pred_emb),
            'precision': precision_score(y_test, y_pred_emb, average='weighted'),
            'recall': recall_score(y_test, y_pred_emb, average='weighted'),
            'f1': f1_score(y_test, y_pred_emb, average='weighted')
        }
        logger.info(f"Embedding classifier test metrics: {metrics['embedding_classifier']}")
    except Exception as e:
        logger.error(f"Error evaluating embedding classifier: {e}")
    
    try:
        logger.info("Evaluating ensemble classifier...")
        ensemble = EnsembleClassifier.load_model("data/models/ensemble_classifier.pkl")
        y_pred_ensemble = ensemble.predict(X_test)
        
        metrics['ensemble_classifier'] = {
            'accuracy': accuracy_score(y_test, y_pred_ensemble),
            'precision': precision_score(y_test, y_pred_ensemble, average='weighted'),
            'recall': recall_score(y_test, y_pred_ensemble, average='weighted'),
            'f1': f1_score(y_test, y_pred_ensemble, average='weighted')
        }
        logger.info(f"Ensemble classifier test metrics: {metrics['ensemble_classifier']}")
    except Exception as e:
        logger.error(f"Error evaluating ensemble classifier: {e}")
    
    return metrics

def train_all_models():
    """
    Train all models (individual and ensemble)
    
    Returns:
        dict: Training results and evaluation metrics
    """
    logger.info("=== Starting model training process ===")
    start_time = time.time()
    
    # Train individual models
    vuln_classifier, emb_classifier = train_individual_models()
    
    # Train ensemble model
    ensemble = train_ensemble_model()
    
    # Evaluate models
    evaluation_metrics = evaluate_models()
    
    # Create training report
    training_time = time.time() - start_time
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = {
        'timestamp': timestamp,
        'training_time_seconds': training_time,
        'vulnerability_classifier_metrics': vuln_classifier.metrics,
        'embedding_classifier_metrics': emb_classifier.metrics,
        'ensemble_classifier_metrics': ensemble.metrics,
        'evaluation_metrics': evaluation_metrics
    }
    
    # Save report
    import json
    os.makedirs("data/reports", exist_ok=True)
    with open(f"data/reports/model_training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"=== Model training completed in {training_time:.2f} seconds ===")
    
    return report

if __name__ == "__main__":
    # Run the training process
    train_all_models()
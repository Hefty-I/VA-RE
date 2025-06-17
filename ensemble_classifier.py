import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle

from models.vulnerability_classifier import VulnerabilityClassifier
from models.embedding_classifier import EmbeddingClassifier

class EnsembleClassifier:
    """
    An ensemble classifier that combines multiple vulnerability classifiers
    for improved prediction accuracy
    """
    
    def __init__(self):
        """
        Initialize the ensemble classifier
        """
        self.classifiers = []
        self.weights = []
        self.is_trained = False
        self.metrics = {}
        self.label_mapping = None
    
    def add_classifier(self, classifier, weight=1.0):
        """
        Add a classifier to the ensemble
        
        Args:
            classifier: A classifier object with train and predict methods
            weight (float): Weight for this classifier in the ensemble
        """
        self.classifiers.append(classifier)
        self.weights.append(weight)
    
    def train(self, X_train, y_train, validation_split=0.2):
        """
        Train all classifiers in the ensemble
        
        Args:
            X_train (list or DataFrame): Training data
            y_train (list): Label data
            validation_split (float): Proportion to use for validation
        
        Returns:
            dict: Training metrics
        """
        # Create a mapping of labels to integers
        unique_labels = sorted(set(y_train))
        self.label_mapping = {label: i for i, label in enumerate(unique_labels)}
        
        # Split data for validation
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train, y_train, test_size=validation_split, random_state=42
        )
        
        # Train each classifier
        for i, classifier in enumerate(self.classifiers):
            print(f"Training classifier {i+1}/{len(self.classifiers)}...")
            classifier.train(X_train_split, y_train_split, validation_split=0.1)
        
        # Evaluate ensemble on validation set
        y_pred = self.predict(X_val)
        
        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_val, y_pred),
            'precision': precision_score(y_val, y_pred, average='weighted'),
            'recall': recall_score(y_val, y_pred, average='weighted'),
            'f1': f1_score(y_val, y_pred, average='weighted')
        }
        
        self.is_trained = True
        return self.metrics
    
    def predict(self, X):
        """
        Make predictions using the ensemble
        
        Args:
            X (list or DataFrame): Data to predict
        
        Returns:
            list: Predicted labels
        """
        if not self.is_trained and self.label_mapping is None:
            raise ValueError("Ensemble has not been trained yet")
        
        # Get predictions from each classifier
        all_predictions = []
        for i, classifier in enumerate(self.classifiers):
            try:
                predictions = classifier.predict(X)
                all_predictions.append(predictions)
            except Exception as e:
                print(f"Error with classifier {i}: {e}")
                # Return empty predictions for this classifier
                if isinstance(X, (list, np.ndarray)):
                    all_predictions.append([""] * len(X))
                else:
                    all_predictions.append([""] * len(X.index))
        
        # Convert predictions to a numpy array
        all_predictions = np.array(all_predictions)
        
        # Use voting to determine final predictions
        final_predictions = []
        
        # Handle the case where X is a list or DataFrame
        num_samples = len(X) if isinstance(X, (list, np.ndarray)) else len(X.index)
        
        for i in range(num_samples):
            sample_preds = all_predictions[:, i]
            
            # Count occurrences of each prediction
            unique_preds, counts = np.unique(sample_preds, return_counts=True)
            
            # Apply weights to counts
            weighted_counts = np.zeros_like(counts, dtype=float)
            for j, pred in enumerate(unique_preds):
                for k, classifier_pred in enumerate(sample_preds):
                    if classifier_pred == pred:
                        weighted_counts[j] += self.weights[k]
            
            # Get the prediction with the highest weighted count
            final_pred = unique_preds[np.argmax(weighted_counts)]
            final_predictions.append(final_pred)
        
        return final_predictions
    
    def save_model(self, path='ensemble_classifier.pkl'):
        """
        Save the ensemble model to disk
        
        Args:
            path (str): Path to save the model
        """
        if not self.is_trained:
            raise ValueError("Ensemble has not been trained yet")
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        
        # Create a dictionary of model data
        model_data = {
            'metrics': self.metrics,
            'label_mapping': self.label_mapping,
            'weights': self.weights
        }
        
        # Save the data
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        # Save individual classifiers
        base_path = os.path.splitext(path)[0]
        for i, classifier in enumerate(self.classifiers):
            classifier_path = f"{base_path}_classifier_{i}.pkl"
            classifier.save_model(classifier_path)
    
    @classmethod
    def load_model(cls, path='ensemble_classifier.pkl'):
        """
        Load a trained ensemble model from disk
        
        Args:
            path (str): Path to the saved model
        
        Returns:
            EnsembleClassifier: Loaded ensemble
        """
        # Load model data
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        # Create new ensemble
        ensemble = cls()
        ensemble.metrics = model_data['metrics']
        ensemble.label_mapping = model_data['label_mapping']
        ensemble.weights = model_data['weights']
        ensemble.is_trained = True
        
        # Load individual classifiers
        base_path = os.path.splitext(path)[0]
        i = 0
        while True:
            classifier_path = f"{base_path}_classifier_{i}.pkl"
            if not os.path.exists(classifier_path):
                break
                
            # Determine the type of classifier from the path
            if 'embedding' in classifier_path:
                classifier = EmbeddingClassifier.load_model(classifier_path)
            else:
                classifier = VulnerabilityClassifier.load_model(classifier_path)
                
            ensemble.add_classifier(classifier, ensemble.weights[i])
            i += 1
        
        return ensemble

def create_default_ensemble():
    """
    Create a default ensemble classifier with standard classifier types
    
    Returns:
        EnsembleClassifier: Default ensemble with multiple classifier types
    """
    ensemble = EnsembleClassifier()
    
    # Add a Random Forest classifier with high weight
    rf_classifier = VulnerabilityClassifier(model_type='random_forest')
    ensemble.add_classifier(rf_classifier, weight=2.0)
    
    # Add a Logistic Regression classifier with medium weight
    lr_classifier = VulnerabilityClassifier(model_type='logistic_regression')
    ensemble.add_classifier(lr_classifier, weight=1.0)
    
    # Add an Embedding classifier with high weight
    emb_classifier = EmbeddingClassifier()
    ensemble.add_classifier(emb_classifier, weight=2.0)
    
    return ensemble

if __name__ == "__main__":
    # Example usage
    X_sample = [
        "Remote code execution vulnerability in web application",
        "Information disclosure in API endpoint",
        "Cross-site scripting vulnerability in form submission",
        "Buffer overflow in network service"
    ]
    y_sample = ["Critical", "Medium", "High", "Critical"]
    
    # Create and train ensemble classifier
    ensemble = create_default_ensemble()
    metrics = ensemble.train(X_sample, y_sample)
    
    print("Ensemble training metrics:")
    for metric, value in metrics.items():
        print(f"{metric}: {value:.4f}")
    
    # Test predictions
    X_test = [
        "SQL injection vulnerability in login form",
        "Missing access control in user profile",
        "Memory corruption in audio processing library"
    ]
    
    predictions = ensemble.predict(X_test)
    print("\nEnsemble predictions:")
    for text, prediction in zip(X_test, predictions):
        print(f"Text: {text}")
        print(f"Prediction: {prediction}\n")
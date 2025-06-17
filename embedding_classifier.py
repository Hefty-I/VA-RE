import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import string

# Download NLTK resources if not already downloaded
try:
    nltk.data.find('corpora/stopwords')
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('stopwords', quiet=True)
    nltk.download('punkt', quiet=True)
    nltk.download('wordnet', quiet=True)

class EmbeddingClassifier:
    """
    An enhanced classifier for vulnerability severity using NLTK and word embeddings
    """
    
    def __init__(self):
        """
        Initialize the embedding classifier
        """
        self.label_encoder = LabelEncoder()
        self.word_vectors = {}
        self.is_trained = False
        self.metrics = {}
        self.embedding_dim = 100  # Default embedding dimension
    
    def _preprocess_text(self, text):
        """
        Preprocess text for embedding generation
        
        Args:
            text (str): Input text
        
        Returns:
            list: List of preprocessed tokens
        """
        if not isinstance(text, str):
            return []
            
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation
        text = ''.join([char for char in text if char not in string.punctuation])
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stopwords
        stop_words = set(stopwords.words('english'))
        tokens = [word for word in tokens if word not in stop_words]
        
        # Lemmatize
        lemmatizer = WordNetLemmatizer()
        tokens = [lemmatizer.lemmatize(word) for word in tokens]
        
        return tokens
    
    def _create_document_embedding(self, tokens):
        """
        Create a document embedding from tokens
        
        Args:
            tokens (list): List of tokens
        
        Returns:
            numpy.ndarray: Document embedding vector
        """
        if not tokens:
            return np.zeros(self.embedding_dim)
            
        # Sum individual word vectors
        vector_sum = np.zeros(self.embedding_dim)
        count = 0
        
        for token in tokens:
            if token in self.word_vectors:
                vector_sum += self.word_vectors[token]
                count += 1
        
        # Average the vectors
        if count > 0:
            return vector_sum / count
        else:
            return vector_sum
    
    def _generate_embeddings(self, X):
        """
        Generate embeddings for a list of texts
        
        Args:
            X (list): List of text descriptions
        
        Returns:
            numpy.ndarray: Matrix of document embeddings
        """
        embeddings = []
        
        for text in X:
            tokens = self._preprocess_text(text)
            embedding = self._create_document_embedding(tokens)
            embeddings.append(embedding)
        
        return np.array(embeddings)
    
    def _load_word_vectors(self, custom_vectors=None):
        """
        Load or create word vectors
        
        Args:
            custom_vectors (dict, optional): Custom word vectors
        """
        if custom_vectors and isinstance(custom_vectors, dict):
            self.word_vectors = custom_vectors
            # Update embedding dimension based on first vector
            for vec in custom_vectors.values():
                self.embedding_dim = len(vec)
                break
        else:
            # Create simple vectors for common security terms
            security_terms = [
                "vulnerability", "exploit", "attack", "remote", "local", "injection",
                "overflow", "buffer", "privilege", "escalation", "code", "execution",
                "cross", "site", "script", "xss", "sql", "denial", "service", "dos",
                "authentication", "bypass", "information", "disclosure", "critical",
                "high", "medium", "low", "network", "application", "web", "system",
                "patch", "update", "mitigation", "remediation", "security", "cve",
                "malware", "ransomware", "backdoor", "trojan", "worm", "virus",
                "firewall", "encryption", "decryption", "certificate", "credential"
            ]
            
            # Create random vectors for these terms
            np.random.seed(42)  # For reproducibility
            for term in security_terms:
                self.word_vectors[term] = np.random.randn(self.embedding_dim)
    
    def train(self, X_train, y_train, validation_split=0.2, custom_vectors=None):
        """
        Train the classifier
        
        Args:
            X_train (list): List of text descriptions
            y_train (list): List of labels
            validation_split (float): Proportion of data to use for validation
            custom_vectors (dict, optional): Custom word vectors
        
        Returns:
            dict: Metrics from training
        """
        # Load or create word vectors
        self._load_word_vectors(custom_vectors)
        
        # Convert to DataFrame if not already
        if isinstance(X_train, list):
            X_train = pd.DataFrame({'description': X_train})
        
        # Handle missing values
        X_train = X_train.fillna('')
        
        # Extract text descriptions
        if 'description' in X_train.columns:
            descriptions = X_train['description'].astype(str).tolist()
        elif 'title' in X_train.columns and 'description' in X_train.columns:
            descriptions = (X_train['title'] + ' ' + X_train['description']).astype(str).tolist()
        else:
            descriptions = X_train.iloc[:, 0].astype(str).tolist()
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y_train)
        
        # Generate embeddings
        X_embeddings = self._generate_embeddings(descriptions)
        
        # Split into training and validation sets
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_embeddings, y_encoded, test_size=validation_split, random_state=42
        )
        
        # Use KNN for classification based on embeddings
        from sklearn.neighbors import KNeighborsClassifier
        self.model = KNeighborsClassifier(n_neighbors=5)
        self.model.fit(X_train_split, y_train_split)
        
        # Make predictions on validation set
        y_pred = self.model.predict(X_val)
        
        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_val, y_pred),
            'precision': precision_score(y_val, y_pred, average='weighted'),
            'recall': recall_score(y_val, y_pred, average='weighted'),
            'f1': f1_score(y_val, y_pred, average='weighted')
        }
        
        # Set trained flag
        self.is_trained = True
        
        return self.metrics
    
    def predict(self, X):
        """
        Predict severity for new vulnerabilities
        
        Args:
            X (list): List of text descriptions
        
        Returns:
            list: Predicted severity levels
        """
        if not self.is_trained:
            raise ValueError("Model has not been trained yet")
        
        # Convert to DataFrame if not already
        if isinstance(X, list):
            X = pd.DataFrame({'description': X})
        
        # Handle missing values
        X = X.fillna('')
        
        # Extract text descriptions
        if 'description' in X.columns:
            descriptions = X['description'].astype(str).tolist()
        elif 'title' in X.columns and 'description' in X.columns:
            descriptions = (X['title'] + ' ' + X['description']).astype(str).tolist()
        else:
            descriptions = X.iloc[:, 0].astype(str).tolist()
        
        # Generate embeddings
        X_embeddings = self._generate_embeddings(descriptions)
        
        # Make predictions
        predictions_encoded = self.model.predict(X_embeddings)
        
        # Decode predictions
        predictions = self.label_encoder.inverse_transform(predictions_encoded)
        
        return predictions
    
    def save_model(self, path='embedding_classifier.pkl'):
        """
        Save the trained model to disk
        
        Args:
            path (str): Path to save the model
        """
        if not self.is_trained:
            raise ValueError("Model has not been trained yet")
        
        model_data = {
            'word_vectors': self.word_vectors,
            'model': self.model,
            'label_encoder': self.label_encoder,
            'embedding_dim': self.embedding_dim,
            'metrics': self.metrics
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
    
    @classmethod
    def load_model(cls, path='embedding_classifier.pkl'):
        """
        Load a trained model from disk
        
        Args:
            path (str): Path to the saved model
        
        Returns:
            EmbeddingClassifier: Loaded classifier
        """
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        classifier = cls()
        classifier.word_vectors = model_data['word_vectors']
        classifier.model = model_data['model']
        classifier.label_encoder = model_data['label_encoder']
        classifier.embedding_dim = model_data['embedding_dim']
        classifier.metrics = model_data['metrics']
        classifier.is_trained = True
        
        return classifier

if __name__ == "__main__":
    # Example usage
    X_sample = [
        "Remote code execution vulnerability in web application",
        "Information disclosure in API endpoint",
        "Cross-site scripting vulnerability in form submission",
        "Buffer overflow in network service"
    ]
    y_sample = ["Critical", "Medium", "High", "Critical"]
    
    # Create and train classifier
    classifier = EmbeddingClassifier()
    metrics = classifier.train(X_sample, y_sample)
    
    print("Training metrics:")
    for metric, value in metrics.items():
        print(f"{metric}: {value:.4f}")
    
    # Test predictions
    X_test = [
        "SQL injection vulnerability in login form",
        "Missing access control in user profile",
        "Memory corruption in audio processing library"
    ]
    
    predictions = classifier.predict(X_test)
    print("\nPredictions:")
    for text, prediction in zip(X_test, predictions):
        print(f"Text: {text}")
        print(f"Prediction: {prediction}\n")
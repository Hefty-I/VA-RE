import os
import json
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import string
import nltk

# Download NLTK resources if not already downloaded
# Download resources unconditionally to ensure they're always available
# import nltk
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True, download_dir='./nltk_data')
    
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True, download_dir='./nltk_data')

# Download punkt package 
nltk.download('punkt', quiet=True, download_dir='./nltk_data')

# Create a simple word tokenizer that doesn't depend on NLTK's punkt_tab
import re
def simple_word_tokenize(text):
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

# Override NLTK's word_tokenize function
from nltk.tokenize import word_tokenize
nltk.tokenize.word_tokenize = simple_word_tokenize
# Set the global function too
word_tokenize = simple_word_tokenize
    
try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet', quiet=True, download_dir='./nltk_data')
    
try:
    nltk.data.find('corpora/omw-1.4')
except LookupError:
    nltk.download('omw-1.4', quiet=True, download_dir='./nltk_data')  # Open Multilingual WordNet

# Set the NLTK data path to include our local directory
nltk.data.path.append('./nltk_data')

class SBERTEmulator:
    """
    A class that emulates the functionality of Sentence-BERT (SBERT)
    for creating sentence embeddings when the actual SBERT library
    is not available.
    
    This implements a simplified version that combines TF-IDF with SVD
    and some preprocessing to create dense vector representations of text.
    """
    
    def __init__(self, embedding_dim=128):
        """
        Initialize the SBERT emulator
        
        Args:
            embedding_dim (int): Dimension of the embeddings to generate
        """
        self.embedding_dim = embedding_dim
        # Increase max_features to ensure we have enough features for SVD
        self.vectorizer = TfidfVectorizer(max_features=10000)
        # SVD will be initialized later with appropriate n_components
        self.svd = None
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.is_fitted = False
        self.security_term_weights = self._get_security_term_weights()
    
    def _get_security_term_weights(self):
        """
        Get weights for security-related terms to enhance embeddings
        
        Returns:
            dict: Dictionary mapping security terms to weight values
        """
        # Common security-related terms and their importance weights
        return {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8,
            'vulnerability': 1.3,
            'exploit': 1.4,
            'remote': 1.2,
            'execution': 1.3,
            'code': 1.2,
            'injection': 1.4,
            'sql': 1.3,
            'xss': 1.3,
            'overflow': 1.3,
            'buffer': 1.2,
            'authentication': 1.2,
            'authorization': 1.2,
            'bypass': 1.3,
            'privilege': 1.3,
            'escalation': 1.3,
            'disclosure': 1.2,
            'information': 1.0,
            'denial': 1.1,
            'service': 0.9,
            'dos': 1.1,
            'cve': 1.4,
            'attack': 1.3,
            'malicious': 1.2,
            'compromise': 1.2,
            'security': 1.1,
            'patch': 1.0
        }
    
    def _preprocess_text(self, text):
        """
        Preprocess text for embedding generation
        
        Args:
            text (str): Input text
        
        Returns:
            str: Preprocessed text
        """
        if not isinstance(text, str):
            return ""
            
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation
        text = ''.join([char for char in text if char not in string.punctuation])
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stopwords and apply lemmatization
        tokens = [self.lemmatizer.lemmatize(word) for word in tokens if word not in self.stop_words]
        
        # Apply security term weights
        weighted_tokens = []
        for token in tokens:
            weight = self.security_term_weights.get(token, 1.0)
            # Add the token multiple times based on weight
            weighted_count = int(weight * 1.5)
            weighted_tokens.extend([token] * weighted_count)
        
        return ' '.join(weighted_tokens)
    
    def fit(self, sentences):
        """
        Fit the model on a list of sentences
        
        Args:
            sentences (list): List of text sentences
        """
        # Preprocess the sentences
        preprocessed_sentences = [self._preprocess_text(sent) for sent in sentences]
        
        # Add more text samples if we have too few
        if len(preprocessed_sentences) < 5:
            # Add security-related sample texts
            additional_samples = [
                "remote code execution vulnerability in server",
                "sql injection attack in database",
                "buffer overflow vulnerability in memory allocation",
                "cross site scripting xss vulnerability in web form",
                "denial of service attack on server",
                "authentication bypass using privilege escalation",
                "information disclosure vulnerability leaking sensitive data"
            ]
            preprocessed_sentences.extend(additional_samples)
        
        # Ensure all preprocessed sentences have content
        preprocessed_sentences = [text if text else "empty text" for text in preprocessed_sentences]
        
        # Fit the TF-IDF vectorizer
        tfidf_matrix = self.vectorizer.fit_transform(preprocessed_sentences)
        
        # Get the number of features
        n_features = tfidf_matrix.shape[1]
        
        # Determine appropriate SVD components (must be <= n_features)
        n_components = min(self.embedding_dim, n_features - 1)
        n_components = max(n_components, 1)  # Ensure at least 1 component
        
        # Initialize SVD with appropriate component count
        self.svd = TruncatedSVD(n_components=n_components, random_state=42)
        
        # Fit the SVD
        self.svd.fit(tfidf_matrix)
        
        self.is_fitted = True
    
    def encode(self, sentences, batch_size=32):
        """
        Encode sentences to embeddings
        
        Args:
            sentences (list or str): Sentence or list of sentences to encode
            batch_size (int): Batch size for processing
        
        Returns:
            numpy.ndarray: Array of embeddings
        """
        # Handle single sentence
        if isinstance(sentences, str):
            sentences = [sentences]
        
        # Preprocess the sentences
        preprocessed_sentences = [self._preprocess_text(sent) for sent in sentences]
        
        # Check if the model is fitted
        if not self.is_fitted:
            self.fit(preprocessed_sentences)
        
        # Transform with TF-IDF
        tfidf_matrix = self.vectorizer.transform(preprocessed_sentences)
        
        # Transform with SVD
        embeddings = self.svd.transform(tfidf_matrix)
        
        # Normalize the embeddings
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0] = 1  # Avoid division by zero
        embeddings = embeddings / norms
        
        return embeddings
    
    def save(self, path):
        """
        Save the model to disk
        
        Args:
            path (str): Path to save the model
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save the model
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'svd': self.svd,
                'embedding_dim': self.embedding_dim,
                'is_fitted': self.is_fitted,
                'security_term_weights': self.security_term_weights
            }, f)
    
    @classmethod
    def load(cls, path):
        """
        Load the model from disk
        
        Args:
            path (str): Path to the saved model
        
        Returns:
            SBERTEmulator: Loaded model
        """
        with open(path, 'rb') as f:
            data = pickle.load(f)
        
        model = cls(embedding_dim=data['embedding_dim'])
        model.vectorizer = data['vectorizer']
        model.svd = data['svd']
        model.is_fitted = data['is_fitted']
        model.security_term_weights = data['security_term_weights']
        
        return model

def get_sentence_embeddings(sentences, model_path=None):
    """
    Get embeddings for a list of sentences
    
    Args:
        sentences (list): List of sentences to embed
        model_path (str): Path to a saved model to load
    
    Returns:
        numpy.ndarray: Array of embeddings
    """
    # Default model path
    if model_path is None:
        model_path = 'data/models/sbert_emulator.pkl'
    
    # Try to load existing model
    if os.path.exists(model_path):
        try:
            model = SBERTEmulator.load(model_path)
        except Exception as e:
            print(f"Error loading model: {e}")
            model = SBERTEmulator()
    else:
        # Create new model
        model = SBERTEmulator()
    
    # Encode sentences
    embeddings = model.encode(sentences)
    
    # Save model if it wasn't loaded
    if not os.path.exists(model_path):
        try:
            model.save(model_path)
        except Exception as e:
            print(f"Error saving model: {e}")
    
    return embeddings

def semantic_similarity(text1, text2, model_path=None):
    """
    Calculate semantic similarity between two texts
    
    Args:
        text1 (str): First text
        text2 (str): Second text
        model_path (str): Path to a saved model to load
    
    Returns:
        float: Similarity score between 0 and 1
    """
    # Get embeddings
    embeddings = get_sentence_embeddings([text1, text2], model_path)
    
    # Calculate cosine similarity
    similarity = np.dot(embeddings[0], embeddings[1])
    
    # Handle similarity > 1 due to numerical errors
    if similarity > 1:
        similarity = 1.0
    
    return similarity

def find_most_similar(query, candidates, model_path=None):
    """
    Find the most similar text to a query from a list of candidates
    
    Args:
        query (str): Query text
        candidates (list): List of candidate texts
        model_path (str): Path to a saved model to load
    
    Returns:
        tuple: (most_similar_text, similarity_score)
    """
    # Get embeddings
    all_texts = [query] + candidates
    embeddings = get_sentence_embeddings(all_texts, model_path)
    
    query_embedding = embeddings[0]
    candidate_embeddings = embeddings[1:]
    
    # Calculate similarities
    similarities = [np.dot(query_embedding, candidate_embedding) 
                   for candidate_embedding in candidate_embeddings]
    
    # Find most similar
    max_index = np.argmax(similarities)
    max_similarity = similarities[max_index]
    
    return candidates[max_index], max_similarity

if __name__ == "__main__":
    # Example usage
    sentences = [
        "Remote code execution vulnerability in the web server",
        "SQL injection vulnerability in the login form",
        "Cross-site scripting vulnerability in the comment system",
        "Buffer overflow vulnerability in the network driver",
        "Information disclosure vulnerability in the API"
    ]
    
    # Create embeddings
    embeddings = get_sentence_embeddings(sentences)
    print(f"Generated {len(embeddings)} embeddings of dimension {embeddings[0].shape[0]}")
    
    # Test similarity
    text1 = "Remote code execution flaw allows attackers to run malicious code"
    text2 = "SQL injection in the authentication module permits database access"
    similarity = semantic_similarity(text1, text2)
    print(f"Similarity between the texts: {similarity:.4f}")
    
    # Test finding most similar
    query = "Command injection allows attackers to execute arbitrary system commands"
    most_similar, score = find_most_similar(query, sentences)
    print(f"Most similar to '{query}':")
    print(f"  -> '{most_similar}' (similarity: {score:.4f})")
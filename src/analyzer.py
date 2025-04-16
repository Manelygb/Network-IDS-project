import os
import pickle
import numpy as np
import config
from typing import Dict, Any, Tuple

class NetworkFlowClassifier:
    """Classifier for network flows."""
    
    def __init__(self, model_path: str = config.DEFAULT_MODEL_PATH):
        """Initialize the classifier with a pre-trained model."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        # Load the model
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"Model loaded from {model_path}")
        except Exception as e:
            raise Exception(f"Failed to load model: {e}")
            
        # Features expected by the model
        self.features = [
            'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 
            'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes'
        ]
    
    def extract_features(self, line: str) -> Dict[str, Any]:
        """Extract features from a log line."""
        fields = line.strip().split('\t')
        # Create a dictionary mapping column names to field values
        data = {col: fields[i] if i < len(fields) else "" for i, col in enumerate(config.COLUMNS)}
        
        # Convert features to appropriate types
        flow_data = {}
        for feature in self.features:
            if feature in data:
                # Handle missing or '-' values
                value = data[feature]
                if value == '-' or value == '':
                    value = 0
                
                # Convert numeric features
                try:
                    if feature in ['duration']:
                        flow_data[feature] = float(value)
                    else:
                        flow_data[feature] = int(value)
                except ValueError:
                    flow_data[feature] = 0
        
        # Add non-feature data for reference
        flow_data['timestamp'] = fields[0] if len(fields) > 0 else ""
        flow_data['uid'] = fields[1] if len(fields) > 1 else ""
        
        return flow_data
    
    def predict(self, line: str) -> Tuple[str, Dict[str, Any]]:
        """Predict the attack type from a log line."""
        # Extract features
        flow_data = self.extract_features(line)
        
        # Prepare feature vector for prediction
        X = np.array([[flow_data.get(feature, 0) for feature in self.features]])
        
        # Make prediction
        try:
            y_pred = self.model.predict(X)
            # Assuming the model returns class labels directly
            attack_type = y_pred[0]
            
            # Convert numeric label to string if needed
            if isinstance(attack_type, (int, np.integer)):
                attack_type = config.ATTACK_TYPES[attack_type] if attack_type < len(config.ATTACK_TYPES) else str(attack_type)
            
            return attack_type, flow_data
        except Exception as e:
            print(f"Error during prediction: {e}")
            return "Error", flow_data
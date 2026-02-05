import pickle
import numpy as np
from typing import Tuple, Optional, Dict, Any
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, f1_score
import warnings
warnings.filterwarnings('ignore')

class EnhancedScamDetector:
    def __init__(self, use_pretrained: bool = True):
        self.model = None
        self.vectorizer = None
        self.scaler = StandardScaler()
        self.feature_names = []
        
        if use_pretrained:
            self.load_model()
    
    def build_model_pipeline(self) -> Pipeline:
        """Build an ensemble model pipeline"""
        # Text feature extractors
        text_features = FeatureUnion([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                stop_words='english',
                min_df=2
            )),
            ('count', CountVectorizer(
                max_features=3000,
                ngram_range=(1, 2),
                binary=True
            ))
        ])
        
        # Ensemble of classifiers
        estimators = [
            ('rf', RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                random_state=42,
                class_weight='balanced'
            )),
            ('gb', GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )),
            ('lr', LogisticRegression(
                C=1.0,
                class_weight='balanced',
                max_iter=1000,
                random_state=42
            ))
        ]
        
        # Create voting classifier
        voting_clf = VotingClassifier(
            estimators=estimators,
            voting='soft',
            weights=[2, 1.5, 1]
        )
        
        # Build pipeline
        pipeline = Pipeline([
            ('text_features', text_features),
            ('scaler', StandardScaler(with_mean=False)),
            ('classifier', voting_clf)
        ])
        
        return pipeline
    
    def train(self, X_train: list, y_train: np.ndarray, 
              X_val: Optional[list] = None, y_val: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Train the model with hyperparameter tuning"""
        
        # Create and train pipeline
        self.model = self.build_model_pipeline()
        
        # Parameter grid for tuning
        param_grid = {
            'classifier__rf__n_estimators': [100, 200],
            'classifier__rf__max_depth': [10, 15, None],
            'classifier__gb__learning_rate': [0.05, 0.1],
            'classifier__gb__n_estimators': [50, 100],
            'text_features__tfidf__max_features': [3000, 5000],
            'text_features__count__max_features': [2000, 3000]
        }
        
        # Perform grid search
        grid_search = GridSearchCV(
            self.model,
            param_grid,
            cv=3,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1
        )
        
        print("Training model with grid search...")
        grid_search.fit(X_train, y_train)
        
        # Set best model
        self.model = grid_search.best_estimator_
        
        # Get feature names if available
        if hasattr(self.model.named_steps['text_features'], 'get_feature_names_out'):
            self.feature_names = self.model.named_steps['text_features'].get_feature_names_out()
        
        # Evaluate
        train_pred = self.model.predict(X_train)
        train_acc = accuracy_score(y_train, train_pred)
        train_f1 = f1_score(y_train, train_pred)
        
        results = {
            'best_params': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'train_accuracy': train_acc,
            'train_f1': train_f1
        }
        
        if X_val is not None and y_val is not None:
            val_pred = self.model.predict(X_val)
            val_acc = accuracy_score(y_val, val_pred)
            val_f1 = f1_score(y_val, val_pred)
            results['val_accuracy'] = val_acc
            results['val_f1'] = val_f1
            
            print("Validation Report:")
            print(classification_report(y_val, val_pred))
        
        return results
    
    def predict(self, text: str, include_features: bool = False) -> Tuple[bool, float, Dict[str, Any]]:
        """Predict scam probability"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        # Make prediction
        proba = self.model.predict_proba([text])[0]
        scam_prob = proba[1] if len(proba) > 1 else proba[0]
        is_scam = scam_prob > 0.7
        
        result = {
            'probability': float(scam_prob),
            'prediction': int(is_scam),
            'proba_distribution': [float(p) for p in proba]
        }
        
        if include_features and hasattr(self.model, 'named_steps'):
            # Extract important features
            try:
                if hasattr(self.model.named_steps['classifier'], 'feature_importances_'):
                    importances = self.model.named_steps['classifier'].feature_importances_
                    if len(self.feature_names) == len(importances):
                        top_indices = np.argsort(importances)[-10:][::-1]
                        top_features = [
                            (self.feature_names[i], float(importances[i]))
                            for i in top_indices
                        ]
                        result['top_features'] = top_features
            except:
                pass
        
        return is_scam, scam_prob, result
    
    def save_model(self, model_path: str = 'models/scam_classifier.pkl',
                   vectorizer_path: str = 'models/vectorizer.pkl'):
        """Save trained model and vectorizer"""
        import os
        os.makedirs('models', exist_ok=True)
        
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Save vectorizer separately if it exists
        if hasattr(self.model, 'named_steps') and 'text_features' in self.model.named_steps:
            with open(vectorizer_path, 'wb') as f:
                pickle.dump(self.model.named_steps['text_features'], f)
    
    def load_model(self, model_path: str = 'models/scam_classifier.pkl',
                   vectorizer_path: str = 'models/vectorizer.pkl'):
        """Load trained model and vectorizer"""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            if os.path.exists(vectorizer_path):
                with open(vectorizer_path, 'rb') as f:
                    vectorizer = pickle.load(f)
                    if hasattr(self.model, 'named_steps'):
                        self.model.named_steps['text_features'] = vectorizer
            
            print("Model loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
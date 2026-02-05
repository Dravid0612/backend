import pandas as pd
import numpy as np
import re
import json
from typing import List, Dict, Tuple
from sklearn.model_selection import train_test_split
from collections import Counter
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

nltk.download('punkt')
nltk.download('stopwords')

class FraudDataProcessor:
    def __init__(self):
        self.scam_patterns = self._load_scam_patterns()
        self.stop_words = set(stopwords.words('english'))
        
    def _load_scam_patterns(self) -> Dict[str, List[str]]:
        """Load known scam patterns and keywords"""
        return {
            "urgent_action": [
                "immediate action required", "urgent", "act now", "limited time",
                "your account will be blocked", "suspended", "terminated"
            ],
            "verification": [
                "verify your account", "confirm your identity", "update your details",
                "security check", "authentication required"
            ],
            "financial_threats": [
                "unauthorized transaction", "fraud detected", "money laundering",
                "account compromised", "security breach"
            ],
            "fake_rewards": [
                "you have won", "prize money", "reward", "lottery", "bonus",
                "free gift", "special offer"
            ],
            "phishing": [
                "click this link", "visit this website", "download this attachment",
                "login here", "secure your account"
            ],
            "impersonation": [
                "bank official", "government agency", "tech support",
                "customer service", "security team"
            ]
        }
    
    def load_ba_fraud_dataset(self, filepath: str) -> pd.DataFrame:
        """Load and preprocess Bank Account Fraud Dataset"""
        try:
            # Load the NeurIPS 2022 dataset
            df = pd.read_csv(filepath)
            
            # Preprocessing steps
            df = self._clean_dataset(df)
            df = self._extract_features(df)
            
            return df
            
        except Exception as e:
            print(f"Error loading dataset: {e}")
            # Create synthetic dataset if real one isn't available
            return self._create_synthetic_dataset()
    
    def _clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and standardize the dataset"""
        # Remove duplicates
        df = df.drop_duplicates()
        
        # Handle missing values
        df = df.fillna('')
        
        # Standardize text
        if 'text' in df.columns:
            df['text'] = df['text'].apply(lambda x: x.lower().strip())
        
        return df
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract linguistic and structural features"""
        if 'text' not in df.columns:
            return df
        
        # Length features
        df['text_length'] = df['text'].apply(len)
        df['word_count'] = df['text'].apply(lambda x: len(x.split()))
        
        # Scam pattern matching
        for pattern_type, patterns in self.scam_patterns.items():
            df[f'contains_{pattern_type}'] = df['text'].apply(
                lambda x: int(any(pattern in x.lower() for pattern in patterns))
            )
        
        # URL detection
        url_pattern = r'https?://\S+|www\.\S+'
        df['contains_url'] = df['text'].apply(
            lambda x: 1 if re.search(url_pattern, x) else 0
        )
        
        # Phone number detection
        phone_pattern = r'\b\d{10}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        df['contains_phone'] = df['text'].apply(
            lambda x: 1 if re.search(phone_pattern, x) else 0
        )
        
        # Special characters
        df['special_char_ratio'] = df['text'].apply(
            lambda x: len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', x)) / max(len(x), 1)
        )
        
        # Uppercase ratio (urgency indicator)
        df['uppercase_ratio'] = df['text'].apply(
            lambda x: sum(1 for c in x if c.isupper()) / max(len(x), 1)
        )
        
        return df
    
    def _create_synthetic_dataset(self) -> pd.DataFrame:
        """Create synthetic training data"""
        scam_messages = [
            "Your bank account will be blocked today. Verify immediately: http://fake-bank.com",
            "You've won $5000! Click here to claim: bit.ly/fakelink",
            "Urgent: Your account has been compromised. Call 123-456-7890",
            "Apple support: Your iCloud was hacked. Login to secure: apple-fake.com",
            "Government tax refund: You're eligible for $1200. Submit details now.",
            "PayPal security alert: Unusual login detected. Verify account.",
            "Bank of America: Suspicious transaction of $899. Reply STOP to block.",
            "FedEx: Package delivery failed. Update address: fedex-fake-link.com",
            "Netflix: Your account is on hold. Update payment: netflix-secure.com",
            "COVID relief fund: You qualify for $1000 grant. Apply now."
        ]
        
        legit_messages = [
            "Hi, just checking if you received my email.",
            "Meeting tomorrow at 3 PM in conference room B.",
            "Can you send me the report by end of day?",
            "Your Amazon order #12345 has shipped.",
            "Don't forget about the team lunch tomorrow.",
            "The quarterly results look promising.",
            "Please review the attached document.",
            "Let's schedule a call for next week.",
            "Thanks for your help with the project.",
            "Reminder: Team building activity this Friday."
        ]
        
        data = []
        for msg in scam_messages:
            data.append({'text': msg, 'label': 1, 'scam_type': 'phishing'})
        
        for msg in legit_messages:
            data.append({'text': msg, 'label': 0, 'scam_type': 'legitimate'})
        
        return pd.DataFrame(data)
    
    def prepare_training_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels for training"""
        # Select feature columns
        feature_columns = [
            'text_length', 'word_count', 'contains_url', 'contains_phone',
            'special_char_ratio', 'uppercase_ratio'
        ]
        
        # Add pattern columns
        for pattern_type in self.scam_patterns.keys():
            col_name = f'contains_{pattern_type}'
            if col_name in df.columns:
                feature_columns.append(col_name)
        
        # Ensure all columns exist
        available_cols = [col for col in feature_columns if col in df.columns]
        
        X = df[available_cols].values
        y = df['label'].values if 'label' in df.columns else np.zeros(len(df))
        
        return X, y
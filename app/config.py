import os
from typing import Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # API Configuration
    API_KEY: str = os.getenv("API_KEY", "default-secret-key")
    API_NAME: str = "Agentic Honeypot API"
    VERSION: str = "1.0.0"
    
    # Model Configuration
    MODEL_PATH: str = "models/scam_classifier.pkl"
    VECTORIZER_PATH: str = "models/vectorizer.pkl"
    MIN_SCAM_CONFIDENCE: float = 0.7
    
    # Agent Configuration
    AGENT_PERSONAS: dict = {
        "default": "You are a concerned but cautious individual. You're not too tech-savvy but want to protect your finances.",
        "elderly": "You are an elderly person who is not very familiar with technology. You move slowly and ask many questions.",
        "young_adult": "You are a young adult who uses digital banking regularly. You're somewhat skeptical but can be convinced.",
        "business": "You are a small business owner concerned about payment disruptions."
    }
    
    # Redis for session management
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Rate limiting
    RATE_LIMIT: int = 100  # requests per minute
    
    # Callback Configuration
    EVALUATION_ENDPOINT: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    CALLBACK_TIMEOUT: int = 5  # seconds
    MIN_MESSAGES_FOR_CALLBACK: int = 3  # Minimum messages before sending callback
    CALLBACK_ENABLED: bool = True  # Enable/disable for testing
    CALLBACK_MIN_CONFIDENCE: float = 0.8  # Minimum confidence to send callback
    
    class Config:
        env_file = ".env"

settings = Settings()
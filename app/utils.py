import hashlib
import time
from typing import Dict, Any
import logging
from datetime import datetime
from functools import wraps

def setup_logging():
    """Setup application logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def validate_api_key(api_key: str, expected_key: str) -> bool:
    """Validate API key"""
    if not api_key:
        return False
    return api_key == expected_key

class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
    
    def check_limit(self, api_key: str) -> bool:
        """Check if request is within rate limit"""
        current_time = time.time()
        
        if api_key not in self.requests:
            self.requests[api_key] = []
        
        # Remove old requests
        self.requests[api_key] = [
            req_time for req_time in self.requests[api_key]
            if current_time - req_time < self.window_seconds
        ]
        
        # Check limit
        if len(self.requests[api_key]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[api_key].append(current_time)
        return True

# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

def generate_session_id() -> str:
    """Generate unique session ID"""
    return hashlib.sha256(
        f"{datetime.now().isoformat()}{time.time()}".encode()
    ).hexdigest()[:20]

def sanitize_text(text: str) -> str:
    """Sanitize input text"""
    if not text:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = text.replace('\x00', '').replace('\r', '').replace('\n', ' ')
    
    # Limit length
    max_length = 1000
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    
    return sanitized.strip()

def format_timestamp(timestamp: int) -> str:
    """Format epoch timestamp to readable date"""
    try:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(timestamp)
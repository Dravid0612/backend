import requests
import json
from typing import Dict, Optional, List, Any
import logging
from datetime import datetime
from .config import settings

logger = logging.getLogger(__name__)

class EvaluationCallback:
    def __init__(self, endpoint: str = None, timeout: int = None):
        self.endpoint = endpoint or settings.EVALUATION_ENDPOINT
        self.timeout = timeout or settings.CALLBACK_TIMEOUT
        
    def send_final_result(self, 
                         session_id: str,
                         scam_detected: bool,
                         total_messages_exchanged: int,
                         extracted_intelligence: Dict,
                         agent_notes: str) -> Dict[str, Any]:
        """
        Send final results to evaluation endpoint
        Returns dictionary with status and details
        """
        if not settings.CALLBACK_ENABLED:
            return {
                "status": "disabled",
                "message": "Callback is disabled in configuration"
            }
        
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages_exchanged,
            "extractedIntelligence": extracted_intelligence,
            "agentNotes": agent_notes
        }
        
        logger.info(f"Sending callback for session {session_id} with payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                timeout=self.timeout,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"{settings.API_NAME}/{settings.VERSION}"
                }
            )
            
            result = {
                "status_code": response.status_code,
                "response_text": response.text,
                "success": response.status_code == 200,
                "timestamp": datetime.now().isoformat()
            }
            
            if response.status_code == 200:
                logger.info(f"Callback successful for session {session_id}")
                try:
                    result["response_data"] = response.json()
                except:
                    result["response_data"] = response.text
            else:
                logger.error(f"Callback failed with status {response.status_code}: {response.text}")
                
            return result
            
        except requests.exceptions.Timeout:
            error_msg = f"Callback timeout for session {session_id}"
            logger.error(error_msg)
            return {
                "status": "timeout",
                "message": error_msg,
                "success": False,
                "timestamp": datetime.now().isoformat()
            }
            
        except requests.exceptions.ConnectionError:
            error_msg = f"Connection error for callback endpoint"
            logger.error(error_msg)
            return {
                "status": "connection_error",
                "message": error_msg,
                "success": False,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error sending callback: {str(e)}"
            logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "success": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def prepare_intelligence_payload(self, intelligence_data: Dict) -> Dict:
        """
        Format intelligence data according to required schema
        """
        return {
            "bankAccounts": intelligence_data.get("bank_names", []),
            "upids": intelligence_data.get("upi_ids", []),
            "phishingLinks": intelligence_data.get("urls", []),
            "phoneNumbers": intelligence_data.get("phone_numbers", []),
            "suspiciousKeywords": intelligence_data.get("suspicious_keywords", [])
        }
    
    def validate_payload(self, payload: Dict) -> bool:
        """
        Validate callback payload format
        """
        required_fields = [
            "sessionId", 
            "scamDetected", 
            "totalMessagesExchanged",
            "extractedIntelligence",
            "agentNotes"
        ]
        
        for field in required_fields:
            if field not in payload:
                logger.error(f"Missing required field in callback payload: {field}")
                return False
        
        # Validate extractedIntelligence structure
        intel_fields = [
            "bankAccounts", 
            "upids", 
            "phishingLinks", 
            "phoneNumbers", 
            "suspiciousKeywords"
        ]
        
        for field in intel_fields:
            if field not in payload["extractedIntelligence"]:
                logger.warning(f"Missing intelligence field: {field}")
                # Add empty list if missing
                payload["extractedIntelligence"][field] = []
        
        return True
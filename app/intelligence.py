import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import phonenumbers
from email_validator import validate_email, EmailNotValidError

class IntelligenceExtractor:
    def __init__(self):
        self.extracted_data = {
            "phone_numbers": set(),
            "urls": set(),
            "email_addresses": set(),
            "bank_names": set(),
            "upi_ids": set(),
            "scam_tactics": set(),
            "requested_actions": set(),
            "threats": set(),
            "suspicious_keywords": set(),
            "timestamps": []
        }
        
        # Bank name patterns
        self.bank_patterns = [
            r'(?:bank\s+of\s+(?:america|baroda|india|maharashtra))',
            r'(?:state\s+bank\s+of\s+(?:india|sikkim|patiala))',
            r'(?:icici\s+bank|hdfc\s+bank|axis\s+bank|kotak\s+bank)',
            r'(?:punjab\s+national\s+bank|canara\s+bank|union\s+bank)',
            r'(?:standard\s+chartered|citibank|hsbc)',
            r'(?:yes\s+bank|indusind\s+bank|rbl\s+bank)',
            r'(?:sbi\s+bank|pnb\s+bank|bob\s+bank)',
            r'(?:idbi\s+bank|boi\s+bank|central\s+bank)'
        ]
        
        # UPI ID patterns
        self.upi_patterns = [
            r'\b[A-Za-z0-9._%+-]+@(?:okaxis|okhdfcbank|oksbi|okicici|okkotak|okbob)\b',
            r'\b\d{10,12}@(?:apl|axis|hdfc|sbi|icici|kotak|ybl|paytm|oksbi)\b',
            r'\b[A-Za-z0-9._%+-]+@(?:ybl|axl|oksbi|upi)\b',
            r'\b(?:[\w.]+)@(?:ok\w+|axl|ybl|paytm)\b',
            r'upi:\/\/pay\?[^\\s]+',
            r'\bupi_[A-Za-z0-9]+\b'
        ]
        
        # Suspicious keywords
        self.suspicious_keywords_list = [
            'urgent', 'immediate', 'asap', 'now', 'quick', 'hurry',
            'verify', 'confirm', 'authenticate', 'validate',
            'blocked', 'suspended', 'locked', 'terminated', 'closed',
            'won', 'prize', 'reward', 'bonus', 'free', 'cash', 'money',
            'click', 'link', 'website', 'url', 'download',
            'password', 'otp', 'pin', 'security', 'hacked', 'compromised',
            'share', 'send', 'provide', 'give', 'submit',
            'unauthorized', 'fraud', 'scam', 'illegal', 'warning',
            'limited time', 'last chance', 'final notice',
            'government', 'police', 'court', 'legal', 'authority'
        ]
        
        # Scam tactic patterns
        self.tactic_patterns = {
            "urgency": [r'urgent', r'immediate', r'asap', r'right away', r'within \d+ hours'],
            "fear": [r'blocked', r'suspended', r'terminated', r'closed', r'frozen', r'hacked'],
            "greed": [r'won', r'prize', r'reward', r'bonus', r'free', r'cash', r'money'],
            "authority": [r'official', r'government', r'police', r'court', r'legal', r'authority'],
            "help": [r'help', r'assistance', r'support', r'guidance', r'advice']
        }
    
    def extract(self, message: str, conversation_history: List[Dict] = None) -> Dict:
        """Extract intelligence from message and conversation"""
        
        # Extract from current message
        self._extract_from_text(message)
        
        # Extract from conversation history if available
        if conversation_history:
            for msg in conversation_history:
                self._extract_from_text(msg.get('text', ''))
        
        # Analyze conversation patterns
        if conversation_history and len(conversation_history) > 1:
            self._analyze_conversation_patterns(conversation_history)
        
        # Convert sets to lists for JSON serialization
        result = {}
        for key, value in self.extracted_data.items():
            if isinstance(value, set):
                result[key] = list(value)
            else:
                result[key] = value
        
        # Add extraction metadata
        result.update({
            "extraction_method": "pattern_matching",
            "total_extractions": sum(len(v) for v in result.values() if isinstance(v, list)),
            "extraction_timestamp": self.extracted_data.get("timestamps", [])[-1] if self.extracted_data.get("timestamps") else None
        })
        
        return result
    
    def _extract_from_text(self, text: str):
        """Extract intelligence from a single text"""
        
        # Phone numbers
        phone_numbers = self._extract_phone_numbers(text)
        self.extracted_data["phone_numbers"].update(phone_numbers)
        
        # URLs
        urls = self._extract_urls(text)
        self.extracted_data["urls"].update(urls)
        
        # Email addresses
        emails = self._extract_emails(text)
        self.extracted_data["email_addresses"].update(emails)
        
        # Bank names
        banks = self._extract_bank_names(text)
        self.extracted_data["bank_names"].update(banks)
        
        # UPI IDs
        upi_ids = self._extract_upi_ids(text)
        self.extracted_data["upi_ids"].update(upi_ids)
        
        # Scam tactics
        tactics = self._extract_scam_tactics(text)
        self.extracted_data["scam_tactics"].update(tactics)
        
        # Requested actions
        actions = self._extract_requested_actions(text)
        self.extracted_data["requested_actions"].update(actions)
        
        # Threats
        threats = self._extract_threats(text)
        self.extracted_data["threats"].update(threats)
        
        # Suspicious keywords
        keywords = self._extract_suspicious_keywords(text)
        self.extracted_data["suspicious_keywords"].update(keywords)
        
        # Add timestamp
        self.extracted_data["timestamps"].append(len(text))
    
    def _extract_phone_numbers(self, text: str) -> Set[str]:
        """Extract phone numbers from text"""
        numbers = set()
        
        # International format
        try:
            for match in phonenumbers.PhoneNumberMatcher(text, "IN"):
                numbers.add(phonenumbers.format_number(match.number, 
                                                      phonenumbers.PhoneNumberFormat.E164))
        except:
            pass
        
        # Indian mobile numbers
        indian_mobile_pattern = r'\b[6789]\d{9}\b'
        for match in re.finditer(indian_mobile_pattern, text):
            numbers.add(match.group())
        
        # Landline patterns
        landline_pattern = r'\b\d{2,4}[-.]?\d{6,8}\b'
        for match in re.finditer(landline_pattern, text):
            numbers.add(match.group())
        
        return numbers
    
    def _extract_urls(self, text: str) -> Set[str]:
        """Extract URLs from text"""
        urls = set()
        
        # Common URL patterns
        url_patterns = [
            r'https?://\S+',
            r'www\.\S+',
            r'\S+\.(?:com|in|org|net|co|xyz|info|biz|online)\S*',
            r'bit\.ly/\S+|tinyurl\.com/\S+|goo\.gl/\S+|t\.co/\S+',
            r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'
        ]
        
        for pattern in url_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                url = match.group()
                # Clean up URL
                url = url.split(' ')[0].split('\n')[0].rstrip('.,;!?')
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
                urls.add(url)
        
        return urls
    
    def _extract_emails(self, text: str) -> Set[str]:
        """Extract email addresses from text"""
        emails = set()
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for match in re.finditer(email_pattern, text, re.IGNORECASE):
            email = match.group()
            try:
                # Validate email
                validate_email(email)
                emails.add(email.lower())
            except EmailNotValidError:
                continue
        
        return emails
    
    def _extract_bank_names(self, text: str) -> Set[str]:
        """Extract bank names from text"""
        banks = set()
        
        for pattern in self.bank_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                bank_name = match.group()
                banks.add(bank_name.title())
        
        return banks
    
    def _extract_upi_ids(self, text: str) -> Set[str]:
        """Extract UPI IDs from text"""
        upi_ids = set()
        
        for pattern in self.upi_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                upi_id = match.group()
                # Clean up UPI ID
                upi_id = upi_id.strip()
                upi_ids.add(upi_id)
        
        return upi_ids
    
    def _extract_scam_tactics(self, text: str) -> Set[str]:
        """Extract scam tactics from text"""
        tactics = set()
        
        for tactic_type, patterns in self.tactic_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    tactics.add(tactic_type)
                    break
        
        return tactics
    
    def _extract_requested_actions(self, text: str) -> Set[str]:
        """Extract requested actions from text"""
        actions = set()
        
        action_patterns = {
            "share_info": [r'share\s+(?:your\s+)?(?:details|information|data|upi|account|id)',
                          r'provide\s+(?:your\s+)?(?:details|information)',
                          r'send\s+(?:your\s+)?(?:details|info|particulars)',
                          r'give\s+(?:your\s+)?(?:details|info)'],
            "click_link": [r'click\s+(?:the\s+)?link', r'visit\s+(?:the\s+)?website',
                          r'go\s+to\s+(?:the\s+)?link', r'open\s+(?:the\s+)?url',
                          r'follow\s+(?:the\s+)?link'],
            "call_number": [r'call\s+(?:us|me|this\s+number)', r'ring\s+(?:us|me)',
                           r'dial\s+(?:\d+|this\s+number)', r'contact\s+(?:us|me)'],
            "pay_money": [r'pay\s+(?:rs\.?|₹|fee|tax|charge|amount)', r'send\s+money',
                          r'transfer\s+(?:funds|money|amount)', r'deposit',
                          r'pay\s+via\s+(?:upi|bank|card)'],
            "download": [r'download\s+(?:the\s+)?(?:file|app|software|attachment)',
                        r'install\s+(?:the\s+)?(?:app|software)',
                        r'save\s+(?:the\s+)?(?:file|attachment)']
        }
        
        for action, patterns in action_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    actions.add(action)
                    break
        
        return actions
    
    def _extract_threats(self, text: str) -> Set[str]:
        """Extract threats from text"""
        threats = set()
        
        threat_patterns = [
            r'account\s+will\s+be\s+(?:blocked|suspended|closed|terminated|frozen)',
            r'legal\s+action', r'police\s+complaint', r'court\s+case', r'fir\s+filed',
            r'fined', r'penalty', r'punishment', r'jail', r'arrest',
            r'lose\s+(?:access|money|account|service|data)',
            r'permanent\s+(?:ban|block|suspension|closure)',
            r'severe\s+(?:consequences|action|penalty)'
        ]
        
        for pattern in threat_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            threats.update(matches)
        
        return threats
    
    def _extract_suspicious_keywords(self, text: str) -> Set[str]:
        """Extract suspicious keywords from text"""
        keywords = set()
        text_lower = text.lower()
        
        for keyword in self.suspicious_keywords_list:
            if keyword in text_lower:
                keywords.add(keyword)
        
        return keywords
    
    def _analyze_conversation_patterns(self, conversation_history: List[Dict]):
        """Analyze patterns across conversation"""
        if len(conversation_history) < 2:
            return
        
        # Check for escalation
        urgency_words = ['urgent', 'immediate', 'now', 'quick', 'asap', 'hurry']
        urgency_counts = []
        
        for msg in conversation_history:
            text = msg.get('text', '').lower()
            count = sum(1 for word in urgency_words if word in text)
            urgency_counts.append(count)
        
        # If urgency is increasing
        if len(urgency_counts) >= 3 and urgency_counts[-1] > urgency_counts[0]:
            self.extracted_data["scam_tactics"].add("escalation_of_urgency")
        
        # Check for repeated information requests
        request_words = ['share', 'send', 'provide', 'give', 'tell', 'submit']
        request_count = 0
        
        for msg in conversation_history:
            text = msg.get('text', '').lower()
            if any(word in text for word in request_words):
                request_count += 1
        
        if request_count >= 3:
            self.extracted_data["scam_tactics"].add("repeated_information_requests")
        
        # Check for pressure tactics
        pressure_words = ['now', 'immediately', 'right away', 'last chance']
        pressure_count = 0
        for msg in conversation_history:
            text = msg.get('text', '').lower()
            if any(word in text for word in pressure_words):
                pressure_count += 1
        
        if pressure_count >= 2:
            self.extracted_data["scam_tactics"].add("pressure_tactics")
    
    def get_callback_data(self) -> Dict:
        """Get data formatted for callback"""
        return {
            "bank_names": list(self.extracted_data["bank_names"]),
            "upi_ids": list(self.extracted_data["upi_ids"]),
            "urls": list(self.extracted_data["urls"]),
            "phone_numbers": list(self.extracted_data["phone_numbers"]),
            "suspicious_keywords": list(self.extracted_data["suspicious_keywords"])
        }
    
    def reset(self):
        """Reset extracted data"""
        for key in self.extracted_data:
            if isinstance(self.extracted_data[key], set):
                self.extracted_data[key] = set()
            elif key == "timestamps":
                self.extracted_data[key] = []
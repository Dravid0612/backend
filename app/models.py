from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class SenderType(str, Enum):
    SCAMMER = "scammer"
    USER = "user"

class ChannelType(str, Enum):
    SMS = "SMS"
    WHATSAPP = "WhatsApp"
    EMAIL = "Email"
    CHAT = "Chat"

class Message(BaseModel):
    sender: SenderType
    text: str
    timestamp: int

class Metadata(BaseModel):
    channel: ChannelType
    language: str = "English"
    locale: str = "IN"

class ConversationRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

class ScamDetectionResult(BaseModel):
    is_scam: bool
    confidence: float
    scam_type: Optional[str] = None
    risk_score: float = Field(ge=0, le=1)
    indicators: List[str] = []

class IntelligenceExtraction(BaseModel):
    extraction_method: Optional[str] = None
    phone_numbers: List[str] = []
    urls: List[str] = []
    email_addresses: List[str] = []
    bank_names: List[str] = []
    upi_ids: List[str] = []
    scam_tactics: List[str] = []
    requested_actions: List[str] = []
    threats: List[str] = []
    suspicious_keywords: List[str] = []

class SessionState(BaseModel):
    session_id: str
    message_count: int
    strategy: Optional[str] = None
    persona: Optional[str] = None
    next_action: Optional[str] = None
    callback_triggered: bool = False

class AgentResponse(BaseModel):
    status: str
    reply: str
    detection: Optional[ScamDetectionResult] = None
    intelligence: Optional[IntelligenceExtraction] = None
    session_state: Optional[SessionState] = None

class APIError(BaseModel):
    detail: str
    error_code: str

class CallbackRequest(BaseModel):
    session_id: str
    scam_detected: bool
    total_messages_exchanged: int
    extracted_intelligence: Dict[str, List[str]]
    agent_notes: str

class CallbackResponse(BaseModel):
    status: str
    message: str
    callback_result: Optional[Dict[str, Any]] = None
    session_id: str
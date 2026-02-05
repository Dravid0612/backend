from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import time
from typing import Optional, Dict, Any, List
import redis
import json
import logging

from .config import settings
from .models import ConversationRequest, AgentResponse, APIError
from .scam_detector import ScamDetector
from .agent import HoneypotAgent
from .intelligence import IntelligenceExtractor
from .callback import EvaluationCallback
from .utils import rate_limiter, validate_api_key, setup_logging, sanitize_text

# Initialize FastAPI app
app = FastAPI(
    title=settings.API_NAME,
    version=settings.VERSION,
    description="AI-powered Agentic Honeypot for scam detection and engagement"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
scam_detector = ScamDetector({
    "MIN_SCAM_CONFIDENCE": settings.MIN_SCAM_CONFIDENCE,
    "USE_LLM": True
})
agent = HoneypotAgent({
    "USE_LLM": True,
    "AGENT_PERSONAS": settings.AGENT_PERSONAS
})
intelligence_extractor = IntelligenceExtractor()
callback_service = EvaluationCallback()

# Redis for session management
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

# Setup logging
logger = setup_logging()

@app.middleware("http")
async def log_requests(request, call_next):
    """Log all requests"""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    
    return response

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "name": settings.API_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "process": "/api/v1/process",
            "session_info": "/api/v1/session/{sessionId}",
            "trigger_callback": "/api/v1/trigger-callback/{session_id}"
        },
        "callback_enabled": settings.CALLBACK_ENABLED,
        "callback_endpoint": settings.EVALUATION_ENDPOINT
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "components": {
            "scam_detector": "operational",
            "agent": "operational",
            "intelligence_extractor": "operational",
            "callback_service": "operational",
            "redis": "connected" if redis_client.ping() else "disconnected"
        }
    }

@app.post("/api/v1/process", 
          response_model=AgentResponse,
          responses={400: {"model": APIError}, 
                    401: {"model": APIError}, 
                    429: {"model": APIError}})
async def process_message(
    request: ConversationRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None)
):
    """
    Process incoming scam messages and generate agent responses.
    
    - **sessionId**: Unique conversation identifier
    - **message**: Latest scammer message
    - **conversationHistory**: Previous messages in conversation
    - **metadata**: Channel, language, and locale info
    """
    
    # Validate API key
    if not validate_api_key(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "APIKey"}
        )
    
    # Rate limiting
    if not rate_limiter.check_limit(x_api_key):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded"
        )
    
    try:
        # Extract data from request
        session_id = request.sessionId
        message_text = sanitize_text(request.message.text)
        conversation_history = request.conversationHistory or []
        metadata = request.metadata
        
        logger.info(f"Processing message for session {session_id}, message length: {len(message_text)}")
        
        # 1. Detect scam intent
        detection_result = scam_detector.detect(message_text, conversation_history)
        
        # 2. Extract intelligence
        intelligence_result = intelligence_extractor.extract(message_text, conversation_history)
        
        # 3. Generate agent response
        session_key = f"session:{session_id}"
        
        # Get or create session state
        session_state = redis_client.hgetall(session_key)
        if not session_state:
            session_state = {
                "message_count": "0",
                "detection_history": "[]",
                "intelligence_data": "{}",
                "callback_sent": "false"
            }
            redis_client.hset(session_key, mapping=session_state)
        
        # Update session data
        current_message_count = len(conversation_history) + 1
        detection_history = json.loads(session_state.get("detection_history", "[]"))
        detection_history.append(detection_result)
        
        update_data = {
            "message_count": str(current_message_count),
            "detection_history": json.dumps(detection_history),
            "intelligence_data": json.dumps(intelligence_result),
            "last_updated": str(time.time()),
            "last_message": message_text[:500]  # Store truncated message
        }
        
        if metadata:
            update_data["metadata"] = json.dumps(metadata.dict())
        
        redis_client.hset(session_key, mapping=update_data)
        
        # 4. Generate agent response
        agent_result = agent.generate_response(
            message_text,
            detection_result,
            conversation_history,
            session_state
        )
        
        # 5. Check if we should trigger callback
        callback_triggered = False
        if (settings.CALLBACK_ENABLED and 
            detection_result.get("is_scam", False) and 
            session_state.get("callback_sent", "false") == "false"):
            
            should_trigger = check_callback_conditions(
                detection_result,
                current_message_count,
                message_text,
                conversation_history
            )
            
            if should_trigger:
                # Prepare and send callback in background
                background_tasks.add_task(
                    send_evaluation_callback,
                    session_id,
                    detection_result,
                    intelligence_result,
                    current_message_count,
                    conversation_history,
                    agent_result
                )
                callback_triggered = True
                redis_client.hset(session_key, "callback_sent", "true")
                redis_client.hset(session_key, "callback_triggered_at", str(time.time()))
        
        # 6. Prepare response
        response_data = {
            "status": "success",
            "reply": agent_result["reply"],
            "detection": detection_result,
            "intelligence": intelligence_result,
            "session_state": {
                "session_id": session_id,
                "message_count": current_message_count,
                "strategy": agent_result.get("strategy"),
                "persona": agent_result.get("persona"),
                "next_action": agent_result.get("next_action"),
                "callback_triggered": callback_triggered
            }
        }
        
        return AgentResponse(**response_data)
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

def check_callback_conditions(detection_result: Dict, 
                             message_count: int,
                             current_message: str,
                             conversation_history: List[Dict]) -> bool:
    """
    Determine if we should send callback
    Based on: scam detection confidence, message count, and conversation state
    """
    # Check if scam is confirmed with required confidence
    if not detection_result.get("is_scam", False):
        return False
    
    confidence = detection_result.get("confidence", 0)
    if confidence < settings.CALLBACK_MIN_CONFIDENCE:
        return False
    
    # Check if we have enough messages
    if message_count < settings.MIN_MESSAGES_FOR_CALLBACK:
        return False
    
    # Check for conversation end indicators
    end_indicators = ['thanks', 'thank you', 'bye', 'goodbye', 'okay', 'ok', 'done']
    current_lower = current_message.lower()
    if any(indicator in current_lower for indicator in end_indicators):
        logger.info(f"Callback triggered due to conversation end indicator: {current_message[:50]}...")
        return True
    
    # Check if scammer is asking for final action
    final_action_indicators = [
        'send now', 'transfer now', 'pay now', 'click now',
        'final step', 'last step', 'complete now'
    ]
    if any(indicator in current_lower for indicator in final_action_indicators):
        logger.info(f"Callback triggered due to final action request: {current_message[:50]}...")
        return True
    
    # Default: send after 8+ messages with high confidence
    if message_count >= 8 and confidence > 0.9:
        logger.info(f"Callback triggered due to long conversation: {message_count} messages")
        return True
    
    return False

async def send_evaluation_callback(session_id: str,
                                  detection_result: Dict,
                                  intelligence_result: Dict,
                                  message_count: int,
                                  conversation_history: List[Dict],
                                  agent_result: Dict):
    """
    Background task to send evaluation callback
    """
    try:
        logger.info(f"Starting callback process for session {session_id}")
        
        # Generate agent notes
        agent_notes = generate_agent_notes(conversation_history, detection_result, agent_result)
        
        # Prepare intelligence data
        intelligence_payload = callback_service.prepare_intelligence_payload(intelligence_result)
        
        # Send callback
        callback_result = callback_service.send_final_result(
            session_id=session_id,
            scam_detected=True,
            total_messages_exchanged=message_count,
            extracted_intelligence=intelligence_payload,
            agent_notes=agent_notes
        )
        
        # Store callback result
        session_key = f"session:{session_id}"
        redis_client.hset(session_key, "callback_result", json.dumps(callback_result))
        redis_client.hset(session_key, "callback_time", str(time.time()))
        
        logger.info(f"Callback process completed for session {session_id}. Success: {callback_result.get('success', False)}")
        
    except Exception as e:
        logger.error(f"Error in callback task for session {session_id}: {str(e)}", exc_info=True)

def generate_agent_notes(conversation_history: List[Dict], 
                        detection_result: Dict,
                        agent_result: Dict) -> str:
    """
    Generate summary notes about the scammer's behavior
    """
    notes = []
    
    # Add scam type
    scam_type = detection_result.get("scam_type", "unknown")
    if scam_type:
        notes.append(f"Scam type: {scam_type}")
    
    # Add confidence level
    confidence = detection_result.get("confidence", 0)
    confidence_percent = round(confidence * 100, 1)
    notes.append(f"Detection confidence: {confidence_percent}%")
    
    # Add agent strategy and persona
    agent_strategy = agent_result.get("strategy", "unknown")
    agent_persona = agent_result.get("persona", "default")
    notes.append(f"Agent strategy: {agent_strategy}, Persona: {agent_persona}")
    
    # Analyze tactics
    tactics = set()
    urgency_count = 0
    info_request_count = 0
    
    for msg in conversation_history:
        if msg.get('sender') == 'scammer':
            text = msg.get('text', '').lower()
            
            # Urgency tactics
            if any(word in text for word in ['urgent', 'immediate', 'now', 'quick', 'hurry']):
                urgency_count += 1
                tactics.add("urgency")
            
            # Greed triggers
            if any(word in text for word in ['free', 'win', 'prize', 'reward', 'bonus', 'money']):
                tactics.add("greed_trigger")
            
            # Information requests
            if any(word in text for word in ['verify', 'confirm', 'update', 'share', 'send', 'provide']):
                info_request_count += 1
                tactics.add("information_request")
            
            # Threats
            if any(word in text for word in ['block', 'suspend', 'terminate', 'legal', 'police']):
                tactics.add("threats")
    
    if tactics:
        notes.append(f"Identified tactics: {', '.join(sorted(tactics))}")
    
    # Add counts
    notes.append(f"Urgency indicators: {urgency_count}")
    notes.append(f"Information requests: {info_request_count}")
    
    # Add conversation metrics
    total_messages = len(conversation_history)
    scammer_messages = sum(1 for msg in conversation_history if msg.get('sender') == 'scammer')
    notes.append(f"Total messages: {total_messages} (Scammer: {scammer_messages})")
    
    # Add risk assessment
    risk_level = "high" if confidence > 0.9 else "medium" if confidence > 0.7 else "low"
    notes.append(f"Risk assessment: {risk_level}")
    
    # Add engagement summary
    if total_messages > 10:
        engagement = "deep"
    elif total_messages > 5:
        engagement = "moderate"
    else:
        engagement = "shallow"
    notes.append(f"Engagement level: {engagement}")
    
    return ". ".join(notes)

@app.get("/api/v1/session/{session_id}")
async def get_session_info(
    session_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """Get information about a specific session"""
    
    if not validate_api_key(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )
    
    # Parse JSON fields
    parsed_data = {}
    for key, value in session_data.items():
        if key in ["detection_history", "intelligence_data", "metadata", "callback_result"]:
            try:
                parsed_data[key] = json.loads(value)
            except:
                parsed_data[key] = value
        else:
            parsed_data[key] = value
    
    return {
        "session_id": session_id,
        **parsed_data
    }

@app.post("/api/v1/trigger-callback/{session_id}")
async def trigger_callback_manually(
    session_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """
    Manually trigger callback for a session (for testing)
    """
    if not validate_api_key(x_api_key, settings.API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not settings.CALLBACK_ENABLED:
        raise HTTPException(status_code=400, detail="Callback is disabled in configuration")
    
    # Get session data from Redis
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")
    
    try:
        # Parse stored data
        detection_history = json.loads(session_data.get("detection_history", "[]"))
        intelligence_data = json.loads(session_data.get("intelligence_data", "{}"))
        message_count = int(session_data.get("message_count", 0))
        
        if not detection_history:
            raise HTTPException(status_code=400, detail="No detection history found")
        
        # Use the latest detection result
        latest_detection = detection_history[-1] if detection_history else {}
        
        # Prepare intelligence payload
        intelligence_payload = callback_service.prepare_intelligence_payload(intelligence_data)
        
        # Generate agent notes
        conversation_text = session_data.get("last_message", "")
        agent_notes = f"Manually triggered callback. Last message: {conversation_text[:100]}..."
        
        # Send callback
        callback_result = callback_service.send_final_result(
            session_id=session_id,
            scam_detected=latest_detection.get("is_scam", False),
            total_messages_exchanged=message_count,
            extracted_intelligence=intelligence_payload,
            agent_notes=agent_notes
        )
        
        # Store callback result
        redis_client.hset(session_key, "manual_callback_result", json.dumps(callback_result))
        redis_client.hset(session_key, "manual_callback_time", str(time.time()))
        
        return {
            "status": "success" if callback_result.get("success") else "error",
            "message": "Callback sent successfully" if callback_result.get("success") else "Failed to send callback",
            "callback_result": callback_result,
            "session_id": session_id
        }
            
    except Exception as e:
        logger.error(f"Error triggering manual callback: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/api/v1/analytics")
async def get_analytics(
    x_api_key: Optional[str] = Header(None)
):
    """Get system analytics"""
    
    if not validate_api_key(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    # Get basic analytics from Redis
    try:
        session_keys = redis_client.keys("session:*")
        total_sessions = len(session_keys)
        
        scam_count = 0
        callback_sent_count = 0
        total_messages = 0
        
        for key in session_keys:
            session_data = redis_client.hgetall(key)
            if "detection_history" in session_data:
                try:
                    detections = json.loads(session_data["detection_history"])
                    if any(d.get("is_scam", False) for d in detections):
                        scam_count += 1
                except:
                    pass
            
            if session_data.get("callback_sent") == "true":
                callback_sent_count += 1
            
            if "message_count" in session_data:
                try:
                    total_messages += int(session_data["message_count"])
                except:
                    pass
        
        # Get scam type distribution
        scam_types = {}
        for key in session_keys:
            session_data = redis_client.hgetall(key)
            if "detection_history" in session_data:
                try:
                    detections = json.loads(session_data["detection_history"])
                    for detection in detections:
                        scam_type = detection.get("scam_type")
                        if scam_type:
                            scam_types[scam_type] = scam_types.get(scam_type, 0) + 1
                except:
                    pass
        
        return {
            "total_sessions": total_sessions,
            "scam_sessions": scam_count,
            "legitimate_sessions": total_sessions - scam_count,
            "callback_sent_sessions": callback_sent_count,
            "scam_rate": scam_count / total_sessions if total_sessions > 0 else 0,
            "average_messages_per_session": total_messages / total_sessions if total_sessions > 0 else 0,
            "scam_type_distribution": scam_types,
            "callback_config": {
                "enabled": settings.CALLBACK_ENABLED,
                "endpoint": settings.EVALUATION_ENDPOINT,
                "min_confidence": settings.CALLBACK_MIN_CONFIDENCE,
                "min_messages": settings.MIN_MESSAGES_FOR_CALLBACK
            },
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error(f"Error getting analytics: {str(e)}")
        return {
            "error": "Could not retrieve analytics",
            "timestamp": time.time()
        }

@app.get("/api/v1/sessions")
async def list_sessions(
    x_api_key: Optional[str] = Header(None)
):
    """List recent sessions for dashboard view"""

    if not validate_api_key(x_api_key, settings.API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    try:
        session_keys = redis_client.keys("session:*")
        sessions = []

        for key in session_keys:
            session_data = redis_client.hgetall(key)
            session_id = key.split("session:", 1)[-1]

            detection_history = []
            if "detection_history" in session_data:
                try:
                    detection_history = json.loads(session_data["detection_history"])
                except:
                    detection_history = []

            latest_detection = detection_history[-1] if detection_history else {}

            try:
                message_count = int(session_data.get("message_count", 0))
            except:
                message_count = 0

            try:
                last_updated = float(session_data.get("last_updated", 0))
            except:
                last_updated = 0

            sessions.append({
                "session_id": session_id,
                "is_scam": latest_detection.get("is_scam", False),
                "confidence": latest_detection.get("confidence", 0),
                "message_count": message_count,
                "last_updated": last_updated
            })

        sessions.sort(key=lambda s: s.get("last_updated", 0), reverse=True)
        return sessions

    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}")
        return []

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

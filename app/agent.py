import json
import random
from typing import Dict, List, Optional, Tuple
import openai
from datetime import datetime
from .config import settings

class HoneypotAgent:
    def __init__(self, config: Dict):
        self.config = config
        self.persona = self._select_persona()
        self.conversation_state = {}
        self.strategy = "engagement"  # engagement, extraction, escalation, termination
        
        # Initialize OpenAI if API key is available
        self.use_openai = False
        if hasattr(settings, 'OPENAI_API_KEY') and settings.OPENAI_API_KEY:
            openai.api_key = settings.OPENAI_API_KEY
            self.use_openai = True
    
    def _select_persona(self) -> str:
        """Select a random persona for variety"""
        personas = list(settings.AGENT_PERSONAS.keys())
        return random.choice(personas)
    
    def generate_response(self, 
                         message: str, 
                         detection_result: Dict,
                         conversation_history: List[Dict],
                         session_state: Dict) -> Dict:
        """Generate agent response based on strategy"""
        
        # Update conversation state
        self._update_state(message, detection_result, conversation_history, session_state)
        
        # Determine strategy
        self._determine_strategy(conversation_history)
        
        # Generate response
        if self.use_openai and self.config.get("USE_LLM", False):
            response = self._generate_llm_response(message, detection_result, conversation_history)
        else:
            response = self._generate_rule_based_response(message, detection_result, conversation_history)
        
        # Post-process response
        response = self._add_typos_and_delays(response)
        
        return {
            "reply": response,
            "strategy": self.strategy,
            "persona": self.persona,
            "next_action": self._get_next_action()
        }
    
    def _determine_strategy(self, conversation_history: List[Dict]):
        """Determine the best engagement strategy"""
        if len(conversation_history) < 2:
            self.strategy = "engagement"  # Initial engagement
        elif len(conversation_history) < 5:
            self.strategy = "extraction"  # Try to extract information
        elif len(conversation_history) > 8:
            self.strategy = "escalation"  # Escalate or prepare to terminate
        else:
            self.strategy = "engagement"
    
    def _generate_rule_based_response(self, 
                                    message: str, 
                                    detection_result: Dict,
                                    conversation_history: List[Dict]) -> str:
        """Generate response using rule-based system"""
        
        message_lower = message.lower()
        scam_type = detection_result.get("scam_type", "unknown")
        
        # Response templates based on scam type and strategy
        templates = {
            "bank_fraud": {
                "engagement": [
                    "Oh no, what's wrong with my account?",
                    "I'm worried about my account. What happened?",
                    "Can you tell me more about this issue?",
                    "I haven't done anything wrong. Why is this happening?"
                ],
                "extraction": [
                    "Which bank are you calling from?",
                    "What's your employee ID so I can verify?",
                    "Can you send me an official email from the bank?",
                    "What information do you need from me exactly?"
                ],
                "escalation": [
                    "This sounds serious. Let me call the bank directly.",
                    "I need to speak with your supervisor about this.",
                    "Can you provide a reference number for this case?",
                    "I'm going to visit my branch to sort this out."
                ]
            },
            "phishing": {
                "engagement": [
                    "What link should I click?",
                    "I'm not very tech-savvy. Can you guide me?",
                    "Is this website safe to enter my details?",
                    "My computer has been acting strange lately."
                ],
                "extraction": [
                    "What's the website address? I want to check it first.",
                    "Do you have a phone number I can call instead?",
                    "Can you send me an SMS with the link?",
                    "What information will I need to provide?"
                ],
                "escalation": [
                    "I'm not comfortable clicking links. Can we do this another way?",
                    "Let me check with my son/daughter who works in IT.",
                    "I think I should contact customer support directly.",
                    "This seems suspicious. I'm not going to click anything."
                ]
            },
            "fake_offers": {
                "engagement": [
                    "Wow, I won something? What did I win?",
                    "This is exciting! Tell me more!",
                    "I never win anything. Are you sure it's me?",
                    "What do I need to do to claim my prize?"
                ],
                "extraction": [
                    "What company is this prize from?",
                    "Is there any fee or tax I need to pay?",
                    "Can you send me official documentation?",
                    "What's the exact amount I won?"
                ],
                "escalation": [
                    "I need to verify this with the lottery commission.",
                    "Let me consult with my family before proceeding.",
                    "This sounds too good to be true. I'm skeptical.",
                    "I'll check with consumer protection agencies first."
                ]
            }
        }
        
        # Default templates if scam type not found
        default_templates = {
            "engagement": [
                "I'm not sure I understand. Can you explain?",
                "What do you mean by that?",
                "Can you tell me more about this?",
                "I need more information before I can proceed."
            ],
            "extraction": [
                "Who exactly are you representing?",
                "What organization are you from?",
                "Can you provide verification?",
                "How did you get my contact information?"
            ],
            "escalation": [
                "I need to think about this.",
                "Let me get back to you on this.",
                "I'm going to verify this independently.",
                "I don't feel comfortable sharing that information."
            ]
        }
        
        # Select template
        if scam_type in templates and self.strategy in templates[scam_type]:
            template_list = templates[scam_type][self.strategy]
        else:
            template_list = default_templates[self.strategy]
        
        # Add context-specific responses
        context_responses = self._get_context_specific_responses(message_lower, conversation_history)
        if context_responses:
            template_list = context_responses + template_list
        
        return random.choice(template_list)
    
    def _get_context_specific_responses(self, message: str, history: List[Dict]) -> List[str]:
        """Generate responses based on specific message content"""
        responses = []
        
        # Check for specific requests
        if any(word in message for word in ['upi', 'upi id', 'payment']):
            responses.extend([
                "I have multiple UPI IDs. Which bank should I use?",
                "Is Google Pay okay or do you need PhonePe?",
                "I'm not comfortable sharing UPI ID via text."
            ])
        
        if any(word in message for word in ['otp', 'password', 'pin']):
            responses.extend([
                "I never share OTPs. Is there another way?",
                "My bank says never to share OTP with anyone.",
                "Can you tell me what the OTP is for exactly?"
            ])
        
        if any(word in message for word in ['call', 'phone', 'number']):
            responses.extend([
                "I have poor network. Can we continue texting?",
                "What number should I call you back on?",
                "I prefer written communication for records."
            ])
        
        if any(word in message for word in ['link', 'website', 'url']):
            responses.extend([
                "My phone shows warning about this link.",
                "Can you spell out the website address?",
                "I'll check the link on my computer instead."
            ])
        
        return responses
    
    def _generate_llm_response(self, 
                              message: str, 
                              detection_result: Dict,
                              conversation_history: List[Dict]) -> str:
        """Generate response using LLM"""
        try:
            # Build conversation context
            context = self._build_llm_context(conversation_history)
            
            # Create prompt
            prompt = f"""
            You are a honeypot agent engaging with a potential scammer. Your persona: {self.persona}
            Current strategy: {self.strategy}
            Scam type detected: {detection_result.get('scam_type', 'unknown')}
            
            Conversation history:
            {context}
            
            Latest scammer message: "{message}"
            
            Generate a believable human response that:
            1. Engages naturally without raising suspicion
            2. Follows the {self.strategy} strategy
            3. Extracts useful intelligence if possible
            4. Sounds like a real {self.persona}
            5. Is concise (1-2 sentences max)
            
            Response:"""
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a honeypot agent designed to engage scammers naturally."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"LLM error: {e}")
            return self._generate_rule_based_response(message, detection_result, conversation_history)
    
    def _build_llm_context(self, conversation_history: List[Dict]) -> str:
        """Build conversation context for LLM"""
        context = []
        for msg in conversation_history[-6:]:  # Last 6 messages for context
            sender = "User" if msg.get('sender') == 'user' else "Scammer"
            context.append(f"{sender}: {msg.get('text', '')}")
        
        return "\n".join(context)
    
    def _add_typos_and_delays(self, response: str) -> str:
        """Add realistic typos and delays"""
        if random.random() < 0.3:  # 30% chance of typo
            typo_responses = [
                response.replace('.', '..'),
                response + ' ...',
                response.replace('you', 'u').replace('are', 'r'),
                response.lower().capitalize()  # Only first letter capitalized
            ]
            response = random.choice(typo_responses)
        
        return response
    
    def _update_state(self, message: str, detection_result: Dict, 
                     conversation_history: List[Dict], session_state: Dict):
        """Update conversation state"""
        self.conversation_state.update({
            "last_message": message,
            "detection_confidence": detection_result.get("confidence", 0),
            "message_count": len(conversation_history) + 1,
            "last_update": datetime.now().isoformat()
        })
    
    def _get_next_action(self) -> str:
        """Determine next action based on strategy"""
        actions = {
            "engagement": "continue_conversation",
            "extraction": "request_information",
            "escalation": "prepare_termination",
            "termination": "end_conversation"
        }
        return actions.get(self.strategy, "continue_conversation")
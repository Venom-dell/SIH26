from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field

class HeaderMetadata(BaseModel):
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    message_id: str = ""
    date: str = ""
    suspicious_attachments: List[str] = Field(default_factory=list)
    html_obfuscation_detected: bool = False

class AuthStatus(BaseModel):
    spf: Literal["pass", "fail", "neutral"] = "neutral"
    dkim: Literal["pass", "fail", "neutral"] = "neutral"
    dmarc: Literal["pass", "fail", "neutral"] = "neutral"
    domain_mismatch: bool = False
    display_name_spoofed: bool = False
    reply_to_hijacked: bool = False
    punycode_detected: bool = False
    lookalike_domain: bool = False
    domain_age_days: int = 0
    newly_registered: bool = False

class RelayHop(BaseModel):
    hop_number: int
    ip: str
    country: str = ""
    city: str = ""
    isp: str = ""
    is_anonymized: bool = False
    anonymization_type: Optional[str] = None
    is_forged: bool = False
    is_anonymized_node: bool = False

class NLPScore(BaseModel):
    urgency_score: float = 0.0
    fraud_score: float = 0.0
    intent_label: str = "neutral"

class AnalysisResult(BaseModel):
    overall_threat_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_level: Literal["Low", "Medium", "High"] = "Low"
    headers: HeaderMetadata = Field(default_factory=HeaderMetadata)
    auth: AuthStatus = Field(default_factory=AuthStatus)
    hops: List[RelayHop] = Field(default_factory=list)
    nlp: NLPScore = Field(default_factory=NLPScore)
    forgery_detected: bool = False
    domain_age_days: int = 0
    newly_registered: bool = False
    suspicious_links: List[str] = Field(default_factory=list)
    attachment_hashes: Dict[str, str] = Field(default_factory=dict)
    lethal_payload_detected: bool = False

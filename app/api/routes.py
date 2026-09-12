from fastapi import APIRouter, UploadFile, File, HTTPException
import tldextract
import re
from email.utils import parseaddr

from app.api.schemas import AnalysisResult, HeaderMetadata
from app.services.parser import EMLParser
from app.services.auth import AuthVerifier
from app.services.tracer import RelayTracer
from app.services.nlp import ThreatClassifier
from app.services.graph_analyzer import CommunicationGraph

router = APIRouter()

# Initialize services globally to reuse them across requests
parser = EMLParser()
auth_verifier = AuthVerifier()
tracer = RelayTracer()
nlp_classifier = ThreatClassifier()
comm_graph = CommunicationGraph()

def analyze_links(extracted_links: list[str], from_addr: str) -> list[str]:
    suspicious = []
    trusted_providers = {
        "google.com", "microsoft.com", "twitter.com", "facebook.com",
        "instagram.com", "linkedin.com", "sendgrid.net", "mailchimp.com",
        "hubspot.com", "aws.amazon.com"
    }
    
    _, parsed_from = parseaddr(from_addr)
    from_root = ""
    if "@" in parsed_from:
        from_domain = parsed_from.split("@")[1].lower()
        from_ext = tldextract.extract(from_domain)
        if from_ext.domain and from_ext.suffix:
            from_root = f"{from_ext.domain}.{from_ext.suffix}".lower()
        else:
            from_root = getattr(from_ext, 'domain', '').lower()

    for url in extracted_links:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            url_root = f"{ext.domain}.{ext.suffix}".lower()
        else:
            url_root = getattr(ext, 'domain', '').lower()
            
        if url_root and url_root != from_root and url_root not in trusted_providers:
            suspicious.append(url)
            
    return suspicious

@router.post("/analyze", response_model=AnalysisResult)
async def analyze_email(file: UploadFile = File(...)):
    try:
        raw_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # 1. Execute EMLParser
    headers_dict, body, received_headers = parser.parse(raw_bytes)
    
    # 2. Verify Authentication
    auth_status = auth_verifier.verify(headers_dict)
    
    # 3. Trace Relays
    hops, forgery_detected = tracer.trace(received_headers, headers_dict)
    
    # 4. Execute Threat Classifier
    subject = headers_dict.get("Subject", "")
    full_text = f"Subject: {subject}\n\n{body}" if subject else body
    nlp_score = nlp_classifier.analyze_text(full_text)
    
    # 5. Extract Header Metadata
    extracted_links = headers_dict.get("extracted_links", [])
    from_addr = headers_dict.get("From", "")
    to_addr   = headers_dict.get("To", "")
    suspicious_links = analyze_links(extracted_links, from_addr)
    
    # 5b. Structural Graph Analysis
    structural_risk = comm_graph.evaluate_connection(from_addr, to_addr)
    
    attachment_hashes = headers_dict.get("attachment_hashes", {})
    lethal_payload_detected = False
    lethal_pattern = re.compile(r'\.(exe|bat|vbs|scr)$|\.[^.]+\.(exe|bat|vbs|scr)$', re.IGNORECASE)
    for filename in attachment_hashes.keys():
        if lethal_pattern.search(filename):
            lethal_payload_detected = True
            break
            
    headers = HeaderMetadata(
        from_addr=headers_dict.get("From", ""),
        to_addr=headers_dict.get("To", ""),
        reply_to=headers_dict.get("Reply-To", ""),
        return_path=headers_dict.get("Return-Path", ""),
        subject=headers_dict.get("Subject", ""),
        message_id=headers_dict.get("Message-ID", ""),
        date=headers_dict.get("Date", ""),
        suspicious_attachments=headers_dict.get("suspicious_attachments", []),
        html_obfuscation_detected=headers_dict.get("html_obfuscation_detected", False)
    )
    
    # 6. Weighted Scoring Matrix
    
    # Step 1: Base score = NLP fraud_score (0–100)
    overall_threat_score = nlp_score.fraud_score
    
    # Step 2: Authentication Override
    # If both SPF and DKIM pass, reduce score by 20 (floor at 0)
    if auth_status.spf == "pass" and auth_status.dkim == "pass":
        overall_threat_score = max(overall_threat_score - 20.0, 0.0)
    
    # Step 3: Capped Technical Penalties (max combined = 40)
    tech_penalty = 0.0
    if auth_status.domain_mismatch:
        tech_penalty += 20.0
    if auth_status.newly_registered:
        tech_penalty += 20.0
    if structural_risk > 0:
        tech_penalty += 15.0
    if headers.suspicious_attachments:
        tech_penalty += 15.0
    overall_threat_score += min(tech_penalty, 40.0)
    
    # Step 4: Fatal Flags (bypass caps, +50/60 each)
    if forgery_detected:
        overall_threat_score += 50.0
    if auth_status.reply_to_hijacked:
        overall_threat_score += 50.0
    if lethal_payload_detected:
        overall_threat_score += 60.0
        
    # Check for anonymized relay in originating hop
    anonymized_relay_detected = False
    for hop in hops:
        if "Sender Origin" not in hop.isp:
            if getattr(hop, "is_anonymized_node", False):
                anonymized_relay_detected = True
                if suspicious_links:
                    overall_threat_score += 60.0
                else:
                    overall_threat_score += 25.0
            break
    
    # Final cap at 100
    overall_threat_score = min(round(overall_threat_score, 2), 100.0)
    
    # 7. Assign Risk Level & Feedback Loop
    if overall_threat_score <= 40:
        risk_level = "Low"
        # Continuous Learning: Mark connection as safe if overall threat is strictly less than 20
        if overall_threat_score < 20:
            comm_graph.add_safe_connection(from_addr, to_addr)
    elif overall_threat_score <= 75:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return AnalysisResult(
        overall_threat_score=overall_threat_score,
        risk_level=risk_level,
        headers=headers,
        auth=auth_status,
        hops=hops,
        nlp=nlp_score,
        forgery_detected=forgery_detected,
        domain_age_days=auth_status.domain_age_days,
        newly_registered=auth_status.newly_registered,
        suspicious_links=suspicious_links,
        attachment_hashes=attachment_hashes,
        lethal_payload_detected=lethal_payload_detected
    )

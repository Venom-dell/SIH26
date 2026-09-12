from transformers import pipeline
from app.api.schemas import NLPScore

class ThreatClassifier:
    def __init__(self):
        # Initialize zero-shot pipeline with CPU optimization (device=-1)
        self.classifier = pipeline(
            "zero-shot-classification",
            model="typeform/distilbert-base-uncased-mnli",
            device=-1
        )
        self.candidate_labels = [
            "phishing credential theft",
            "financial extortion",
            "business email compromise",
            "safe promotional or administrative"
        ]

    def analyze_text(self, body: str) -> NLPScore:
        # Return default low-risk scores if text is empty
        if not body or not body.strip():
            return NLPScore(urgency_score=0.0, fraud_score=0.0, intent_label="neutral")

        try:
            # Pass text to pipeline, ensuring truncation to model's token limit
            result = self.classifier(
                body,
                candidate_labels=self.candidate_labels,
                truncation=True,
                max_length=512
            )
            
            labels = result.get("labels", [])
            scores = result.get("scores", [])
            
            # Map labels to their respective confidence scores
            score_dict = dict(zip(labels, scores))
            
            # Pipeline returns labels sorted by highest score first
            intent_label = labels[0] if labels else "neutral"
            
            malicious_labels = [
                "phishing credential theft",
                "financial extortion",
                "business email compromise"
            ]
            
            fraud_score = 0.0
            if intent_label == "safe promotional or administrative":
                fraud_score = 0.0
            else:
                for m_label in malicious_labels:
                    conf = score_dict.get(m_label, 0.0)
                    if conf > 0.65:
                        fraud_score += conf * 100.0
                        
            fraud_score = min(fraud_score, 100.0)
            
            # Keep urgency_score based on financial extortion for schema backwards compatibility
            urgency_score = score_dict.get("financial extortion", 0.0) * 100.0
            
            return NLPScore(
                urgency_score=urgency_score,
                fraud_score=fraud_score,
                intent_label=intent_label
            )
            
        except Exception:
            # Fallback to defaults on error (e.g., tokenization issues)
            return NLPScore(urgency_score=0.0, fraud_score=0.0, intent_label="neutral")

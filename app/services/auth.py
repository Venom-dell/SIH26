import re
import difflib
import whois
import datetime
from email.utils import parseaddr
from app.api.schemas import AuthStatus

class AuthVerifier:
    def _get_root_domain(self, email_addr: str) -> str:
        """
        Naive root domain extraction for basic mismatch comparison.
        """
        if not email_addr:
            return ""
        _, addr = parseaddr(email_addr)
        if '@' not in addr:
            return ""
        
        domain = addr.split('@')[-1].lower()
        parts = domain.split('.')
        
        if len(parts) > 2:
            # Basic heuristic to handle ccTLDs (e.g., .co.uk)
            if parts[-2] in ["co", "com", "net", "org", "ac", "gov", "edu", "mil"]:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain

    def verify(self, headers: dict) -> AuthStatus:
        auth_results = str(headers.get("Authentication-Results", ""))
        received_spf = str(headers.get("Received-SPF", ""))
        from_header = str(headers.get("From", ""))
        return_path = str(headers.get("Return-Path", ""))
        reply_to_header = str(headers.get("Reply-To", ""))
        
        spf = "neutral"
        dkim = "neutral"
        dmarc = "neutral"
        
        # 1. Parse SPF from Authentication-Results or Received-SPF
        spf_match = re.search(r'\bspf\s*=\s*(pass|fail|neutral|softfail|hardfail|none)\b', auth_results, re.IGNORECASE)
        if not spf_match:
             spf_match = re.search(r'^\s*(pass|fail|neutral|softfail|hardfail|none)\b', received_spf, re.IGNORECASE)
             
        if spf_match:
            val = spf_match.group(1).lower()
            if "pass" in val:
                spf = "pass"
            elif "fail" in val:
                spf = "fail"
                
        # 2. Parse DKIM
        dkim_match = re.search(r'\bdkim\s*=\s*(pass|fail|neutral|none)\b', auth_results, re.IGNORECASE)
        if dkim_match:
            val = dkim_match.group(1).lower()
            if "pass" in val:
                dkim = "pass"
            elif "fail" in val:
                dkim = "fail"
                
        # 3. Parse DMARC
        dmarc_match = re.search(r'\bdmarc\s*=\s*(pass|fail|neutral|none|bestguesspass)\b', auth_results, re.IGNORECASE)
        if dmarc_match:
            val = dmarc_match.group(1).lower()
            if "pass" in val:
                dmarc = "pass"
            elif "fail" in val:
                dmarc = "fail"
                
        # 4. Compare domains
        from_domain = self._get_root_domain(from_header)
        return_domain = self._get_root_domain(return_path)
        
        domain_mismatch = False
        if from_domain and return_domain and from_domain != return_domain:
            domain_mismatch = True
            
        # 5. Display Name Spoofing Check
        display_name, from_addr = parseaddr(from_header)
        high_value_keywords = ["admin", "support", "ceo", "it desk", "helpdesk", "billing", "security", "update"]
        free_webmail_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "proton.me", "protonmail.com", "mail.com", "ymail.com"]
        
        display_name_spoofed = False
        display_name_lower = display_name.lower()
        if any(keyword in display_name_lower for keyword in high_value_keywords):
            if from_domain in free_webmail_domains:
                display_name_spoofed = True
                
        # 6. Reply-To Hijack Check
        reply_to_hijacked = False
        if reply_to_header:
            reply_to_domain = self._get_root_domain(reply_to_header)
            if reply_to_domain and from_domain and reply_to_domain != from_domain:
                reply_to_hijacked = True
        # 7. Homograph / Lookalike Domain Check
        punycode_detected = False
        lookalike_domain = False
        protected_domains = ["yourcompany.com", "google.com", "microsoft.com", "amazon.com", "apple.com", "paypal.com"]
        
        if from_domain:
            if from_domain.startswith("xn--"):
                punycode_detected = True
            
            for protected in protected_domains:
                # Calculate similarity ratio
                ratio = difflib.SequenceMatcher(None, from_domain, protected).ratio()
                # If it's highly similar but not an exact match (0.80 to 0.99)
                if 0.80 <= ratio <= 0.99:
                    lookalike_domain = True
                    break

        # 8. Domain Age / WHOIS Check
        domain_age_days = 0
        newly_registered = False
        
        if from_domain:
            try:
                domain_info = whois.whois(from_domain, timeout=2)
                creation_date = domain_info.creation_date
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    if isinstance(creation_date, datetime.datetime):
                        delta = datetime.datetime.now() - creation_date
                        domain_age_days = delta.days
                        if domain_age_days < 30:
                            newly_registered = True
            except Exception:
                pass # Ignore timeout or WHOIS query failures

        return AuthStatus(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            domain_mismatch=domain_mismatch,
            display_name_spoofed=display_name_spoofed,
            reply_to_hijacked=reply_to_hijacked,
            punycode_detected=punycode_detected,
            lookalike_domain=lookalike_domain,
            domain_age_days=domain_age_days,
            newly_registered=newly_registered
        )

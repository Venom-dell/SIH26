import re
import email
import hashlib
from email.message import Message
from email.header import decode_header, make_header

class EMLParser:
    def parse(self, raw_bytes: bytes) -> tuple[dict, str, list[str]]:
        msg = email.message_from_bytes(raw_bytes)
        
        headers = {}
        # Iterate over all headers; keep the first occurrence (top-most MTA headers)
        for key, value in msg.items():
            if key not in headers:
                headers[key] = str(value)
        
        # Decode MIME-encoded headers (=?UTF-8?B?...?=) back to Unicode
        for field in ("Subject", "From", "To"):
            if field in headers:
                headers[field] = self._decode_header(headers[field])
            
        body_parts = []
        suspicious_attachments = []
        attachment_hashes = {}
        html_obfuscation_detected = False
        extracted_links = set()
        
        high_risk_extensions = {".xlsm", ".docm", ".vbs", ".bat", ".ps1", ".hta", ".html", ".htm"}
        double_ext_pattern = re.compile(r'\.[^.]+\.(exe|js|bat|cmd|scr|vbs|pif|wsf|ps1)$', re.IGNORECASE)
        for part in msg.walk():
            if part.is_multipart():
                continue
                
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in content_disposition.lower():
                filename = part.get_filename()
                if filename:
                    # Compute SHA-256 hash for every attachment
                    raw_payload = part.get_payload(decode=True)
                    if raw_payload:
                        sha256 = hashlib.sha256(raw_payload).hexdigest()
                        attachment_hashes[filename] = sha256
                    
                    # Check for high-risk single extensions
                    ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                    is_high_risk_single = ext in high_risk_extensions
                    
                    # Check for double extensions ending in executables
                    is_double_ext = bool(double_ext_pattern.search(filename))
                    
                    if is_high_risk_single or is_double_ext:
                        suspicious_attachments.append(filename)
                continue
                
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except Exception:
                        text = payload.decode("utf-8", errors="replace")
                    body_parts.append(text)
                    extracted_links.update(re.findall(r'https?://[^\s<>\"\']+', text))
                        
            elif part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        html_text = payload.decode(charset, errors="replace")
                    except Exception:
                        html_text = payload.decode("utf-8", errors="replace")
                        
                    extracted_links.update(re.findall(r'https?://[^\s<>\"\']+', html_text))
                        
                    hidden_matches = re.findall(
                        r'<(?:div|span|p|td|font)[^>]*style\s*=\s*[\'"]?[^\'">]*(?:display:\s*none|color:\s*white|color:\s*#ffffff|color:\s*#fff|font-size:\s*0)[^\'">]*[\'"]?[^>]*>(.*?)</(?:div|span|p|td|font)>',
                        html_text,
                        re.IGNORECASE | re.DOTALL
                    )
                    
                    hidden_length = 0
                    for match in hidden_matches:
                        clean_text = re.sub(r'<[^>]+>', '', match)
                        hidden_length += len(clean_text.strip())
                        
                    if hidden_length > 150:
                        html_obfuscation_detected = True
                        
        body = "\n".join(body_parts)
        
        # get_all returns a list of header values
        raw_received = msg.get_all("Received", [])
        received_headers = [str(r) for r in raw_received]
        
        headers["suspicious_attachments"] = suspicious_attachments
        headers["attachment_hashes"] = attachment_hashes
        headers["html_obfuscation_detected"] = html_obfuscation_detected
        headers["extracted_links"] = list(extracted_links)
        
        return headers, body, received_headers

    @staticmethod
    def _decode_header(raw_value: str) -> str:
        """
        Decode MIME-encoded header values (e.g., =?UTF-8?B?...?=)
        back into standard Unicode text including emojis.
        Falls back to the original string if decoding fails.
        """
        try:
            return str(make_header(decode_header(raw_value)))
        except Exception:
            return raw_value

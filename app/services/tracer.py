import re
import time
import ipaddress
import requests
from functools import lru_cache
from typing import List, Tuple, Optional

from app.api.schemas import RelayHop
from app.core.security import KNOWN_TOR_NODES, HIGH_RISK_VPN_ASNS

HIGH_RISK_VPN_KEYWORDS = {'m247', 'datacamp', 'ovh', 'linode', 'digitalocean', 'choopa', 'vultr', 'mullvad', 'nordvpn', 'expressvpn', 'proton', 'hetzner', 'leaseweb', 'tzulo'}

@lru_cache(maxsize=1024)
def _fetch_ip_data(ip: str) -> dict:
    """
    Fetch IP metadata from ip-api.com with an LRU cache.
    Implements a strict 0.5-second rate limit for cache misses.
    """
    time.sleep(0.5)
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as,query,org"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return {}

class RelayTracer:
    def __init__(self):
        # Regex to find IPv4 addresses
        self.ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        # Regex to find basic IPv6 addresses
        self.ipv6_pattern = re.compile(r'(?<![:.\w])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}(?![:.\w])', re.IGNORECASE)

    def _is_public(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            # Exclude loopback and private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if ip.is_loopback or ip.is_private or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                return False
            return True
        except ValueError:
            return False

    def _check_anonymization(self, ip: str, asn_str: str) -> Tuple[bool, Optional[str]]:
        if ip in KNOWN_TOR_NODES:
            return True, "Tor"
            
        if asn_str:
            asn_upper = asn_str.upper()
            
            # Extract AS number to check exact match against the high-risk set
            asn_match = re.search(r'\b(AS\d+)\b', asn_upper)
            if asn_match:
                as_num = asn_match.group(1)
                if as_num in HIGH_RISK_VPN_ASNS:
                    return True, "VPN"
                    
            # Substring match for broader coverage
            for vpn_asn in HIGH_RISK_VPN_ASNS:
                if vpn_asn in asn_upper:
                    return True, "VPN"
                    
        return False, None

    def trace(self, received_headers: List[str], headers_dict: dict) -> Tuple[List[RelayHop], bool]:
        # Extract the authenticated client-ip
        client_ip = None
        auth_results = str(headers_dict.get("Authentication-Results", ""))
        received_spf = str(headers_dict.get("Received-SPF", ""))
        
        # Check for client-ip=... or designates ... as permitted sender
        ip_match = re.search(r'client-ip=([a-fA-F0-9\.\:]+)', received_spf, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'client-ip=([a-fA-F0-9\.\:]+)', auth_results, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'designates ([a-fA-F0-9\.\:]+) as permitted sender', received_spf, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'designates ([a-fA-F0-9\.\:]+) as permitted sender', auth_results, re.IGNORECASE)
            
        if ip_match:
            client_ip = ip_match.group(1).strip(";")

        # Read the Received chain from top to bottom (newest to oldest)
        hops_newest_first = []
        boundary_found = False
        forgery_detected = False
        
        for header in received_headers:
            ipv4s = self.ipv4_pattern.findall(header)
            ipv6s = self.ipv6_pattern.findall(header)
            
            # Find the first public IP in this header line
            public_ip = None
            for ip_candidate in ipv4s + ipv6s:
                if self._is_public(ip_candidate):
                    public_ip = ip_candidate
                    break
                    
            if not public_ip:
                continue
                
            is_forged = False
            country = city = isp = asn_str = org = ""
            is_anon, anon_type = False, None
            is_anonymized_node = False
            
            if boundary_found:
                # If we've passed the trust boundary, this hop is forged
                is_forged = True
                forgery_detected = True
            else:
                ip_data = _fetch_ip_data(public_ip)
                country = ip_data.get("country", "")
                city = ip_data.get("city", "")
                isp = ip_data.get("isp", "")
                asn_str = ip_data.get("as", "")
                org = ip_data.get("org", "")
                
                is_anon, anon_type = self._check_anonymization(public_ip, asn_str)
                
                for keyword in HIGH_RISK_VPN_KEYWORDS:
                    if keyword in org.lower() or keyword in isp.lower() or keyword in asn_str.lower():
                        is_anonymized_node = True
                        break
                
                # Check if this node marks the trust boundary (the authentic sender)
                if client_ip and public_ip == client_ip:
                    boundary_found = True
            
            hop = RelayHop(
                hop_number=0, # Will assign chronologically below
                ip=public_ip,
                country=country,
                city=city,
                isp=isp,
                is_anonymized=is_anon,
                anonymization_type=anon_type,
                is_forged=is_forged,
                is_anonymized_node=is_anonymized_node
            )
            hops_newest_first.append(hop)
            
        # Reverse to chronological order (oldest to newest)
        hops = []
        for i, hop in enumerate(reversed(hops_newest_first), 1):
            hop.hop_number = i
            hops.append(hop)
            
        # If the authenticated IP was extracted but NEVER found in the Received chain,
        # the SPF/Auth headers were likely injected/spoofed by the attacker!
        if client_ip and not boundary_found:
            forgery_detected = True
        
        # --- Inject Sender (origin) and Receiver (destination) endpoint hops ---
        from_header = headers_dict.get("From", "")
        to_header   = headers_dict.get("To", "")
        
        sender_hop = self._resolve_endpoint(from_header, "Sender Origin")
        receiver_hop = self._resolve_endpoint(to_header, "Receiver Destination")
        
        # Prepend sender as hop 0 and append receiver as the final hop
        final_hops = []
        next_num = 1
        
        if sender_hop:
            sender_hop.hop_number = next_num
            final_hops.append(sender_hop)
            next_num += 1
        
        for hop in hops:
            hop.hop_number = next_num
            final_hops.append(hop)
            next_num += 1
            
        if receiver_hop:
            receiver_hop.hop_number = next_num
            final_hops.append(receiver_hop)
            
        return final_hops, forgery_detected

    def _resolve_endpoint(self, header_value: str, label: str) -> Optional[RelayHop]:
        """
        Resolves an email address header (From/To) to a geolocation hop
        by doing a DNS lookup on the domain and then querying ip-api.
        """
        import socket
        from email.utils import parseaddr
        
        _, addr = parseaddr(header_value)
        if not addr or "@" not in addr:
            return None
            
        domain = addr.split("@")[1].strip()
        
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return None
            
        if not self._is_public(ip):
            return None
            
        ip_data = _fetch_ip_data(ip)
        if not ip_data or ip_data.get("status") == "fail":
            return None
            
        isp = ip_data.get("isp", "")
        asn_str = ip_data.get("as", "")
        org = ip_data.get("org", "")
        is_anonymized_node = False
        for keyword in HIGH_RISK_VPN_KEYWORDS:
            if keyword in org.lower() or keyword in isp.lower() or keyword in asn_str.lower():
                is_anonymized_node = True
                break

        return RelayHop(
            hop_number=0,
            ip=ip,
            country=ip_data.get("country", ""),
            city=ip_data.get("city", ""),
            isp=f"{label} ({isp})",
            is_anonymized=False,
            anonymization_type=None,
            is_forged=False,
            is_anonymized_node=is_anonymized_node
        )

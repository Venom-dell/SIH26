# Static fallback set of known Tor exit node IPs
KNOWN_TOR_NODES = {
    "104.244.72.115",
    "185.220.101.4",
    "185.220.101.14",
    "192.42.116.16",
    "109.70.100.11",
    "198.98.59.117",
    "171.25.193.20",
    "171.25.193.77",
    "199.249.230.73",
    "199.249.230.74",
    "185.220.101.12",
}

# Static fallback set of high-risk VPN ASN strings
HIGH_RISK_VPN_ASNS = {
    "AS9009",   # M247
    "AS212238", # Datacamp
    "AS60068",  # Datacamp / CDN77
    "AS205100", # NordVPN
    "AS398324", # Mullvad
    "AS211252", # Delis LLC
    "AS34994",  # LiquidWeb
    "AS62282",  # Kape Technologies (ExpressVPN, CyberGhost, PIA)
}

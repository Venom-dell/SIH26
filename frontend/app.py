import streamlit as st
import requests
import folium
from streamlit_folium import st_folium
import pandas as pd
from fpdf import FPDF
from fpdf.enums import XPos, YPos

st.set_page_config(page_title="Email Forensic Dashboard", layout="wide")

API_URL = "http://localhost:8000/analyze"

st.title("Email Forensic Analysis Dashboard")

# 1. File Uploader
uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

def generate_pdf(data):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("Arial", "", "C:/Windows/Fonts/arial.ttf")
    pdf.add_font("Arial", "B", "C:/Windows/Fonts/arialbd.ttf")
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Email Forensic Incident Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    
    pdf.cell(0, 5, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # 1. Email Metadata
    headers_info = data.get("headers", {})
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Email Metadata:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Arial", "", 11)
    
    # Handle long subjects or addresses by using multi_cell if needed, but for simplicity cell is fine if text is short
    pdf.cell(0, 6, f"From: {headers_info.get('from_addr', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"To: {headers_info.get('to_addr', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Date: {headers_info.get('date', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Subject might be long, so we use multi_cell
    pdf.multi_cell(0, 6, f"Subject: {headers_info.get('subject', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(0, 5, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # 2. Threat Analysis
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Threat Analysis:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 6, f"Overall Threat Score: {data.get('overall_threat_score')} / 100", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Risk Level: {data.get('risk_level')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    nlp = data.get("nlp", {})
    if nlp:
        pdf.cell(0, 6, f"Urgency Score: {round(nlp.get('urgency_score', 0), 2)}% | Fraud Score: {round(nlp.get('fraud_score', 0), 2)}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 6, f"Primary Intent: {nlp.get('intent_label', 'Unknown').title()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(0, 5, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # 3. Authentication
    auth = data.get("auth", {})
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Authentication Status:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 6, f"SPF: {auth.get('spf', 'N/A').upper()} | DKIM: {auth.get('dkim', 'N/A').upper()} | DMARC: {auth.get('dmarc', 'N/A').upper()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Domain Mismatch: {'Yes (Warning)' if auth.get('domain_mismatch') else 'No'}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(0, 5, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # 4. Relay Hops
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Relay Hops (Chronological):", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Arial", "", 10)
    for hop in data.get("hops", []):
        isp = hop.get("isp", "Unknown ISP")
        if hop.get("is_anonymized_node"):
            status = "Commercial VPN / Hosting (Warning)"
        else:
            status = "Forged" if hop.get("is_forged") else (f"Yes ({hop.get('anonymization_type')})" if hop.get("is_anonymized") else "No")
        hop_text = f"Hop {hop.get('hop_number')}: {hop.get('ip')} - {hop.get('city')}, {hop.get('country')} | ISP: {isp} | Status: {status}"
        pdf.multi_cell(0, 6, hop_text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
    return bytes(pdf.output())

def process_email(file_name, file_bytes):
    files = {"file": (file_name, file_bytes, "message/rfc822")}
    try:
        response = requests.post(API_URL, files=files)
        if response.status_code == 200:
            data = response.json()
            
            # Fetch coordinates on the fly and store inside data
            map_hops = []
            for hop in data.get("hops", []):
                if hop.get("is_forged"):
                    continue # Skip geolocation mapping for forged hops
                ip = hop.get("ip")
                try:
                    loc_resp = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon")
                    if loc_resp.status_code == 200:
                        loc_data = loc_resp.json()
                        if "lat" in loc_data and "lon" in loc_data:
                            hop_copy = hop.copy()
                            hop_copy["lat"] = loc_data["lat"]
                            hop_copy["lon"] = loc_data["lon"]
                            map_hops.append(hop_copy)
                except Exception:
                    pass
            data["map_hops"] = map_hops
            return data, None
        else:
            return None, f"Error from API: {response.status_code} - {response.text}"
    except Exception as e:
        return None, f"Failed to connect to API: {e}"

if uploaded_file is not None:
    if "current_file_id" not in st.session_state or st.session_state.current_file_id != uploaded_file.file_id:
        with st.spinner("Analyzing email and mapping locations..."):
            data, error = process_email(uploaded_file.name, uploaded_file.getvalue())
            if error:
                st.error(error)
                st.session_state.data = None
            else:
                st.session_state.data = data
                st.session_state.current_file_id = uploaded_file.file_id
                
    data = st.session_state.get("data")
    if data:
        # 3. Display three columns at the top
        col1, col2, col3 = st.columns(3)
        
        score = data.get("overall_threat_score", 0)
        risk_level = data.get("risk_level", "Unknown")
        domain_mismatch = data.get("auth", {}).get("domain_mismatch", False)
        
        # Use delta for colored metric
        delta_color = "inverse" if risk_level in ["High", "Medium"] else "normal"
        col1.metric("Overall Threat Score", f"{score} / 100", delta=risk_level, delta_color=delta_color)
        
        col2.metric("Risk Level", risk_level)
        
        mismatch_text = "Yes (Warning)" if domain_mismatch else "No"
        col3.metric("Domain Mismatch", mismatch_text)
        
        st.divider()
        st.subheader("Email Metadata")
        headers_info = data.get("headers", {})
        st.write(f"**From:** `{headers_info.get('from_addr', 'N/A')}`")
        st.write(f"**To:** `{headers_info.get('to_addr', 'N/A')}`")
        st.write(f"**Date:** {headers_info.get('date', 'N/A')}")
        st.write(f"**Subject:** {headers_info.get('subject', 'N/A')}")
        st.write(f"**Message-ID:** `{headers_info.get('message_id', 'N/A')}`")
        
        domain_age_str = f"{data.get('domain_age_days', 0)} days"
        if data.get('newly_registered'):
            domain_age_str += " (🚨 **NEWLY REGISTERED**)"
        st.write(f"**Domain Age:** {domain_age_str}")
        
        if data.get("lethal_payload_detected"):
            st.error("🚨💀 **CRITICAL: LETHAL PAYLOAD DETECTED! Executable or Double-Extension attachment found. DO NOT OPEN.**")
            
        suspicious_attachments = headers_info.get("suspicious_attachments", [])
        if suspicious_attachments:
            st.error(f"🚨 **Suspicious Attachments Detected:** {', '.join(suspicious_attachments)}")
            
        if headers_info.get("html_obfuscation_detected"):
            st.error("🚨 **HTML Obfuscation Detected:** Hidden text or zero-width spaces found in the email body!")
            
        suspicious_links = data.get("suspicious_links", [])
        if suspicious_links:
            st.error("🚨 **Suspicious Links Detected (Mismatched Root Domain):**")
            for link in suspicious_links:
                st.write(f"- `{link}`")
        
        attachment_hashes = data.get("attachment_hashes", {})
        if attachment_hashes:
            st.subheader("📎 Attachment Forensics")
            hash_rows = [{"Filename": fname, "SHA-256": sha} for fname, sha in attachment_hashes.items()]
            st.table(pd.DataFrame(hash_rows))
                
        st.divider()
        
        # 5. Render a summary table
        st.subheader("Authentication Summary")
        if data.get("forgery_detected"):
            st.error("🚨 Forgery Detected: Received headers contain injected or spoofed hops beyond the trust boundary!")
            
        auth_data = data.get("auth", {})
        auth_df = pd.DataFrame([
            {"Protocol": "SPF", "Status": auth_data.get("spf", "unknown").upper()},
            {"Protocol": "DKIM", "Status": auth_data.get("dkim", "unknown").upper()},
            {"Protocol": "DMARC", "Status": auth_data.get("dmarc", "unknown").upper()},
            {"Protocol": "Display Name Spoof", "Status": "DETECTED" if auth_data.get("display_name_spoofed") else "Safe"},
            {"Protocol": "Reply-To Hijack", "Status": "DETECTED" if auth_data.get("reply_to_hijacked") else "Safe"},
            {"Protocol": "Punycode (xn--)", "Status": "DETECTED" if auth_data.get("punycode_detected") else "Safe"},
            {"Protocol": "Lookalike Domain", "Status": "DETECTED" if auth_data.get("lookalike_domain") else "Safe"}
        ])
        st.table(auth_df)
        
        # 4. Display a Folium map
        st.subheader("Relay Path Map")
        map_hops = data.get("map_hops", [])
        
        if map_hops:
            map_hops = sorted(map_hops, key=lambda h: h.get("hop_number", 0))
            start_lat = map_hops[0]["lat"]
            start_lon = map_hops[0]["lon"]
            m = folium.Map(location=[start_lat, start_lon], zoom_start=2)
            
            coordinates = []
            for hop in map_hops:
                lat = hop["lat"]
                lon = hop["lon"]
                coordinates.append([lat, lon])
                
                is_anon = hop.get("is_anonymized", False)
                isp_label = hop.get("isp", "")
                
                if "Sender Origin" in isp_label:
                    color = "blue"
                    icon_name = "envelope"
                elif "Receiver Destination" in isp_label:
                    color = "purple"
                    icon_name = "inbox"
                elif is_anon:
                    color = "red"
                    icon_name = "info-sign"
                else:
                    color = "green"
                    icon_name = "info-sign"
                
                popup_text = f"""
                <b>Hop {hop.get('hop_number')}</b><br>
                <b>IP:</b> {hop.get('ip')}<br>
                <b>Location:</b> {hop.get('city')}, {hop.get('country')}<br>
                <b>ISP:</b> {hop.get('isp')}
                """
                if is_anon:
                    popup_text += f"<br><b style='color:red;'>Alert:</b> {hop.get('anonymization_type')} Node"

                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_text, max_width=300),
                    icon=folium.Icon(color=color, icon=icon_name)
                ).add_to(m)
                
            # Connected lines for sequential routing
            if len(coordinates) > 1:
                folium.PolyLine(
                    coordinates,
                    weight=2,
                    color="blue",
                    opacity=0.8
                ).add_to(m)
                
            # Use returned_objects=[] to prevent map interactions from triggering Streamlit reruns
            st_folium(m, width=800, height=400, returned_objects=[])
            
            # Show a detailed table of hops
            st.write("### Hop Details")
            hop_data = []
            has_vpn = False
            for hop in data.get("hops", []):
                if hop.get("is_anonymized_node"):
                    status = "Commercial VPN / Hosting"
                    has_vpn = True
                else:
                    status = "Forged" if hop.get("is_forged") else ("Yes (" + str(hop.get("anonymization_type")) + ")" if hop.get("is_anonymized") else "No")
                
                hop_data.append({
                    "Hop": hop.get("hop_number"),
                    "IP": hop.get("ip"),
                    "Location": f"{hop.get('city')}, {hop.get('country')}",
                    "ISP": hop.get("isp"),
                    "Status": status
                })
                
            if has_vpn:
                st.error("🚨 **Traffic routed through commercial VPN / Hosting Provider**")
                
            df = pd.DataFrame(hop_data)
            def highlight_vpn(row):
                if row["Status"] == "Commercial VPN / Hosting":
                    return ['background-color: rgba(255, 75, 75, 0.2); color: #ff4b4b; font-weight: bold'] * len(row)
                return [''] * len(row)
                
            st.table(df.style.apply(highlight_vpn, axis=1))
        else:
            st.warning("Could not map relay hops (No location data found).")
        
        # 6. Generate Forensic PDF button
        st.subheader("Export Report")
        pdf_bytes = generate_pdf(data)
        st.download_button(
            label="Generate Forensic PDF",
            data=pdf_bytes,
            file_name="forensic_report.pdf",
            mime="application/pdf"
        )

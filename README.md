# Advanced Email Threat Detection Engine

## Overview
This project presents a multi-layered forensic analysis and threat intelligence platform designed to identify, deconstruct, and mitigate sophisticated email-borne attacks. Built specifically to detect Business Email Compromise (BEC), spear-phishing, and credential harvesting, the system acts as a specialized pipeline evaluating raw `.eml` files against cryptographic, structural, and linguistic vectors.

## 💡 Why This Approach is Superior

Traditional email security gateways (SEGs) primarily rely on static blacklists, Bayesian spam filters, and binary cryptographic checks. Our pipeline fundamentally improves upon legacy systems by:

1. **Contextual Intent over Static Signatures:** Instead of relying solely on known-bad signatures, our **Zero-Shot NLP** model understands the *semantic intent* of the email (e.g., financial urgency, credential requests). This stops zero-day BEC attacks that contain no malicious links or payloads.
2. **Defeating Vendor Email Compromise (VEC):** Attackers frequently hijack legitimate vendor accounts to easily bypass SPF/DKIM checks. Our **Structural Graph Analysis** models historical relationships. Even if an email originates from a trusted domain, it is flagged if the structural pathway (e.g., a low-level vendor suddenly emailing the CFO) is highly anomalous.
3. **Neutralizing Evasion Tactics:** Modern attackers use hidden CSS text, Unicode spoofing, and double-extensions to bypass standard scanners. Our engine deeply parses raw MIME headers and executes regex checks to strip these obfuscation techniques *before* classification.
4. **Geographical & Infrastructural Correlation:** By tracing raw SMTP relay hops and correlating autonomous systems (ASNs) against threat intelligence, the engine identifies the true footprint of the attacker, exposing campaigns hiding behind commercial VPNs and bulletproof hosting.

## 🛡️ Threat Detection Pipeline

Our architecture operates on a unified, weighted threat scoring matrix. Incoming communications are passed through five sequential analysis layers:

### 1. Cryptographic Authentication & Spoofing Detection
- Validates the integrity of **SPF, DKIM, and DMARC** protocols.
- Detects sophisticated spoofing techniques, including homograph attacks (Punycode `xn--` domain variants), lookalike domains, and display name manipulation.
- Evaluates domain age to penalize newly registered infrastructure.

### 2. Network Infrastructure & Relay Tracing
- Maps SMTP relay hops geographically to construct the true origin path of the communication.
- Cross-references IP Autonomous System Numbers (ASNs) against threat intelligence heuristics to identify anonymization nodes, commercial VPNs, and bulletproof hosting providers.
- Enforces an un-cappable "Fatal Penalty" if an email originates from high-risk infrastructure and contains suspicious external links.

### 3. Structural Graph Analysis (Continuous Learning)
- Utilizes `networkx` to map the corporate network, establishing a dynamic baseline of verified communication edges.
- Evaluates structural risk by identifying anomalous connections to high-value organizational targets (e.g., Accounts Payable, Procurement).
- Features an automated feedback loop that persists safe communication paths (`graph_baseline.json`) when analyzed emails score below a strict risk threshold.

### 4. Zero-Shot Linguistic Threat Classification
- Leverages Hugging Face `transformers` to run zero-shot semantic analysis over standard Unicode strings (fully decoded from MIME header obfuscation).
- Tuned to identify intent markers indicative of BEC, artificial urgency, and credential theft, minimizing false positives via a strict confidence threshold.
- Detects HTML and CSS-based text obfuscation (e.g., invisible text stuffing) designed to poison traditional Bayesian spam filters.

### 5. Payload Forensics & Triage
- Statically analyzes extracted attachments to compute binary SHA-256 hashes for incident response tracking.
- Identifies lethal payloads, including direct executables and disguised double-extensions (e.g., `invoice.pdf.exe`).
- Instantly flags the communication as fundamentally compromised upon payload detection, overriding technical scoring caps.

## 🛠️ Technical Architecture

* **Backend API:** FastAPI (Python 3.10+) 
* **Interactive Dashboard:** Streamlit 
* **Data Validation:** Pydantic
* **Analysis Modules:** `transformers` (NLP), `networkx` (Graph Analytics), `folium` (Geographic Mapping), `fpdf2` (Unicode Forensic Reporting)

## 🔧 Getting Started

### Prerequisites
* Python 3.10 or higher.
* Install core dependencies via `pip install -r requirements.txt`.

### Execution

1. **Initialize Backend API**
   ```bash
   uvicorn main:app --reload --port 8000
   ```
2. **Launch Forensic Dashboard**
   Open a new terminal and run:
   ```bash
   streamlit run frontend/app.py
   ```
3. **Analyze Evidence:** Upload raw `.eml` samples directly into the Streamlit dashboard to engage the threat pipeline and export comprehensive forensic reports.

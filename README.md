
# 🔍 Tools for Phishing Email Analysis

A concise reference of useful tools and platforms to analyze and investigate phishing emails, organized by analysis phase. For each tool you’ll find a short description, usage tips, and example commands (where applicable). Always handle suspicious files/links in an isolated environment (VM/sandbox) and follow your organization’s policy.

Prerequisites & safety
- Use an isolated analysis environment (air-gapped VM, sandbox, or container) for attachments and detonation.
- Collect full raw email headers and the original attachment(s) or URL(s).
- Many services require API keys — keep them in secure vaults (e.g., HashiCorp Vault, AWS Secrets Manager).
- When using public sandboxes or uploading samples, consider privacy and legal implications (don’t upload sensitive customer data).

1. Header & Metadata Analysis
- MxToolbox — Checks DNS records relevant to email (SPF/DKIM/DMARC) and provides header checks.
  - Web: https://mxtoolbox.com
  - Quick local checks:
    - SPF: `dig +short TXT example.com`
    - DMARC: `dig +short TXT _dmarc.example.com`
    - DKIM: `dig +short TXT selector._domainkey.example.com`
  - Example (curl to their SuperTool):  
    ```bash
    # Replace domain and action as needed (web usage preferred)
    curl "https://mxtoolbox.com/SuperTool.aspx?action=spf:example.com"
    ```

- Google Admin Toolbox — Messageheader parser (web).
  - Web: https://toolbox.googleapps.com/apps/messageheader/
  - Use: paste the raw headers (From/Return-Path/Received lines) to parse and trace route hops.

- Microsoft Message Header Analyzer — Built-in for Outlook/Exchange/online tool.
  - Outlook: open message → File → Properties → Internet headers, then paste into analyzer or use Exchange Online PowerShell:
    ```powershell
    # Example Exchange Online: view message trace (admin)
    Get-MessageTrace -SenderAddress "attacker@example.com" -StartDate "2026-01-01" -EndDate "2026-01-05"
    ```

2. Sandbox & Detonation
- Cuckoo Sandbox — Open-source malware analysis framework.
  - Install (high-level): `pip install cuckoo` (or use distro packages/docker).
  - Submit a sample:
    ```bash
    cuckoo submit /path/to/suspicious.docx
    ```
  - Use web UI to review behavior, network calls, spawned processes, and dropped files.

- Any.Run — Interactive web sandbox (manual, great for analysts).
  - Web: https://any.run
  - Upload file or paste URL; interact with the VM in real time to observe behavior.
  - API / automation available for pro users (check Any.Run docs).

- Hybrid Analysis — Free cloud-based analysis with API.
  - Web: https://www.hybrid-analysis.com
  - Example API upload (requires API key):
    ```bash
    curl -s -H "API-Key: YOUR_API_KEY" -F "file=@sample.exe" https://www.hybrid-analysis.com/api/v2/quick-scan/file
    ```

3. URL & Domain Reputation
- VirusTotal — Multi-engine scanning for files and URLs.
  - Upload file:
    ```bash
    curl -s -X POST "https://www.virustotal.com/api/v3/files" \
      -H "x-apikey: YOUR_API_KEY" \
      -F "file=@/path/to/sample.exe"
    ```
  - Scan a URL:
    ```bash
    curl -s -X POST "https://www.virustotal.com/api/v3/urls" \
      -H "x-apikey: YOUR_API_KEY" \
      --data "url=https://suspicious.example.com/login"
    ```
  - vt-cli (optional): `vt scan file sample.exe` (requires vt client + API key)

- PhishTank — Community phishing URL database.
  - Web: https://phishtank.org
  - Search a URL through the site. For integrations, consult their API docs for lookup endpoints.

- URLScan.io — In-depth URL analysis and page resource collection.
  - Example API scan:
    ```bash
    curl -X POST "https://urlscan.io/api/v1/scan/" \
      -H "API-Key: YOUR_API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"url":"http://suspicious.example.com","public":"on"}'
    ```
  - View the returned result URL for screenshots, resource lists, and network calls.

4. Attachment & Payload Inspection
- OLETools — Analyze Office documents (macros, embedded objects).
  - Install: `pip install oletools`
  - Inspect macros and suspicious content:
    ```bash
    olevba suspicious.docm
    # or
    oledump.py suspicious.doc | less
    ```
  - Use `mraptor` (part of oletools) for macro risk scoring.

- YARA — Signature-based detection for payloads and artifacts.
  - Install: distro package or `pip install yara-python`
  - Example rule (save as rules.yar):
    ```yara
    rule SuspiciousPhishSubject {
      strings:
        $s1 = "account verification required"
      condition:
        $s1
    }
    ```
  - Scan files:
    ```bash
    yara -r rules.yar /path/to/samples/
    ```

- ExifTool — Extract metadata from attachments (images, office files, PDFs).
  - Install: `brew install exiftool` or distro package.
  - Example:
    ```bash
    exiftool suspicious.docx
    exiftool suspicious.pdf
    ```

5. Threat Intelligence & Correlation
- MISP — Malware Information Sharing Platform.
  - Web UI: create events, attributes, and share IoCs.
  - API example (using API key):
    ```bash
    curl -H "Authorization: YOUR_MISP_KEY" -H "Accept: application/json" "https://misp.example.com/events"
    ```
  - Use PyMISP for automation: `pip install pymisp`

- OpenCTI — Threat intelligence platform to model campaigns and relationships.
  - Use the OpenCTI UI or Python client (`pip install pycti`).
  - Example snippet to fetch indicators (Python):
    ```python
    from pycti import OpenCTIConnectorHelper, OpenCTIApiClient
    client = OpenCTIApiClient(api_url="https://opencti.example.com", api_token="YOUR_TOKEN")
    indicators = client.indicator.list()
    print(indicators)
    ```

6. Email Security Gateways
- Proofpoint TAP, Mimecast, Microsoft Defender for Office 365 — enterprise tools that detect, quarantine, and report phishing.
  - Microsoft Defender (Exchange Online PowerShell / Graph):
    ```powershell
    # Search message traces
    Get-MessageTrace -SenderAddress "spoof@example.com" -StartDate "2026-01-01" -EndDate "2026-01-05"
    # For Threat Explorer / Explorer UI use Defender for Office 365 portal
    ```
  - Proofpoint TAP API (example, check vendor docs):
    ```bash
    curl -u 'username:password' 'https://tap-api-v2.proofpoint.com/v2/siem?startDate=2026-01-01'
    ```
  - Mimecast: use their APIs or admin console to search, quarantine, and release messages (check Mimecast API docs for exact endpoints and auth flow).

Quick investigation playbook (recommended sequence)
1. Capture raw headers and the original email file (.eml).
2. Perform header analysis (Google Admin Toolbox, MxToolbox, manual Received chain).
3. Check sender/domain reputation and DNS records (VirusTotal, URLScan, dig).
4. If there are attachments:
   - Extract metadata with ExifTool, check macros with OLETools.
   - Run static YARA rules locally.
5. If safe to detonate, submit to sandbox (Cuckoo / Any.Run / Hybrid Analysis).
6. Correlate IoCs in MISP/OpenCTI and search enterprise gateways (Proofpoint/Microsoft/Mimecast).
7. Take remediation actions: block URL/domain, add indicators to mail filters or blocklists, notify impacted users.

Notes & best practices
- Prefer reading sandbox reports and raw PCAP for network indicators.
- Keep YARA rules and threat feeds updated and tuned to your environment.
- When using public sandboxes, consider not uploading sensitive samples or PII.
- Build automation (scripts) to push critical IoCs to your email gateway and detection tools.

If you’d like, I can:
- Add direct links to official docs for each tool.
- Create example YARA rules for common phishing artifacts.
- Provide a small script to extract headers from an .eml file and run basic local checks.

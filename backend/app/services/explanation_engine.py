"""
Explanation Engine for PhishGuard-AI.
Generates rule-based heuristic indicators distinctly and independently from the neural network ML outputs.
"""

import re
from typing import Dict, List
from backend.app.schemas import HeuristicIndicator


def explain_url_threats(url: str, features: Dict[str, float]) -> List[HeuristicIndicator]:
    """
    Produce heuristic indicators for a URL based on extracted static features and pattern analysis.
    """
    indicators = []

    # 1. IP as hostname
    if features.get("has_ip", 0.0) == 1.0:
        indicators.append(HeuristicIndicator(
            code="URL_IP_HOSTNAME",
            name="IP Address Used as Hostname",
            description="The destination relies directly on a numeric IP address instead of a registered domain name, common in spoofed destinations.",
            severity="danger",
            matched=True
        ))

    # 2. Insecure protocol (No HTTPS)
    if features.get("has_https", 1.0) == 0.0:
        indicators.append(HeuristicIndicator(
            code="URL_NO_HTTPS",
            name="Missing HTTPS Transport Encryption",
            description="The URL uses plaintext HTTP instead of secure HTTPS, indicating missing cryptographic transport protection.",
            severity="warning",
            matched=True
        ))

    # 3. Suspicious keywords count
    kw_count = int(features.get("suspicious_keywords_count", 0.0))
    if kw_count > 0:
        indicators.append(HeuristicIndicator(
            code="URL_SUSPICIOUS_KEYWORDS",
            name=f"Sensitive Keywords Detected ({kw_count})",
            description=f"Contains {kw_count} high-risk keyword(s) commonly associated with account credential theft (e.g., login, verify, banking, update).",
            severity="danger" if kw_count > 1 else "warning",
            matched=True
        ))

    # 4. URL Shortener
    if features.get("has_shortener", 0.0) == 1.0:
        indicators.append(HeuristicIndicator(
            code="URL_SHORTENER_DETECTED",
            name="URL Shortening Service Detected",
            description="Uses a link shortening redirector (e.g. bit.ly, tinyurl) which obfuscates the true destination server.",
            severity="warning",
            matched=True
        ))

    # 5. Excessive length
    length = features.get("url_length", 0.0)
    if length > 80:
        indicators.append(HeuristicIndicator(
            code="URL_EXCESSIVE_LENGTH",
            name=f"Abnormal URL Length ({int(length)} chars)",
            description="Length exceeds standard benchmarks (>80 chars). Phishers often use elongated query parameters to conceal redirect targets.",
            severity="warning",
            matched=True
        ))

    # 6. High Shannon entropy
    entropy = features.get("entropy", 0.0)
    if entropy > 4.5:
        indicators.append(HeuristicIndicator(
            code="URL_HIGH_ENTROPY",
            name=f"High Character Randomness / Entropy ({entropy:.2f})",
            description="High character randomness indicates algorithmically generated domains (DGA) or token-masked URLs.",
            severity="warning",
            matched=True
        ))

    # 7. Multiple Subdomains
    subdomains = int(features.get("num_subdomains", 0.0))
    if subdomains >= 2:
        indicators.append(HeuristicIndicator(
            code="URL_DEEP_SUBDOMAINS",
            name=f"Deep Subdomain Nesting ({subdomains} levels)",
            description="Deep subdomain structure may impersonate legitimate brands inside a prefix domain.",
            severity="warning",
            matched=True
        ))

    # 8. Deceptive '@' character
    if features.get("num_at", 0.0) > 0:
        indicators.append(HeuristicIndicator(
            code="URL_AT_SYMBOL",
            name="Deceptive '@' Character",
            description="Browsers may treat text prior to '@' as user-authentication tokens, concealing the true host.",
            severity="danger",
            matched=True
        ))

    # 9. Non-standard port
    if features.get("has_port", 0.0) == 1.0:
        indicators.append(HeuristicIndicator(
            code="URL_NON_STANDARD_PORT",
            name="Non-Standard Port Explicitly Defined",
            description="Connects to a non-standard HTTP/HTTPS port, bypassing standard security inspection filters.",
            severity="warning",
            matched=True
        ))

    # If no negative indicators fired
    if not indicators:
        indicators.append(HeuristicIndicator(
            code="URL_BENIGN_STRUCTURE",
            name="Clean Structural Syntax",
            description="No anomalous or deceptive syntax patterns detected. Uses standard domain format and HTTPS.",
            severity="info",
            matched=True
        ))

    return indicators


def explain_message_threats(raw_message: str, cleaned_message: str) -> List[HeuristicIndicator]:
    """
    Produce heuristic indicators for message text based on social engineering and phishing linguistic cues.
    """
    indicators = []
    msg_lower = raw_message.lower()

    # 1. Urgency / Pressure
    urgency_patterns = [
        r"\burgent\b", r"\bimmediately\b", r"\bexpire[s]?\b", r"\baction required\b",
        r"\b24 hours\b", r"\bterminate[d]?\b", r"\blocked\b", r"\bsuspend[ed]?\b",
        r"\bfinal warning\b", r"\bcritical\b"
    ]
    matched_urgency = [p for p in urgency_patterns if re.search(p, msg_lower)]
    if matched_urgency:
        indicators.append(HeuristicIndicator(
            code="MSG_URGENCY_PRESSURE",
            name="Artificial Urgency & Pressure Tactics",
            description="Language triggers panic or rapid response deadlines ('immediately', 'suspended', '24h') to circumvent critical thinking.",
            severity="danger",
            matched=True
        ))

    # 2. Financial & Prize Lures
    lure_patterns = [
        r"\bwon\b", r"\bprize\b", r"\bgift card\b", r"\breward\b", r"\brefund\b",
        r"\bbonus\b", r"\blottery\b", r"\bcash\b", r"\bdeposit\b", r"\bclaim\b",
        r"\$|\bfree\b"
    ]
    matched_lures = [p for p in lure_patterns if re.search(p, msg_lower)]
    if len(matched_lures) >= 2 or re.search(r"(\$\s*\d+|\bwon\b|\blottery\b)", msg_lower):
        indicators.append(HeuristicIndicator(
            code="MSG_FINANCIAL_LURE",
            name="Financial Incentive or Prize Lure",
            description="Prompts promises of unexpected cash, lottery wins, gift cards, or unearned tax/shipping refunds.",
            severity="danger",
            matched=True
        ))

    # 3. Impersonation of Financial/Government/Authority Entities
    authority_patterns = [
        r"\birs\b", r"\bpaypal\b", r"\bbank of america\b", r"\bchase\b", r"\bwells fargo\b",
        r"\busps\b", r"\bdhl\b", r"\bfedex\b", r"\bnetflix\b", r"\bamazon\b", r"\bapple\b",
        r"\bsocial security\b", r"\bpolice\b", r"\bcitibank\b"
    ]
    matched_authority = [p for p in authority_patterns if re.search(p, msg_lower)]
    if matched_authority:
        indicators.append(HeuristicIndicator(
            code="MSG_AUTHORITY_IMPERSONATION",
            name="Institutional / Brand Name Mentioned",
            description="References a prominent financial, shipping, or tech brand commonly targeted for credential harvesting.",
            severity="warning",
            matched=True
        ))

    # 4. Action Call & Links
    action_patterns = [
        r"\bclick here\b", r"\bcall now\b", r"\bcall immediately\b", r"\btext yes\b",
        r"\bverify your\b", r"\bsign in\b", r"\bupdate payment\b", r"http[s]?://", r"\bwww\."
    ]
    matched_action = [p for p in action_patterns if re.search(p, msg_lower)]
    if matched_action:
        indicators.append(HeuristicIndicator(
            code="MSG_CALL_TO_ACTION",
            name="Direct Call-to-Action / Embedded Link",
            description="Directs the recipient to click an external link, call an unverified phone number, or disclose sensitive information.",
            severity="warning",
            matched=True
        ))

    # 5. Suspicious Phone / Premium Rate Pattern
    if re.search(r"\b(0800|0871|090|88202|\+?1?\s*800\s*\d{3})\b", msg_lower):
        indicators.append(HeuristicIndicator(
            code="MSG_PREMIUM_PHONE_NUMBER",
            name="Toll/Premium Rate Number Detected",
            description="Contains telephone routing strings or premium SMS shortcodes often tied to fraudulent call-centers.",
            severity="warning",
            matched=True
        ))

    # If no negative indicators fired
    if not indicators:
        indicators.append(HeuristicIndicator(
            code="MSG_NORMAL_CONVERSATIONAL",
            name="Standard Conversational Pattern",
            description="Text does not display characteristic threat triggers, urgency coercion, or unsolicited prize solicitations.",
            severity="info",
            matched=True
        ))

    return indicators

"""
phishing_checker.py
DecodeLabs Cyber Security - Project 3: Phishing Awareness Analysis
"""

import re
SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "verify your account", "act now",
    "password", "confirm your identity", "click here", "suspended",
    "unusual activity", "limited time", "wire transfer", "gift card",
    "congratulations", "you have won", "bank account", "social security",
    "update your billing", "confidential", "bypass", "do not tell",
    "call this number", "free", "claim your", "login now",
]

TRUSTED_DOMAINS = {
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
}

SUSPICIOUS_LINK_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   
    r"bit\.ly|tinyurl\.com|is\.gd|t\.co",     
    r"-secure-|-login-|-verify-|-update-",   
    r"[a-z]+[0-9]+\.(com|net|org)",          
]

def find_links(text):
    """Return every http(s):// or www. link found in the text."""
    pattern = r"(https?://\S+|www\.\S+)"
    return re.findall(pattern, text, flags=re.IGNORECASE)


def find_suspicious_keywords(text):
    """Return the list of suspicious keywords/phrases found in the text."""
    text_lower = text.lower()
    found = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in text_lower:
            found.append(word)
    return found


def check_link_tricks(link):
    """Check ONE link against our list of suspicious patterns.
    Returns a list of reasons (empty list = nothing suspicious found)."""
    reasons = []
    for pattern in SUSPICIOUS_LINK_PATTERNS:
        if re.search(pattern, link, flags=re.IGNORECASE):
            reasons.append(f"matches risky pattern: {pattern}")
    return reasons


def check_brand_mismatch(text, links):
    """If the message mentions a trusted brand (like 'PayPal') but none of
    the links actually go to PayPal's real domain, flag it."""
    reasons = []
    text_lower = text.lower()
    for brand, real_domains in TRUSTED_DOMAINS.items():
        if brand in text_lower:
            matches_real_domain = any(
                domain in link.lower() for link in links for domain in real_domains
            )
            if links and not matches_real_domain:
                reasons.append(
                    f"message mentions '{brand}' but no link points to its real "
                    f"domain ({', '.join(real_domains)})"
                )
    return reasons


def analyze_message(text):
    """
    Analyze the given message text.
    Returns a dictionary with:
        - links found
        - suspicious keywords found
        - red_flags (a list of plain-English reasons)
        - verdict ("Safe", "Suspicious", or "Malicious")
        - action (what to do next)
    """
    red_flags = []
    links = find_links(text)
    keywords = find_suspicious_keywords(text)

    if keywords:
        red_flags.append(
            f"Found {len(keywords)} suspicious keyword(s): {', '.join(keywords)}"
        )
    suspicious_links = []
    for link in links:
        reasons = check_link_tricks(link)
        if reasons:
            suspicious_links.append(link)
            red_flags.append(f"Suspicious link '{link}' -> {', '.join(reasons)}")

    brand_reasons = check_brand_mismatch(text, links)
    red_flags.extend(brand_reasons)

    score = 0
    score += len(keywords) * 10
    score += len(suspicious_links) * 25
    score += len(brand_reasons) * 25

    if score >= 50:
        verdict = "Malicious"
        action = "Block the link/domain and report this to your security team."
    elif score >= 15:
        verdict = "Suspicious"
        action = "Do not click anything. Verify with the sender through another channel."
    else:
        verdict = "Safe"
        action = "No action needed, but stay alert."

    return {
        "links_found": links,
        "suspicious_links": suspicious_links,
        "keywords_found": keywords,
        "red_flags": red_flags,
        "score": score,
        "verdict": verdict,
        "action": action,
    }


def print_report(text, result):
    print("=" * 60)
    print("PHISHING MESSAGE ANALYSIS REPORT")
    print("=" * 60)
    print("\nOriginal message:\n" + "-" * 20)
    print(text.strip())

    print("\n1) LINKS FOUND:")
    if result["links_found"]:
        for link in result["links_found"]:
            flag = " (SUSPICIOUS)" if link in result["suspicious_links"] else ""
            print(f"   - {link}{flag}")
    else:
        print("   No links found.")

    print("\n2) SUSPICIOUS KEYWORDS FOUND:")
    if result["keywords_found"]:
        for word in result["keywords_found"]:
            print(f"   - {word}")
    else:
        print("   None found.")

    print("\n3) RED FLAGS:")
    if result["red_flags"]:
        for i, flag in enumerate(result["red_flags"], start=1):
            print(f"   {i}. {flag}")
    else:
        print("   None found.")

    print("\n4) WHY IS IT (UN)SAFE?")
    print(f"   Risk score: {result['score']} / 100")
    print(f"   Verdict   : {result['verdict']}")
    print(f"   Action    : {result['action']}")
    print("=" * 60 + "\n")


SAMPLE_MESSAGES = [
    # A clearly SAFE message
    """
    Hi Team,
    Please review the attached project status for Q3 at your earliest convenience.
    No immediate action is required.
    Thanks,
    Sarah
    """,

    # A MALICIOUS phishing example (PayPal impersonation + fake link)
    """
    Dear customer,
    We noticed unusual activity on your PayPal account.
    Please verify your account immediately by clicking the link below,
    or your account will be suspended:
    http://google-secure-login.tk/verify
    """,

    # A SUSPICIOUS example (shortened link, mild urgency)
    """
    Hi, a new event was added to your calendar.
    Please view meeting details here: http://bit.ly/3xYzQ9a
    See you there!
    """,
]

if __name__ == "__main__":
    for message in SAMPLE_MESSAGES:
        result = analyze_message(message)
        print_report(message, result)

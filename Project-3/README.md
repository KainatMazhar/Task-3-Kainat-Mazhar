# Phishing Awareness Analyzer (Simple Version)

**DecodeLabs Cyber Security - Project 3**

A beginner-friendly Python script that analyzes an email or message and:
1. **Identifies suspicious links or keywords**
2. **Lists the red flags found**
3. **Explains why the message is unsafe** (with a final verdict)

No external libraries required — just Python's built-in `re` module.

---

## How it works (in plain English)

1. It scans the message text for **suspicious keywords** (e.g. "urgent", "verify your account", "wire transfer").
2. It finds every **link** in the message and checks it for common tricks:
   - raw IP addresses instead of a domain
   - link shorteners (bit.ly, tinyurl, etc.)
   - extra "trust words" stuffed into the domain (`-secure-`, `-login-`, `-verify-`)
   - look-alike domains (e.g. `amaz0n.com`)
3. It checks for **brand impersonation** — e.g. if the message says "google" but the link doesn't
   actually go to `google.com`.
4. It adds up a **risk score** from everything it found and gives a verdict:

| Score | Verdict | What to do |
|---|---|---|
| 0–14 | **Safe** | No action needed |
| 15–49 | **Suspicious** | Don't click, verify with the sender another way |
| 50+ | **Malicious** | Block it and report to your security team |

---

## How to run it

You need **Python 3** installed. Nothing else to install.

```bash
python phishing_checker.py
```

That's it! It will run 3 built-in sample messages (one safe, one suspicious, one malicious) and print
a full report for each.

### Testing your own message

Open `phishing_checker.py`, scroll to the bottom, and uncomment these two lines:

```python
my_message = input("Paste a message to analyze:\n")
result = analyze_message(my_message)
print_report(my_message, result)
```

Then run it again and paste in any email or text message you want to check.

---

## Example output

```
============================================================
PHISHING MESSAGE ANALYSIS REPORT
============================================================

Original message:
--------------------
Dear customer,
We noticed unusual activity on your google account.
Please verify your account immediately by clicking the link below,
or your account will be suspended:
http://google-secure-login.tk/verify

1) LINKS FOUND:
   - http://google-secure-login.tk/verify (SUSPICIOUS)

2) SUSPICIOUS KEYWORDS FOUND:
   - immediately
   - verify your account
   - suspended
   - unusual activity

3) RED FLAGS:
   1. Found 4 suspicious keyword(s): immediately, verify your account, suspended, unusual activity
   2. Suspicious link 'http://google-secure-login.tk/verify' -> matches risky pattern: -secure-|-login-|-verify-|-update-
   3. message mentions 'google' but no link points to its real domain (google.com)

4) WHY IS IT (UN)SAFE?
   Risk score: 90 / 100
   Verdict   : Malicious
   Action    : Block the link/domain and report this to your security team.
============================================================
```

---

## File structure

```
simple-phishing-checker/
├── phishing_checker.py   <- the whole program (one file, well commented)
└── README.md             <- this file
```

---

## How to customize it

Everything you'd want to change lives near the top of `phishing_checker.py`:

- **`SUSPICIOUS_KEYWORDS`** — add more words/phrases you want to flag
- **`TRUSTED_DOMAINS`** — add more brands and their real domains
- **`SUSPICIOUS_LINK_PATTERNS`** — add more regex patterns for link tricks
- **`SAMPLE_MESSAGES`** — add your own test messages here

---

**Key skills:** threat analysis, awareness of cyber attacks, security thinking.
# Educational examples for URL safety learning

URL_QUIZ_EXAMPLES = [
    {
        "legitimate": "https://www.paypal.com/signin",
        "phishing": "https://www.paypa1.com/signin",
        "explanation": "The phishing URL replaces 'l' with '1' - a common typosquatting technique",
        "red_flags": [
            "Character substitution (l → 1)",
            "Looks almost identical at quick glance",
            "Uses similar domain structure"
        ],
        "category": "Typosquatting"
    },
    {
        "legitimate": "https://www.amazon.com/orders",
        "phishing": "https://www.amazon-security-check.com/orders",
        "explanation": "Adds 'security-check' to make it look official, but it's a different domain",
        "red_flags": [
            "Extra hyphenated words in domain",
            "Not the official amazon.com domain",
            "Uses trust words like 'security'"
        ],
        "category": "Domain Spoofing"
    },
    {
        "legitimate": "https://www.microsoft.com/account",
        "phishing": "https://account-microsoft-verify.tk/login",
        "explanation": "Uses suspicious .tk domain and rearranges Microsoft's name",
        "red_flags": [
            "Suspicious .tk domain extension",
            "Microsoft appears in wrong position",
            "Added 'verify' keyword for urgency"
        ],
        "category": "Suspicious TLD"
    },
    {
        "legitimate": "https://secure.bankofamerica.com",
        "phishing": "http://192.168.1.100/bankofamerica/login",
        "explanation": "Uses IP address instead of domain name - major red flag",
        "red_flags": [
            "IP address used instead of domain",
            "No HTTPS encryption",
            "Bank name in URL path, not domain"
        ],
        "category": "IP Address Phishing"
    },
    {
        "legitimate": "https://www.netflix.com/browse",
        "phishing": "https://www.netflix-billing-update.com/verify-payment.php",
        "explanation": "Fake Netflix site with urgent billing update request",
        "red_flags": [
            "Added '-billing-update' to domain",
            "Suspicious 'verify-payment.php' page",
            "Creates false urgency"
        ],
        "category": "Payment Scam"
    },
    {
        "legitimate": "https://appleid.apple.com",
        "phishing": "https://apple-id-locked.com/unlock-account",
        "explanation": "Completely different domain pretending to be Apple",
        "red_flags": [
            "Not appleid.apple.com domain",
            "Uses fear tactic 'locked'",
            "Suspicious 'unlock-account' page"
        ],
        "category": "Account Takeover"
    }
]

URL_COMPARISON_EXAMPLES = [
    {
        "category": "Banking Phishing",
        "legitimate": "https://www.chase.com/personal/checking",
        "phishing": "https://chase-secure-login.tk/verify-account.php",
        "differences": [
            {
                "aspect": "Domain Name",
                "legitimate": "Official chase.com domain",
                "phishing": "Fake domain with added words",
                "risk": "HIGH"
            },
            {
                "aspect": "Domain Extension",
                "legitimate": ".com (standard for US banks)",
                "phishing": ".tk (free, commonly used for scams)",
                "risk": "HIGH"
            },
            {
                "aspect": "HTTPS Status",
                "legitimate": "✅ Secure HTTPS with valid certificate",
                "phishing": "⚠️ May have HTTPS but with invalid cert",
                "risk": "MEDIUM"
            },
            {
                "aspect": "URL Structure",
                "legitimate": "Clean, simple path",
                "phishing": "Suspicious 'verify-account.php'",
                "risk": "MEDIUM"
            }
        ]
    },
    {
        "category": "Email Service Phishing",
        "legitimate": "https://mail.google.com/mail/u/0/",
        "phishing": "https://google-account-recovery.xyz/signin.html",
        "differences": [
            {
                "aspect": "Subdomain",
                "legitimate": "mail.google.com (official subdomain)",
                "phishing": "No subdomain, fake main domain",
                "risk": "HIGH"
            },
            {
                "aspect": "Domain Extension",
                "legitimate": ".com",
                "phishing": ".xyz (cheap, often used for scams)",
                "risk": "HIGH"
            },
            {
                "aspect": "URL Keywords",
                "legitimate": "Simple 'mail' subdomain",
                "phishing": "Scary 'account-recovery' in domain",
                "risk": "MEDIUM"
            }
        ]
    },
    {
        "category": "E-commerce Phishing",
        "legitimate": "https://www.ebay.com/itm/12345",
        "phishing": "https://ebay-item-won.com/claim-prize?id=12345",
        "differences": [
            {
                "aspect": "Domain Authenticity",
                "legitimate": "Official ebay.com",
                "phishing": "Fake domain with 'item-won'",
                "risk": "HIGH"
            },
            {
                "aspect": "URL Path",
                "legitimate": "Standard /itm/ structure",
                "phishing": "Suspicious /claim-prize path",
                "risk": "HIGH"
            },
            {
                "aspect": "Emotional Trigger",
                "legitimate": "Neutral product listing",
                "phishing": "Exciting 'won' and 'prize' words",
                "risk": "MEDIUM"
            }
        ]
    }
]

# Tips for URL safety
URL_SAFETY_TIPS = {
    "basic_checks": [
        "✅ Always check for HTTPS (the padlock icon)",
        "✅ Look for misspellings in the domain name",
        "✅ Verify the domain extension (.com, .org, etc.)",
        "✅ Be suspicious of URLs with many hyphens or numbers",
        "✅ Never click shortened links (bit.ly, tinyurl) from unknown sources"
    ],
    "advanced_checks": [
        "🔍 Check the entire URL, not just the beginning",
        "🔍 Look for the real domain (it comes before the first single /)",
        "🔍 Be wary of subdomains that impersonate brands",
        "🔍 Verify URLs contain the actual company name in the domain",
        "🔍 Use WHOIS lookup to check domain registration date"
    ],
    "what_to_avoid": [
        "❌ URLs with @ symbols (hides real destination)",
        "❌ URLs with IP addresses instead of domains",
        "❌ URLs from unexpected emails or texts",
        "❌ URLs that create urgency or fear",
        "❌ URLs that promise prizes or rewards"
    ]
}

# Real-world phishing examples (anonymized)
PHISHING_CASE_STUDIES = [
    {
        "title": "PayPal Account Verification Scam",
        "phishing_url": "paypa1-secure.com/verify",
        "technique": "Typosquatting",
        "description": "Attackers replaced 'l' with '1' in PayPal. The email claimed urgent account verification needed.",
        "impact": "Victims entered credentials which were stolen",
        "lesson": "Always check spelling carefully. PayPal will never ask you to verify via email link."
    },
    {
        "title": "Fake IRS Tax Refund",
        "phishing_url": "irs-tax-refund.tk/claim",
        "technique": "Impersonation + Suspicious TLD",
        "description": "Used .tk domain to impersonate IRS. Claimed victim had pending tax refund.",
        "impact": "Collected SSN and bank account details",
        "lesson": "Government agencies use .gov domains. IRS never initiates contact via email."
    },
    {
        "title": "Amazon Prime Renewal Scam",
        "phishing_url": "amazon-primе.com/renew",
        "technique": "Unicode Character Substitution",
        "description": "Used Cyrillic 'е' instead of Latin 'e'. Looked identical but was different domain.",
        "impact": "Harvested payment card information",
        "lesson": "Copy-paste URLs into text editor to check for hidden Unicode characters."
    }
]
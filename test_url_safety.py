from utils.url_analyzer import URLAnalyzer

# Test URL extraction
text = """
Check out this deal at http://amaz0n.com/deals
or visit www.paypa1.com for payment
"""

urls = URLAnalyzer.extract_urls(text)
print("URLs found:", urls)

# Test URL analysis
for url in urls:
    result = URLAnalyzer.analyze_url_structure(url)
    print(f"\nURL: {url}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Safe: {result['is_safe']}")
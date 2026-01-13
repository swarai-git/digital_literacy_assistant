import re
import urllib.parse
from typing import List, Dict, Tuple
import tldextract
import socket

class URLAnalyzer:
    """
    Analyzes URLs for phishing patterns, suspicious characteristics,
    and extracts URLs from text.
    """
    
    # Common phishing keywords
    PHISHING_KEYWORDS = [
        'verify', 'account', 'suspended', 'locked', 'confirm', 'update',
        'secure', 'login', 'signin', 'banking', 'paypal', 'amazon',
        'ebay', 'apple', 'microsoft', 'netflix', 'suspended', 'unusual'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
        '.click', '.link', '.download', '.loan', '.win', '.bid'
    ]
    
    # Legitimate domains (whitelist)
    LEGITIMATE_DOMAINS = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com',
        'microsoft.com', 'netflix.com', 'paypal.com', 'twitter.com',
        'instagram.com', 'linkedin.com', 'youtube.com', 'github.com'
    ]
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extract all URLs from text.
        Returns list of URLs found.
        """
        # URL regex pattern
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        # Also match URLs without http/https
        simple_url_pattern = r'(?:www\.|[a-zA-Z0-9-]+\.)[a-zA-Z]{2,}(?:/[^\s]*)?'
        
        urls = re.findall(url_pattern, text)
        simple_urls = re.findall(simple_url_pattern, text)
        
        # Add http:// to simple URLs
        for url in simple_urls:
            if not url.startswith(('http://', 'https://')):
                urls.append('http://' + url)
            else:
                urls.append(url)
        
        return list(set(urls))  # Remove duplicates
    
    @staticmethod
    def analyze_url_structure(url: str) -> Dict:
        """
        Analyze URL structure for suspicious patterns.
        Returns dict with risk score and red flags.
        """
        risk_score = 0
        red_flags = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            extracted = tldextract.extract(url)
            
            domain = extracted.domain
            suffix = extracted.suffix
            subdomain = extracted.subdomain
            full_domain = f"{domain}.{suffix}"
            
            # 1. Check for IP address instead of domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                risk_score += 30
                red_flags.append({
                    "flag": "IP Address Used",
                    "severity": "high",
                    "explanation": "Legitimate sites use domain names, not raw IP addresses"
                })
            
            # 2. Check URL length (phishing URLs are often very long)
            if len(url) > 75:
                risk_score += 15
                red_flags.append({
                    "flag": "Unusually Long URL",
                    "severity": "medium",
                    "explanation": f"URL is {len(url)} characters long. Phishing URLs are often excessively long."
                })
            
            # 3. Check for suspicious TLD
            if f".{suffix}" in URLAnalyzer.SUSPICIOUS_TLDS:
                risk_score += 20
                red_flags.append({
                    "flag": f"Suspicious Domain Extension (.{suffix})",
                    "severity": "medium",
                    "explanation": f".{suffix} domains are commonly used in phishing attacks"
                })
            
            # 4. Check for @ symbol (hides real domain)
            if '@' in url:
                risk_score += 35
                red_flags.append({
                    "flag": "@ Symbol in URL",
                    "severity": "high",
                    "explanation": "The @ symbol can hide the real destination domain"
                })
            
            # 5. Check for excessive subdomains
            if subdomain and subdomain.count('.') > 2:
                risk_score += 20
                red_flags.append({
                    "flag": "Too Many Subdomains",
                    "severity": "medium",
                    "explanation": f"Multiple subdomains ({subdomain}) can indicate domain spoofing"
                })
            
            # 6. Check for HTTPS
            if parsed.scheme != 'https':
                risk_score += 10
                red_flags.append({
                    "flag": "No HTTPS Encryption",
                    "severity": "low",
                    "explanation": "URL doesn't use secure HTTPS protocol"
                })
            
            # 7. Check for phishing keywords in domain
            domain_lower = full_domain.lower()
            found_keywords = [kw for kw in URLAnalyzer.PHISHING_KEYWORDS if kw in domain_lower]
            if found_keywords:
                risk_score += 15
                red_flags.append({
                    "flag": "Suspicious Keywords in Domain",
                    "severity": "medium",
                    "explanation": f"Domain contains phishing keywords: {', '.join(found_keywords)}"
                })
            
            # 8. Check for typosquatting (misspelled legitimate domains)
            for legit_domain in URLAnalyzer.LEGITIMATE_DOMAINS:
                legit_name = legit_domain.split('.')[0]
                if URLAnalyzer._is_similar(domain.lower(), legit_name.lower()) and domain.lower() != legit_name.lower():
                    risk_score += 40
                    red_flags.append({
                        "flag": f"Possible Typosquatting",
                        "severity": "high",
                        "explanation": f"Domain '{domain}' looks similar to '{legit_name}' - possible impersonation"
                    })
                    break
            
            # 9. Check for excessive hyphens or numbers
            if domain.count('-') > 2:
                risk_score += 10
                red_flags.append({
                    "flag": "Many Hyphens in Domain",
                    "severity": "low",
                    "explanation": "Excessive hyphens can indicate a fake domain"
                })
            
            # 10. Check if domain is in whitelist
            if full_domain.lower() in URLAnalyzer.LEGITIMATE_DOMAINS:
                risk_score = max(0, risk_score - 30)
                red_flags.append({
                    "flag": "Known Legitimate Domain",
                    "severity": "low",
                    "explanation": f"{full_domain} is a recognized legitimate domain"
                })
            
            # Cap risk score at 100
            risk_score = min(100, risk_score)
            
            return {
                "url": url,
                "domain": full_domain,
                "subdomain": subdomain,
                "scheme": parsed.scheme,
                "risk_score": risk_score,
                "red_flags": red_flags,
                "is_safe": risk_score < 40
            }
            
        except Exception as e:
            return {
                "url": url,
                "error": f"Failed to parse URL: {str(e)}",
                "risk_score": 50,
                "red_flags": [{
                    "flag": "Malformed URL",
                    "severity": "medium",
                    "explanation": "URL structure appears invalid or malformed"
                }],
                "is_safe": False
            }
    
    @staticmethod
    def _is_similar(str1: str, str2: str, threshold: float = 0.7) -> bool:
        """
        Check if two strings are similar (for typosquatting detection).
        Uses simple character-based similarity.
        """
        if str1 == str2:
            return False
        
        # Check if one contains the other
        if str1 in str2 or str2 in str1:
            return True
        
        # Check Levenshtein-like similarity
        max_len = max(len(str1), len(str2))
        if max_len == 0:
            return False
        
        differences = sum(c1 != c2 for c1, c2 in zip(str1, str2))
        differences += abs(len(str1) - len(str2))
        
        similarity = 1 - (differences / max_len)
        return similarity >= threshold
    
    @staticmethod
    def get_url_info(url: str) -> Dict:
        """
        Get additional information about URL (DNS, port scan, etc.)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            # Try to resolve domain
            try:
                ip_address = socket.gethostbyname(domain)
                dns_resolved = True
            except socket.gaierror:
                ip_address = None
                dns_resolved = False
            
            return {
                "dns_resolved": dns_resolved,
                "ip_address": ip_address,
                "domain": domain
            }
        except Exception as e:
            return {
                "dns_resolved": False,
                "error": str(e)
            }
    
    @staticmethod
    def batch_analyze_urls(urls: List[str]) -> List[Dict]:
        """
        Analyze multiple URLs at once.
        Returns list of analysis results.
        """
        results = []
        for url in urls:
            analysis = URLAnalyzer.analyze_url_structure(url)
            results.append(analysis)
        return results
import requests
import os
from typing import List, Dict

class SafeBrowsingChecker:
    """
    Interface with Google Safe Browsing API to check URL safety.
    Detects malware, phishing, unwanted software, and social engineering.
    """
    
    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    # Threat types to check
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
    ]
    
    # Platform types
    PLATFORM_TYPES = ["ANY_PLATFORM"]
    
    # Threat entry types
    THREAT_ENTRY_TYPES = ["URL"]
    
    def __init__(self, api_key: str = None):
        """
        Initialize with Google Safe Browsing API key.
        If no key provided, tries to get from environment.
        """
        self.api_key = api_key or os.getenv("SAFE_BROWSING_API_KEY")
        
        if not self.api_key:
            raise ValueError(
                "Safe Browsing API key not found. "
                "Set SAFE_BROWSING_API_KEY in .env or pass api_key parameter"
            )
    
    def check_url(self, url: str) -> Dict:
        """
        Check a single URL against Google Safe Browsing database.
        Returns threat information if found.
        """
        return self.check_urls([url])
    
    def check_urls(self, urls: List[str]) -> Dict:
        """
        Check multiple URLs against Google Safe Browsing database.
        
        Returns:
            Dict with structure:
            {
                "safe": bool,
                "threats": List of threat matches,
                "checked_urls": List of URLs checked,
                "error": str (if any)
            }
        """
        if not urls:
            return {
                "safe": True,
                "threats": [],
                "checked_urls": [],
                "error": "No URLs provided"
            }
        
        try:
            # Prepare request payload
            payload = {
                "client": {
                    "clientId": "digital-literacy-assistant",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.THREAT_TYPES,
                    "platformTypes": self.PLATFORM_TYPES,
                    "threatEntryTypes": self.THREAT_ENTRY_TYPES,
                    "threatEntries": [{"url": url} for url in urls]
                }
            }
            
            # Make API request
            response = requests.post(
                f"{self.BASE_URL}?key={self.api_key}",
                json=payload,
                timeout=10
            )
            
            # Check response status
            if response.status_code != 200:
                return {
                    "safe": False,
                    "threats": [],
                    "checked_urls": urls,
                    "error": f"API Error: {response.status_code} - {response.text}"
                }
            
            # Parse response
            data = response.json()
            
            # Check for matches
            matches = data.get("matches", [])
            
            if not matches:
                return {
                    "safe": True,
                    "threats": [],
                    "checked_urls": urls,
                    "message": "No threats detected"
                }
            
            # Format threat information
            threats = []
            for match in matches:
                threat_type = match.get("threatType", "UNKNOWN")
                platform_type = match.get("platformType", "UNKNOWN")
                threat_url = match.get("threat", {}).get("url", "")
                
                threats.append({
                    "url": threat_url,
                    "threat_type": self._format_threat_type(threat_type),
                    "platform": platform_type,
                    "severity": self._get_severity(threat_type),
                    "description": self._get_threat_description(threat_type)
                })
            
            return {
                "safe": False,
                "threats": threats,
                "checked_urls": urls,
                "message": f"Found {len(threats)} threat(s)"
            }
            
        except requests.exceptions.Timeout:
            return {
                "safe": False,
                "threats": [],
                "checked_urls": urls,
                "error": "Request timeout - Safe Browsing API did not respond"
            }
        except requests.exceptions.RequestException as e:
            return {
                "safe": False,
                "threats": [],
                "checked_urls": urls,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            return {
                "safe": False,
                "threats": [],
                "checked_urls": urls,
                "error": f"Unexpected error: {str(e)}"
            }
    
    @staticmethod
    def _format_threat_type(threat_type: str) -> str:
        """Format threat type for display"""
        formatting = {
            "MALWARE": "Malware",
            "SOCIAL_ENGINEERING": "Phishing/Social Engineering",
            "UNWANTED_SOFTWARE": "Unwanted Software",
            "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful"
        }
        return formatting.get(threat_type, threat_type)
    
    @staticmethod
    def _get_severity(threat_type: str) -> str:
        """Get severity level for threat type"""
        severity_map = {
            "MALWARE": "high",
            "SOCIAL_ENGINEERING": "high",
            "UNWANTED_SOFTWARE": "medium",
            "POTENTIALLY_HARMFUL_APPLICATION": "medium"
        }
        return severity_map.get(threat_type, "medium")
    
    @staticmethod
    def _get_threat_description(threat_type: str) -> str:
        """Get human-readable description of threat"""
        descriptions = {
            "MALWARE": "This site may install malicious software that can harm your computer or steal your data",
            "SOCIAL_ENGINEERING": "This site may be a phishing attempt trying to steal your passwords or personal information",
            "UNWANTED_SOFTWARE": "This site may try to install unwanted software on your device",
            "POTENTIALLY_HARMFUL_APPLICATION": "This site may contain potentially harmful applications"
        }
        return descriptions.get(threat_type, "This site has been flagged as potentially dangerous")
    
    def get_api_status(self) -> Dict:
        """
        Check if API key is valid and service is accessible.
        Returns status information.
        """
        try:
            # Test with a known safe URL
            result = self.check_url("https://www.google.com")
            
            if "error" in result:
                return {
                    "status": "error",
                    "message": result["error"]
                }
            
            return {
                "status": "ok",
                "message": "Safe Browsing API is working correctly"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to connect: {str(e)}"
            }
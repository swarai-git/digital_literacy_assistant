import re

class SimpleLanguageProcessor:
    def detect_mixed_language(self, text):
        """
        Simple detection for English + Hindi + Marathi
        Returns: {'en': count, 'hi': count, 'mr': count}
        """
        result = {'en': 0, 'hi': 0, 'mr': 0}
        
        # Split into words
        words = text.split()
        
        for word in words:
            # Check if word has Devanagari (Hindi/Marathi)
            if re.search(r'[\u0900-\u097F]', word):
                # Simple check - if it contains common Marathi ending "े" or "ो"
                if 'े' in word or 'ो' in word:  # Common in Marathi
                    result['mr'] += 1
                else:
                    result['hi'] += 1
            # Check if word is English (only A-Z, a-z)
            elif re.match(r'^[A-Za-z]+$', word):
                result['en'] += 1
            # Mixed word (like "helloकैसे")
            elif re.search(r'[A-Za-z]', word) and re.search(r'[\u0900-\u097F]', word):
                result['en'] += 0.5
                result['hi'] += 0.5  # Count as both
        
        return result
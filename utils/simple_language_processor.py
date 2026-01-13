import re

class SimpleLanguageProcessor:
    """
    Very lightweight mixed-language detector
    Supports English, Hindi (Devanagari), Marathi (Devanagari)
    """

    def detect_mixed_language(self, text):
        words = re.findall(r'\w+', text.lower())

        counts = {
            "en": 0,
            "hi": 0,
            "mr": 0
        }

        for word in words:
            # Hindi / Marathi (Devanagari Unicode range)
            if re.search(r'[\u0900-\u097F]', word):
                # We count both as regional language
                counts["hi"] += 1
                counts["mr"] += 1
            else:
                # English (basic heuristic)
                if re.search(r'[a-z]', word):
                    counts["en"] += 1

        return counts

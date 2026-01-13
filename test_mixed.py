from utils.indian_language_processor import SimpleLanguageProcessor

processor = SimpleLanguageProcessor()

test_messages = [
    "Hello kaise ho",  # Hinglish
    "Hi, tumhi kase ahat",  # Marathi-English
    "यह स्पैम message है",  # Hindi-English
    "Spam message आहे",  # Marathi-English
    "Hello world",  # English only
    "नमस्ते दुनिया",  # Hindi only
]

for msg in test_messages:
    counts = processor.detect_mixed_language(msg)
    print(f"{msg}")
    print(f"  English: {counts['en']}, Hindi: {counts['hi']}, Marathi: {counts['mr']}")
    print()
    
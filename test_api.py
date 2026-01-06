import google.genai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

print("=== Testing API Key ===")
print(f"API Key loaded: {os.getenv('GEMINI_API_KEY')[:10]}...")

print("\n=== Available Models ===")
for m in genai.list_models():
    if 'generateContent' in m.supported_generation_methods:
        print(f"✓ {m.name}")
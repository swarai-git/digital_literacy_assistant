# utils/gemini_utils.py
import os
from google import genai

# Initialize client using API key from env
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def assess_risk(message_text, user_type, message_source, spam_result):
    prompt = f"""
You are a cybersecurity assistant.

Message:
"{message_text}"

Spam detection result:
Label: {spam_result['label']}
Confidence: {spam_result['confidence']}%

User type:
{user_type}

Message source:
{message_source}

Task:
1. Assess the risk level (Low / Medium / High) specifically for this user type.
2. Explain why this message is dangerous in simple language.
3. Give 1 clear recommendation.

Keep the response short, practical, and user-friendly.
"""
    response = client.generate_text(model="gemini-text-2.1", prompt=prompt)
    return response.text.strip()


def generate_safe_reply(message_text, spam_result):
    prompt = f"""
You are a digital safety assistant.

Message:
"{message_text}"

Message type:
{spam_result['label']}

Task:
Generate a short, calm, and safe reply that:
- Does not reveal personal information
- Does not provoke the sender
- Clearly refuses engagement

Reply should sound natural and polite.
"""
    response = client.generate_text(model="gemini-text-2.1", prompt=prompt)
    return response.text.strip()

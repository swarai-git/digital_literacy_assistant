
import os
import pickle

# Absolute path to this file's directory (ml/)
BASE_DIR = os.path.dirname(__file__)

MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")

model = pickle.load(open(MODEL_PATH, "rb"))
vectorizer = pickle.load(open(VECTORIZER_PATH, "rb"))

def predict_message(text):
    vec = vectorizer.transform([text])
    probs = model.predict_proba(vec)[0]
    label = model.classes_[probs.argmax()]
    confidence = round(max(probs) * 100, 2)
    return label, confidence

import os
import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

from scipy.sparse import hstack

# 👇 import your language detector
from utils.simple_language_processor import SimpleLanguageProcessor


# ================= PATHS =================
BASE_DIR = os.path.dirname(__file__)

DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")


# ================= LANGUAGE FEATURES =================
def add_language_features(df):
    """
    Adds English, Hindi, Marathi word counts as numeric features
    """
    processor = SimpleLanguageProcessor()

    en_words = []
    hi_words = []
    mr_words = []

    for text in df["message"]:
        counts = processor.detect_mixed_language(str(text))
        en_words.append(counts.get("en", 0))
        hi_words.append(counts.get("hi", 0))
        mr_words.append(counts.get("mr", 0))

    df["en_words"] = en_words
    df["hi_words"] = hi_words
    df["mr_words"] = mr_words

    return df


# ================= LOAD DATA =================
df = pd.read_csv(DATASET_PATH)

# Add language features
df = add_language_features(df)

X_text = df["message"]
X_lang = df[["en_words", "hi_words", "mr_words"]]
y = df["label"]


# ================= SPLIT =================
X_text_train, X_text_test, X_lang_train, X_lang_test, y_train, y_test = train_test_split(
    X_text,
    X_lang,
    y,
    test_size=0.2,
    random_state=42
)


# ================= TF-IDF =================
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000,
    ngram_range=(1, 2)
)

X_text_train_vec = vectorizer.fit_transform(X_text_train)
X_text_test_vec = vectorizer.transform(X_text_test)


# ================= COMBINE FEATURES =================
X_train_final = hstack([X_text_train_vec, X_lang_train.values])
X_test_final = hstack([X_text_test_vec, X_lang_test.values])


# ================= MODEL =================
model = LogisticRegression(max_iter=1000)
model.fit(X_train_final, y_train)


# ================= EVALUATION =================
y_pred = model.predict(X_test_final)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))


# ================= SAVE =================
pickle.dump(model, open(MODEL_PATH, "wb"))
pickle.dump(vectorizer, open(VECTORIZER_PATH, "wb"))

print("✅ model.pkl and vectorizer.pkl saved in ml/")

import pandas as pd

# Load raw dataset
df = pd.read_csv("spam.csv", encoding="latin-1")

# Keep only needed columns
df = df[["v1", "v2"]]
df.columns = ["label", "message"]

# Convert labels
df["label"] = df["label"].map({
    "spam": "scam",
    "ham": "safe"
})

# Save cleaned dataset
df.to_csv("dataset.csv", index=False)

print("✅ dataset.csv created successfully")

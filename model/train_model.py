import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset (replace 'cyber_data.csv' with actual data)
df = pd.read_csv("cyber_data.csv")

# Feature selection
X = df.drop("threat_label", axis=1)
y = df["threat_label"]

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "model/model.pkl")
print("Model trained and saved successfully!")

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report

# Load cleaned dataset
data_path = "dataset/cleaned_data.csv"  
df = pd.read_csv(data_path)

# Assuming the last column is the label (modify if needed)
X = df.select_dtypes(include=['number']).iloc[:, :-1]  
y = df.iloc[:, -1]  

# Convert target to categorical labels 
if y.dtype == 'float64' or y.dtype == 'int64':
    y = y.astype('category').cat.codes  

# Split data into Training (80%) and Testing (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🔹 Apply Feature Scaling (For SVM)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Initialize models
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
svm_model = SVC(kernel='rbf', C=10, gamma='scale', probability=True) 

# Train Random Forest
print("Training Random Forest...")
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_preds)
print(f"Random Forest Accuracy: {rf_accuracy:.4f}")
print(classification_report(y_test, rf_preds, zero_division=1))

# Train SVM 
print("\nTraining SVM...")
svm_model.fit(X_train_scaled, y_train)
svm_preds = svm_model.predict(X_test_scaled)
svm_accuracy = accuracy_score(y_test, svm_preds)
print(f"SVM Accuracy: {svm_accuracy:.4f}")
print(classification_report(y_test, svm_preds, zero_division=1)) 

# Save the best model
if rf_accuracy > svm_accuracy:
    best_model = rf_model
    model_name = "random_forest_model.pkl"
    print("\nSaving Random Forest as the best model.")
else:
    best_model = svm_model
    model_name = "svm_model.pkl"
    print("\nSaving SVM as the best model.")

# Ensure the directory exists
os.makedirs("ml_model", exist_ok=True)

# Save the model
joblib.dump(best_model, f"ml_model/{model_name}")
print(f"Model saved as ml_model/{model_name}")

# Load the trained Random Forest model
model = joblib.load("ml_model/random_forest_model.pkl")

# Get feature importances
feature_importances = model.feature_importances_
feature_names = df.select_dtypes(include=['number']).columns[:-1]

# Create a DataFrame for feature importances
importance_df = pd.DataFrame({
    'feature': feature_names,
    'importance': feature_importances
})


top_10_features = importance_df.sort_values(by='importance', ascending=False).head(10)['feature'].tolist()
print("Top 10 features:", top_10_features)

df_top_10 = df[top_10_features + [df.columns[-1]]]

df_top_10.to_csv("dataset/cleaned_data_top_10.csv", index=False)

data_path = "dataset/cleaned_data_top_10.csv"
df = pd.read_csv(data_path)

# Assuming the last column is the label (modify if needed)
X = df.iloc[:, :-1] 
y = df.iloc[:, -1]

# Convert target to categorical labels 
if y.dtype == 'float64' or y.dtype == 'int64':
    y = y.astype('category').cat.codes  

# Split data into Training (80%) and Testing (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🔹 Apply Feature Scaling (For SVM)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Initialize models
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
svm_model = SVC(kernel='rbf', C=10, gamma='scale', probability=True) 

# Train Random Forest
print("Training Random Forest...")
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_preds)
print(f"Random Forest Accuracy: {rf_accuracy:.4f}")
print(classification_report(y_test, rf_preds, zero_division=1))

# Train SVM 
print("\nTraining SVM...")
svm_model.fit(X_train_scaled, y_train)
svm_preds = svm_model.predict(X_test_scaled)
svm_accuracy = accuracy_score(y_test, svm_preds)
print(f"SVM Accuracy: {svm_accuracy:.4f}")
print(classification_report(y_test, svm_preds, zero_division=1)) 

# Save the best model
if rf_accuracy > svm_accuracy:
    best_model = rf_model
    model_name = "random_forest_model_top_10.pkl"
    print("\nSaving Random Forest as the best model.")
else:
    best_model = svm_model
    model_name = "svm_model_top_10.pkl"
    print("\nSaving SVM as the best model.")

os.makedirs("ml_model", exist_ok=True)

# Save the model
joblib.dump(best_model, f"ml_model/{model_name}")
print(f"Model saved as ml_model/{model_name}")

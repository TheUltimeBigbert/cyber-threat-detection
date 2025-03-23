import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# =======================
#  Data Preprocessing
# =======================
def load_and_preprocess_data(data_path, sample_fraction=0.5):
    """Loads and preprocesses dataset while retaining IP addresses and attack labels."""
    df = pd.read_csv(data_path, dtype=str)

    # Explicitly define IP columns
    ip_columns = ["Source_IP", "Destination_IP"]
    
    # Convert numeric columns while keeping IPs intact
    df = df.apply(lambda x: pd.to_numeric(x, errors='coerce') 
                  if x.name not in ip_columns and x.name.lower() not in ["attack", "label", "class", "attack type"] else x)

    possible_attack_columns = ["Label"]
    attack_column = next((col for col in possible_attack_columns if col in df.columns), None)

    if attack_column is None:
        print(f"Columns found: {df.columns}")
        raise ValueError("Attack label column not found in dataset.")

    df["original_attack_label"] = df[attack_column]

    # Ensure IP columns are treated as strings
    df[ip_columns] = df[ip_columns].astype(str)

    # Exclude non-numeric columns except IPs and attack label
    non_numeric_columns = df.select_dtypes(exclude=["number"]).columns.tolist()
    non_numeric_columns.remove(attack_column)

    df_numeric = df.drop(columns=[col for col in non_numeric_columns if col not in ip_columns], errors='ignore')

    # Sample dataset while keeping IPs and attack labels
    df_sampled = df.sample(frac=sample_fraction, random_state=42)

    # Select only numeric columns for `X`
    numeric_columns = df_sampled.select_dtypes(include=["number"]).columns.tolist()
    X = df_sampled[numeric_columns]

    y = df_sampled[attack_column].astype(str)  # Ensure y is correctly sampled

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    return X, y_encoded, df_sampled, le, attack_column, ip_columns  # Return df_sampled instead of df

# =======================
#  Train-Test Split & Scaling
# =======================
def split_and_scale_data(X, y, ip_columns):
    """Splits dataset and applies scaling for SVM while excluding non-numeric columns."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Ensure NaN values are replaced with 0
    X_train = X_train.fillna(0).copy()
    X_test = X_test.fillna(0).copy()

    # Select only numeric columns (excluding IPs and other non-numeric features)
    numeric_columns = X_train.select_dtypes(include=["number"]).columns.tolist()

    X_train_numeric = X_train[numeric_columns]
    X_test_numeric = X_test[numeric_columns]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_numeric)
    X_test_scaled = scaler.transform(X_test_numeric)

    return X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled, scaler

# =======================
#  Model Training & Evaluation
# =======================
def train_and_evaluate(X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test, le):
    """Trains and evaluates both models (Random Forest and SVM)"""
    rf_model = RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1, random_state=42)
    svm_model = SVC(kernel='rbf', C=10, gamma='scale', probability=True, max_iter=1000)

    print("\nTraining Random Forest...")
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_accuracy = accuracy_score(y_test, rf_preds)
    print(f"Random Forest Accuracy: {rf_accuracy:.4f}")
    print(classification_report(y_test, rf_preds, target_names=le.classes_, zero_division=1))

    if len(np.unique(y_train)) > 1:
        print("\nTraining SVM...")
        svm_model.fit(X_train_scaled, y_train)
        svm_preds = svm_model.predict(X_test_scaled)
        svm_accuracy = accuracy_score(y_test, svm_preds)
        print(f"SVM Accuracy: {svm_accuracy:.4f}")
        print(classification_report(y_test, svm_preds, target_names=le.classes_, zero_division=1))
    else:
        print("\nSkipping SVM training as only one class exists in the target variable.")
        svm_accuracy = 0

    best_model, model_name = (rf_model, "random_forest_model.pkl") if rf_accuracy > svm_accuracy else (svm_model, "svm_model.pkl")
    os.makedirs("ml_model", exist_ok=True)
    joblib.dump(best_model, f"ml_model/{model_name}")
    print(f"\nBest model saved as ml_model/{model_name}")

    return best_model, model_name

# =======================
#  Prediction with Real Labels
# =======================
def predict_and_display(model, X_test, le, df_test, ip_columns):
    """Predicts and merges predictions back with original IPs and labels."""
    preds = model.predict(X_test)
    decoded_preds = le.inverse_transform(preds)

    df_results = df_test.copy()
    df_results["predicted_attack_label"] = decoded_preds

    return df_results[ip_columns + ["original_attack_label", "predicted_attack_label"]]

# =======================
#  Main Execution
# =======================
if __name__ == "__main__":
    # Load and preprocess full dataset (sample 50% to speed up training)
    full_data_path = "dataset/cleaned_merged_data_limited.csv"
    X, y_encoded, df, le, attack_column, ip_columns = load_and_preprocess_data(full_data_path, sample_fraction=0.5)

    if X.empty or len(y_encoded) == 0:
        raise ValueError("Dataset is empty or preprocessing failed.")

    # Pass ip_columns to split_and_scale_data
    X_train, X_test, y_train, y_test, X_train_scaled, X_tKest_scaled, scaler = split_and_scale_data(X, y_encoded, ip_columns)

    best_model, best_model_name = train_and_evaluate(X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test, le)

    df_results = predict_and_display(best_model, X, le, df, ip_columns)

    output_file = "dataset/cleaned_data_with_details.csv"
    df_results.to_csv(output_file, index=False)
    print(f"\nSaved processed data with predictions to: {output_file}")

    print("\n** Process Completed **")

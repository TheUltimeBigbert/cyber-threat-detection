import os
import pandas as pd
import numpy as np
import joblib
import json  # Import json library
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# =======================
#  Data Preprocessing
# =======================
def determine_severity(row):
    """
    Determine attack severity based on both attack type and flow characteristics.
    Benign traffic is always Low severity as it represents normal network activity.
    """
    # Get attack type and normalize it
    attack_type = str(row.get('label', '') or row.get('original_attack_label', '')).strip().lower()

    # BENIGN traffic is ALWAYS Low severity - no exceptions
    if 'benign' in attack_type:
        return 'Low'

    # Define critical attack types that should always be high severity
    CRITICAL_ATTACKS = {
        'sql injection', 'command injection', 'xss', 'backdoor', 
        'privilege escalation', 'web attack sql injection', 'web attack xss',
        'infiltration', 'heartbleed', 'botnet', 'brute force', 'ddos'
    }

    # Define medium severity attacks
    MEDIUM_ATTACKS = {
        'port scan', 'nmap scan', 'slowloris', 'dos goldeneye', 'dos hulk',
        'dos slowhttptest', 'dos slowloris', 'ftp-patator', 'ssh-patator'
    }

    # If it's a critical attack type, return High severity immediately
    if any(critical in attack_type.lower() for critical in CRITICAL_ATTACKS):
        return 'High'

    # If it's a medium severity attack, return Medium
    if any(medium in attack_type.lower() for medium in MEDIUM_ATTACKS):
        return 'Medium'

    # Safely get values, defaulting to 0 if missing or not numeric
    def safe_float(value, default=0.0):
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # Basic flow characteristics
    flow_duration = safe_float(row.get('flow_duration'))
    fwd_packets = safe_float(row.get('total_fwd_packets'))
    bwd_packets = safe_float(row.get('total_backward_packets'))
    fwd_bytes = safe_float(row.get('total_length_of_fwd_packets'))
    bwd_bytes = safe_float(row.get('total_length_of_bwd_packets'))
    total_bytes = fwd_bytes + bwd_bytes
    total_packets = fwd_packets + bwd_packets
    
    # Calculate average packet size
    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

    # Get flow timing characteristics
    flow_iat_mean = safe_float(row.get('flow_iat_mean', 0))
    active_mean = safe_float(row.get('active_mean', 0))
    idle_mean = safe_float(row.get('idle_mean', 0))
    
    # Calculate timing ratios
    active_idle_ratio = active_mean / idle_mean if idle_mean > 0 else float('inf')
    
    # Get flag counts
    fwd_psh_flags = safe_float(row.get('fwd_psh_flags'))
    bwd_psh_flags = safe_float(row.get('bwd_psh_flags'))
    psh_flags = fwd_psh_flags + bwd_psh_flags
    fwd_urg_flags = safe_float(row.get('fwd_urg_flags'))
    bwd_urg_flags = safe_float(row.get('bwd_urg_flags'))
    urg_flags = fwd_urg_flags + bwd_urg_flags
    
    # Get rate-based features
    packets_per_second = safe_float(row.get('flow_packets/s'))
    bytes_per_second = safe_float(row.get('flow_bytes/s'))

    # Initialize severity score
    severity_score = 0

    # Score based on packet characteristics
    if avg_packet_size > 1500:  # Large packets might indicate exfiltration
        severity_score += 2
    elif avg_packet_size > 1000:
        severity_score += 1

    # Score based on timing patterns
    if flow_iat_mean > 1000000:  # High inter-arrival time might indicate scanning
        severity_score += 2
    elif flow_iat_mean > 500000:
        severity_score += 1

    if active_idle_ratio > 10:  # Frequent switching between active/idle
        severity_score += 2
    elif active_idle_ratio > 5:
        severity_score += 1

    # Score based on traditional flow characteristics
    if ((flow_duration < 100000 and (fwd_packets > 100 or bwd_packets > 100)) or
        (flow_duration > 1000000 and (fwd_packets > 1000 or bwd_packets > 1000))):
        severity_score += 3

    if bytes_per_second > 1000000:
        severity_score += 3
    elif bytes_per_second > 500000:
        severity_score += 2

    if packets_per_second > 1000:
        severity_score += 3
    elif packets_per_second > 500:
        severity_score += 2

    if psh_flags > 50 or urg_flags > 50:
        severity_score += 2
    elif psh_flags > 25 or urg_flags > 25:
        severity_score += 1

    # Determine final severity based on score
    if severity_score >= 8:
        return 'High'
    elif severity_score >= 4:
        return 'Medium'
    else:
        return 'Low'

def load_and_preprocess_data(data_path, sample_fraction=0.8):  # Increased sample fraction
    """Loads and preprocesses dataset, ensuring necessary columns are numeric."""
    df = pd.read_csv(data_path, low_memory=False)

    print(f"Initial columns: {df.columns.tolist()}")
    print(f"Dataset shape: {df.shape}")
    
    # Print initial distribution of attack types
    attack_column = next((col for col in ["label", "attack_type", "class", "attack"] if col in df.columns), None)
    if attack_column:
        print("\nInitial attack type distribution:")
        print(df[attack_column].value_counts())

    # Define IP columns and essential original feature columns
    ip_columns = ["source_ip", "destination_ip"]
    # Columns needed for severity calculation and model training
    required_feature_cols = [
        'flow_duration', 'total_fwd_packets', 'total_backward_packets',
        'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
        'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
        'flow_packets/s', 'flow_bytes/s'
    ]
    # Find the attack label column
    possible_attack_columns = ["label", "attack_type", "class", "attack"]
    attack_column = next((col for col in possible_attack_columns if col in df.columns), None)
    if attack_column is None:
        raise ValueError(f"Attack label column not found in {possible_attack_columns}. Columns present: {df.columns.tolist()}")

    # Columns to keep initially (IPs, features, label)
    cols_to_keep = ip_columns + required_feature_cols + [attack_column]
    # Filter out columns not present in the dataframe
    existing_cols_to_keep = [col for col in cols_to_keep if col in df.columns]
    missing_cols = set(cols_to_keep) - set(existing_cols_to_keep)
    if missing_cols:
        print(f"Warning: The following required columns are missing and will be ignored: {missing_cols}")

    df = df[existing_cols_to_keep].copy() # Work with a copy of the essential columns
    print(f"Columns after initial filtering: {df.columns.tolist()}")

    # Convert feature columns to numeric, coercing errors and filling NaNs
    print("Converting feature columns to numeric...")
    for col in required_feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            # Replace infinite values with NaN, then fill NaNs
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            df[col] = df[col].fillna(0)
            print(f"Processed column: {col}, dtype: {df[col].dtype}")
        else:
            # If a required column was missing from the start, add it with zeros
             print(f"Adding missing required column '{col}' with zeros.")
             df[col] = 0.0

    # Ensure IP columns are strings
    for col in ip_columns:
        if col in df.columns:
            df[col] = df[col].astype(str).fillna('Unknown')

    # Keep original attack label
    df["original_attack_label"] = df[attack_column].astype(str).fillna('Unknown')

    # Calculate severity
    print("\nCalculating severity levels...")
    df["Severity"] = df.apply(determine_severity, axis=1)
    
    # Print severity distribution before and after processing
    print("\nInitial severity distribution:")
    print(df["Severity"].value_counts())
    print("\nSeverity distribution by attack type:")
    print(pd.crosstab(df[attack_column], df["Severity"]))

    # Balance the dataset while maintaining more samples
    print("\nBalancing dataset by severity...")
    severity_counts = df["Severity"].value_counts()
    
    # Calculate target samples - use a larger number but don't exceed the smallest class size
    min_samples = severity_counts.min()
    target_samples = min(max(min_samples, 1000), severity_counts.min())
    
    print(f"\nTargeting {target_samples} samples per severity level")
    
    balanced_dfs = []
    for severity in severity_counts.index:
        severity_df = df[df["Severity"] == severity]
        if len(severity_df) > target_samples:
            severity_df = severity_df.sample(n=target_samples, random_state=42)
        balanced_dfs.append(severity_df)
    
    df = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
    
    print("\nBalanced severity distribution:")
    print(df["Severity"].value_counts())
    print("\nBalanced attack type distribution:")
    print(df[attack_column].value_counts())

    # Sample a larger portion of the balanced dataset
    df_sampled = df.sample(frac=sample_fraction, random_state=42)
    print(f"\nFinal shape after sampling: {df_sampled.shape}")

    # Select features for training (use the numeric columns we processed)
    training_features = [col for col in required_feature_cols if col in df_sampled.columns]
    X = df_sampled[training_features]

    # Encode the target label
    y = df_sampled["original_attack_label"].astype(str)
    le = LabelEncoder()
    # Fit on all possible labels in the original (pre-sampled) data to handle unseen labels in test set if needed
    le.fit(df[attack_column].astype(str).fillna('Unknown'))
    y_encoded = le.transform(y)

    # Verify we have enough samples per class
    unique_classes, class_counts = np.unique(y_encoded, return_counts=True)
    min_class_count = min(class_counts)
    if min_class_count < 2:
        print(f"Warning: Some classes have too few samples (minimum: {min_class_count}). Adjusting sampling...")
        # Increase the number of samples for classes with too few members
        min_samples_per_class = 2
        balanced_dfs = []
        for class_label in unique_classes:
            class_df = df_sampled[y_encoded == class_label]
            if len(class_df) < min_samples_per_class:
                # If we have too few samples, take more from the original dataset
                original_class_df = df[df[attack_column].astype(str) == le.inverse_transform([class_label])[0]]
                if len(original_class_df) >= min_samples_per_class:
                    class_df = original_class_df.sample(n=min_samples_per_class, random_state=42)
                else:
                    print(f"Warning: Class {le.inverse_transform([class_label])[0]} has insufficient samples even in original dataset")
            balanced_dfs.append(class_df)
        df_sampled = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
        X = df_sampled[training_features]
        y_encoded = le.transform(df_sampled["original_attack_label"].astype(str))
        print(f"Final shape after class balancing: {df_sampled.shape}")

    # Return the necessary components
    return X, y_encoded, df_sampled, le, attack_column, ip_columns, training_features

# =======================
#  Train-Test Split & Scaling
# =======================
def split_and_scale_data(X, y, training_features):
    """Split data into train and test sets, and scale features."""
    # First, ensure we have enough samples in each class
    unique_classes, class_counts = np.unique(y, return_counts=True)
    min_samples = min(class_counts)
    
    if min_samples < 2:
        print("Warning: Some classes have too few samples. Adjusting test size...")
        test_size = 0.2  # Reduce test size to ensure enough samples per class
    else:
        test_size = 0.5

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    # Fill NaNs just in case (should be handled earlier, but safe)
    X_train = X_train.fillna(0)
    X_test = X_test.fillna(0)

    # Select only the numeric features specified in training_features for scaling
    X_train_numeric = X_train[training_features]
    X_test_numeric = X_test[training_features]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_numeric)
    X_test_scaled = scaler.transform(X_test_numeric)

    # Return both original and scaled sets, plus scaler
    return X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled, scaler

# =======================
#  Model Training & Evaluation
# =======================
def train_and_evaluate(X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test, le, training_features):
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42) # Adjusted params
    # Use probability=True for potential calibration or threshold tuning later
    svm_model = SVC(kernel='rbf', C=1.0, gamma='scale', probability=True, max_iter=2000, random_state=42) # Switched to RBF kernel, common for SVC

    print("\nTraining Random Forest...")
    rf_model.fit(X_train[training_features], y_train)
    rf_preds = rf_model.predict(X_test[training_features])
    rf_accuracy = accuracy_score(y_test, rf_preds)
    print(f"Random Forest Accuracy: {rf_accuracy:.4f}")
    
    # Get unique classes from both predictions and test set
    unique_preds = np.unique(rf_preds)
    unique_test = np.unique(y_test)
    all_classes = np.union1d(unique_preds, unique_test)
    
    # Create a mapping of encoded labels to their string representations
    label_mapping = {i: le.classes_[i] for i in all_classes}
    target_names = [label_mapping[i] for i in sorted(all_classes)]
    
    print(classification_report(y_test, rf_preds, labels=sorted(all_classes), target_names=target_names, zero_division=0))

    # Ensure there are multiple classes for SVM training
    if len(np.unique(y_train)) > 1:
        print("\nTraining SVM (RBF Kernel)...")
        svm_model.fit(X_train_scaled, y_train)
        svm_preds = svm_model.predict(X_test_scaled)
        svm_accuracy = accuracy_score(y_test, svm_preds)
        print(f"SVM Accuracy: {svm_accuracy:.4f}")
        print(classification_report(y_test, svm_preds, labels=sorted(all_classes), target_names=target_names, zero_division=0))
    else:
        print("\nSkipping SVM training: Only one class present.")
        svm_accuracy = 0
        svm_model = None # Indicate SVM was not trained

    # Determine the best model based on accuracy
    if svm_model is not None and svm_accuracy > rf_accuracy:
        best_model, model_name = (svm_model, "svm_model_rbf.pkl")
        print("\nSVM (RBF) is the best model.")
    else:
        best_model, model_name = (rf_model, "random_forest_model.pkl")
        print("\nRandom Forest is the best model.")

    # Save model and preprocessing objects
    os.makedirs("ml_model", exist_ok=True)
    joblib.dump(best_model, f"ml_model/{model_name}")
    joblib.dump(le, 'ml_model/label_encoder.pkl')
    joblib.dump(scaler, 'ml_model/scaler.pkl')
    joblib.dump(training_features, 'ml_model/training_features.pkl')
    print(f"Best model ('{model_name}') saved to ml_model/")
    print("LabelEncoder, Scaler, and Training Features list also saved.")

    return best_model, model_name

# =======================
#  Prediction with Details
# =======================
def predict_and_display(model, X_test_original, le, df_test, ip_columns, training_features, model_name, scaler):
    """Predicts labels and prepares final DataFrame with individual feature columns."""
    print(f"Predicting using model: {model_name}")
    # Ensure X_test_original has the correct columns and fill NaNs
    X_test_prepared = X_test_original[training_features].fillna(0)

    # Use appropriate features (scaled or original) based on the model
    if "svm" in model_name.lower():
        print("Using scaled features for SVM prediction.")
        X_test_scaled = scaler.transform(X_test_prepared)
        preds = model.predict(X_test_scaled)
    else:
        print("Using original features for Random Forest prediction.")
        preds = model.predict(X_test_prepared)

    # Decode predictions
    try:
        decoded_preds = le.inverse_transform(preds)
    except ValueError as e:
         print(f"Error decoding predictions: {e}. Check LabelEncoder classes.")
         # Handle error, e.g., assign a default value or re-raise
         decoded_preds = ['DecodingError'] * len(preds)

    # Prepare results DataFrame using the original test data indices
    df_results = df_test.loc[X_test_original.index].copy()
    df_results["predicted_attack_label"] = decoded_preds

    # Rename IP columns
    ip_mapping = {'source_ip': 'attacker_ip', 'destination_ip': 'victim_ip'}
    df_results.rename(columns={k: v for k, v in ip_mapping.items() if k in df_results.columns}, inplace=True)

    # Define final columns to save, including individual flow features
    final_output_columns = [
        'attacker_ip', 'victim_ip', 'original_attack_label',
        'predicted_attack_label', 'Severity'
    ] + training_features # Add all the numeric feature columns used

    # Ensure all desired columns exist in the results DataFrame
    for col in final_output_columns:
        if col not in df_results.columns:
            print(f"Warning: Column '{col}' missing in results, adding with default value N/A.")
            df_results[col] = 'N/A' # Add missing columns

    # Return only the specified columns in the desired order
    return df_results[final_output_columns]

# =======================
#  Main Execution
# =======================
if __name__ == "__main__":
    full_data_path = "dataset/cleaned_merged_data_limited.csv"

    # Load and preprocess data
    X, y_encoded, df_sampled, le, attack_column, ip_columns, training_features = load_and_preprocess_data(
        full_data_path, sample_fraction=0.8 # Adjust fraction as needed
    )

    if X.empty or len(y_encoded) == 0:
        raise ValueError("Data loading or preprocessing resulted in empty features (X) or labels (y).")

    # Split data and scale features
    X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled, scaler = split_and_scale_data(
        X, y_encoded, training_features
    )

    # Train and evaluate models
    best_model, best_model_name = train_and_evaluate(
        X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test, le, training_features
    )

    # Prepare data for final prediction display (using the original test set portion of df_sampled)
    df_test_original = df_sampled.loc[X_test.index]

    # Predict on the test set and format results
    df_results = predict_and_display(
        best_model, X_test, le, df_test_original, ip_columns, training_features, best_model_name, scaler
    )

    # Save the final results
    output_file = "dataset/cleaned_data_with_details.csv"
    df_results.to_csv(output_file, index=False)
    print(f"\nSaved final data with predictions and individual features to: {output_file}")
    print(f"Output columns: {df_results.columns.tolist()}")
    print("\n** Process Completed **")

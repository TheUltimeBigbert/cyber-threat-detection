import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample

# Settings
dataset_dir = "dataset"
output_file = "dataset/cleaned_merged_data_limited.csv"
max_total_samples = 500000  # Limit total dataset size
min_sample_size = 1000  # Ensures at least 1000 samples per file

# List of CSV files to process
csv_files = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", 
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv", 
    "Monday-WorkingHours.pcap_ISCX.csv", 
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", 
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv", 
    "Wednesday-workingHours.pcap_ISCX.csv"
]

# Possible names for the attack label column
possible_attack_columns = ["attack", "label", "class", "Attack Type", "Label"]

# Initialize an empty DataFrame to hold the merged data
merged_df = pd.DataFrame()

# Process each CSV file
for file_name in csv_files:
    file_path = os.path.join(dataset_dir, file_name)
    print(f"\n📂 Loading file: {file_name}")

    try:
        df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, encoding='ISO-8859-1', low_memory=False)
    
    print(f"Loaded DataFrame shape: {df.shape}")

    # Sample full dataset for each file (ensuring at least min_sample_size)
    sample_size = min(len(df), max_total_samples // len(csv_files))
    df_sampled = df.sample(n=sample_size, random_state=42)

    print(f"Sampled DataFrame shape: {df_sampled.shape}")

    if df_sampled.empty:
        print(f"⚠️ Sampled DataFrame is empty for file: {file_name}")
        continue

    # Data cleaning
    df_sampled.fillna(0, inplace=True)  # Fill missing values
    df_sampled.drop_duplicates(inplace=True)  # Remove duplicates
    df_sampled.replace([np.inf, -np.inf], 0, inplace=True)  # Handle infinite values
    
    # Normalize numerical columns
    numeric_columns = df_sampled.select_dtypes(include=['number']).columns
    if len(numeric_columns) > 0:
        scaler = StandardScaler()
        df_sampled[numeric_columns] = scaler.fit_transform(df_sampled[numeric_columns])

    # Append to the merged DataFrame
    merged_df = pd.concat([merged_df, df_sampled], ignore_index=True)

    print(f"✅ Data Preprocessing Complete for file: {file_name}")
    print(f"Current merged DataFrame shape: {merged_df.shape}")

# Limit dataset size if it exceeds max_total_samples
if len(merged_df) > max_total_samples:
    print(f"⚠️ Dataset too large ({len(merged_df)} rows), reducing to {max_total_samples} rows.")
    merged_df = merged_df.sample(n=max_total_samples, random_state=42)

# Ensure consistent column names
merged_df.columns = [col.strip().replace(" ", "_") for col in merged_df.columns]

# Identify attack label column
attack_column = next((col for col in possible_attack_columns if col in merged_df.columns), None)

if attack_column:
    print(f"Using attack column: {attack_column}")
else:
    print(f"Columns found: {merged_df.columns}")
    raise ValueError("Attack label column not found in any dataset.")

# Print class distribution before balancing
print("Before balancing:")
print(merged_df[attack_column].value_counts())

# Balance dataset by upsampling minority classes
balanced_df_list = []
class_counts = merged_df[attack_column].value_counts()
max_size = min(class_counts.max(), max_total_samples // len(class_counts))  # Limit per class

for label, count in class_counts.items():
    df_subset = merged_df[merged_df[attack_column] == label]
    
    if count < max_size:  # Upsample minority classes
        df_subset = resample(df_subset, replace=True, n_samples=max_size, random_state=42)
    
    balanced_df_list.append(df_subset)

merged_df = pd.concat(balanced_df_list)

# Print class distribution after balancing
print("After balancing:")
print(merged_df[attack_column].value_counts())

# Save the final cleaned dataset
if merged_df.shape[0] > 1:
    merged_df.to_csv(output_file, index=False)
    print(f"✅ Data Preprocessing Complete! Cleaned data saved to: {output_file}")
else:
    print("❌ Merged dataset is too small. No file saved.")

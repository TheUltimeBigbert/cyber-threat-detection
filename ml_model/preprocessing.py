import os
import pandas as pd
import numpy as np
from sklearn.utils import resample

def determine_severity(row):
    """
    Determine attack severity based on flow characteristics.
    """
    # Get flow characteristics
    flow_duration = float(row.get('flow_duration', 0))
    fwd_packets = float(row.get('total_fwd_packets', 0))
    bwd_packets = float(row.get('total_backward_packets', 0))
    bytes = float(row.get('total_length_of_fwd_packets', 0)) + float(row.get('total_length_of_bwd_packets', 0))
    psh_flags = float(row.get('fwd_psh_flags', 0)) + float(row.get('bwd_psh_flags', 0))
    urg_flags = float(row.get('fwd_urg_flags', 0)) + float(row.get('bwd_urg_flags', 0))
    packets_per_second = float(row.get('flow_packets/s', 0))
    bytes_per_second = float(row.get('flow_bytes/s', 0))

    # Get attack type
    attack_type = row.get('label', '').strip().lower()

    # BENIGN traffic is always Low severity
    if attack_type == 'benign':
        return 'Low'

    # High Severity: Very intense traffic patterns
    if ((flow_duration < 100000 and (fwd_packets > 100 or bwd_packets > 100)) or  # Short & very intense
        (flow_duration > 1000000 and (fwd_packets > 1000 or bwd_packets > 1000)) or  # Long & massive
        (bytes_per_second > 1000000) or  # High bandwidth
        (packets_per_second > 1000) or  # High packet rate
        (psh_flags > 50 or urg_flags > 50)):  # Many urgent packets
        return 'High'

    # Medium Severity: Moderate traffic patterns
    if ((100000 <= flow_duration <= 1000000 and (50 <= fwd_packets <= 100 or 50 <= bwd_packets <= 100)) or
        (flow_duration > 1000000 and (100 <= fwd_packets <= 1000 or 100 <= bwd_packets <= 1000)) or
        (100000 <= bytes_per_second <= 1000000) or
        (100 <= packets_per_second <= 1000) or
        (10 <= psh_flags <= 50 or 10 <= urg_flags <= 50)):
        return 'Medium'

    # Low Severity: Everything else
    return 'Low'





# Settings
dataset_dir = "dataset"
output_file = "dataset/cleaned_merged_data_limited.csv"
max_total_samples = 500000  
min_sample_size = 1000  

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

# Possible attack label column names
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

    # Normalize column names: Convert to lowercase and replace spaces with underscores
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    print(f"Processed column names: {df.columns.tolist()}")  

    # Ensure correct column names
    required_columns = ['flow_duration', 'total_fwd_packets', 'total_backward_packets']
    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        print(f"⚠️ Missing columns in {file_name}: {missing_columns}")
        continue  # Skip this file if critical columns are missing

    # Keep track of unique IP combinations
    def sample_with_ip_diversity(df, sample_size):
        """
        Sample the dataset while maintaining IP address diversity
        """
        # Create a unique identifier for each source-destination IP pair
        df['ip_pair'] = df['source_ip'] + '_' + df['destination_ip']
        
        # Get unique IP pairs
        unique_ip_pairs = df['ip_pair'].unique()
        
        # Calculate how many samples per IP pair to maintain diversity
        samples_per_pair = max(1, sample_size // len(unique_ip_pairs))
        
        sampled_dfs = []
        for ip_pair in unique_ip_pairs:
            pair_df = df[df['ip_pair'] == ip_pair]
            # Sample from each IP pair, but don't sample more than available
            pair_sample_size = min(samples_per_pair, len(pair_df))
            sampled_dfs.append(pair_df.sample(n=pair_sample_size, random_state=42))
        
        # Combine all sampled data
        result_df = pd.concat(sampled_dfs)
        
        # If we need more samples to reach target size, sample randomly from remaining
        if len(result_df) < sample_size:
            remaining = df[~df.index.isin(result_df.index)]
            additional_samples = remaining.sample(n=min(sample_size - len(result_df), len(remaining)), random_state=42)
            result_df = pd.concat([result_df, additional_samples])
        
        # Drop the temporary ip_pair column
        result_df = result_df.drop('ip_pair', axis=1)
        
        return result_df

    # Replace the existing sampling code with:
    sample_size = min(len(df), max_total_samples // len(csv_files))
    df_sampled = sample_with_ip_diversity(df, sample_size)

    print(f"Number of unique source IPs: {df_sampled['source_ip'].nunique()}")
    print(f"Number of unique destination IPs: {df_sampled['destination_ip'].nunique()}")
    print(f"Number of unique IP pairs: {len(df_sampled.groupby(['source_ip', 'destination_ip']))}")

    print(f"Sampled DataFrame shape: {df_sampled.shape}")

    if df_sampled.empty:
        print(f"⚠️ Sampled DataFrame is empty for file: {file_name}")
        continue

    # Add severity level before any other processing
    print("Adding severity levels...")
    df_sampled['Severity'] = df_sampled.apply(determine_severity, axis=1)
    print("Severity distribution:\n", df_sampled['Severity'].value_counts())

    # Data cleaning (but keeping original values)
    df_sampled.fillna(0, inplace=True)  
    df_sampled.drop_duplicates(inplace=True)  
    df_sampled.replace([np.inf, -np.inf], 0, inplace=True)  

    # Append to the merged DataFrame
    merged_df = pd.concat([merged_df, df_sampled], ignore_index=True)

    print(f"✅ Data Preprocessing Complete for file: {file_name}")
    print(f"Current merged DataFrame shape: {merged_df.shape}")

    # Debugging output
    print("Flow Duration stats:", df_sampled['flow_duration'].describe())
    print("Total Fwd Packets stats:", df_sampled['total_fwd_packets'].describe())
    print("Total Backward Packets stats:", df_sampled['total_backward_packets'].describe())

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
max_size = min(class_counts.max(), max_total_samples // len(class_counts))  

for label, count in class_counts.items():
    df_subset = merged_df[merged_df[attack_column] == label]
    
    if count < max_size:  
        df_subset = resample(df_subset, replace=True, n_samples=max_size, random_state=42)
    
    balanced_df_list.append(df_subset)

merged_df = pd.concat(balanced_df_list)

# Print class distribution after balancing
print("After balancing:")
print(merged_df[attack_column].value_counts())

# Save the final cleaned dataset
if merged_df.shape[0] > 1:
    # Ensure Severity column is preserved
    columns_to_save = merged_df.columns.tolist()
    if 'Severity' not in columns_to_save:
        print("Warning: Severity column not found in final dataset!")
    merged_df.to_csv(output_file, index=False)
    print(f"✅ Data Preprocessing Complete! Cleaned data saved to: {output_file}")
    print("Final Severity distribution:\n", merged_df['Severity'].value_counts())
else:
    print("❌ Merged dataset is too small. No file saved.")

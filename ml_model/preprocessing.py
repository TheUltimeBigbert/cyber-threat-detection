import os
import pandas as pd
import numpy as np
from sklearn.utils import resample

<<<<<<< HEAD
# Add this new mapping at the top of the file
ATTACK_SEVERITY_MAPPING = {
    # High severity attacks
    "DDoS": "High",
    "DoS GoldenEye": "High",
    "DoS Hulk": "High",
    "DoS Slowhttptest": "High",
    "DoS slowloris": "High",
    "Heartbleed": "High",
    "Web Attack SQL Injection": "High",
    
    # Medium severity attacks
    "Web Attack Brute Force": "Medium",
    "Web Attack XSS": "Medium",
    "Infiltration": "Medium",
    "SSH-Patator": "Medium",
    "FTP-Patator": "Medium",
    
    # Low severity attacks
    "PortScan": "Low",
    "Bot": "Low",
    "BENIGN": "Low"
}

# Add these constants at the top of the file
FLOW_THRESHOLDS = {
    'duration': {
        'high': 10000000,  # 10 seconds
        'medium': 1000000  # 1 second
    },
    'packets_rate': {
        'high': 500,    # packets per second (high for DDoS)
        'medium': 100   # medium for Brute Force, Flooding
    },
    'bytes_rate': {
        'high': 500000,  # bytes per second (high for DDoS)
        'medium': 50000  # medium for Malware or Flooding
    },
    'flags': {
        'high': 0.5,     # PSH/URG ratio indicating aggressive traffic
        'medium': 0.2    # Medium threshold for more typical attacks
    }
}
def calculate_flow_metrics(row):
    """Calculate derived flow metrics"""
    # Get duration with minimum value of 1 microsecond to avoid division by zero
    duration = max(float(row.get('flow_duration', 1)), 1)  # Ensure minimum of 1 microsecond
    
    # Calculate packets and bytes per second
    total_packets = float(row.get('total_fwd_packets', 0)) + float(row.get('total_backward_packets', 0))
    total_bytes = float(row.get('total_length_of_fwd_packets', 0)) + float(row.get('total_length_of_bwd_packets', 0))
    
    # Calculate rates (converting microseconds to seconds)
    seconds = duration / 1000000
    packets_per_sec = total_packets / seconds if seconds > 0 else 0
    bytes_per_sec = total_bytes / seconds if seconds > 0 else 0
    
    # Calculate flag ratios with safety check for zero packets
    total_flags = float(row.get('fwd_psh_flags', 0)) + float(row.get('bwd_psh_flags', 0)) + \
                  float(row.get('fwd_urg_flags', 0)) + float(row.get('bwd_urg_flags', 0))
    flag_ratio = total_flags / total_packets if total_packets > 0 else 0
    
    return {
        'packets_rate': packets_per_sec,
        'bytes_rate': bytes_per_sec,
        'flag_ratio': flag_ratio,
        'duration': duration
    }

def determine_severity(row):
    """
    Determine attack severity based on attack type and flow characteristics with detailed explanation.
    """
    # First check if traffic is BENIGN
    attack_type = row.get('label', row.get('attack', row.get('attack_type', 'UNKNOWN')))
    if attack_type == "BENIGN":
        return {
            'severity': 'Low',
            'explanation': [{
                'feature': 'Traffic Type',
                'value': 'BENIGN',
                'severity': 'Low',
                'reason': 'Normal network traffic'
            }]
        }

    # For actual attacks, calculate flow metrics
    metrics = calculate_flow_metrics(row)
    severity_reasons = []
    
    # Get base severity from attack type mapping
    base_severity = ATTACK_SEVERITY_MAPPING.get(attack_type, 'Medium')
    severity_reasons.append({
        'feature': 'Attack Type',
        'value': attack_type,
        'severity': base_severity,
        'reason': f'Base severity for {attack_type} attack'
    })

    # Then check flow characteristics to potentially escalate severity
    if metrics['duration'] < FLOW_THRESHOLDS['duration']['medium']:
        severity_reasons.append({
            'feature': 'Flow Duration',
            'value': f"{metrics['duration']/1000000:.2f} seconds",
            'severity': 'High',
            'reason': 'Very short flow duration indicates potential burst attack'
        })
    elif metrics['duration'] < FLOW_THRESHOLDS['duration']['high']:
        severity_reasons.append({
            'feature': 'Flow Duration',
            'value': f"{metrics['duration']/1000000:.2f} seconds",
            'severity': 'Medium',
            'reason': 'Moderately short flow duration'
        })
    
    if metrics['packets_rate'] > FLOW_THRESHOLDS['packets_rate']['high']:
        severity_reasons.append({
            'feature': 'Packet Rate',
            'value': f"{metrics['packets_rate']:.2f} packets/s",
            'severity': 'High',
            'reason': 'Very high packet rate indicates potential DoS attack'
        })
    elif metrics['packets_rate'] > FLOW_THRESHOLDS['packets_rate']['medium']:
        severity_reasons.append({
            'feature': 'Packet Rate',
            'value': f"{metrics['packets_rate']:.2f} packets/s",
            'severity': 'Medium',
            'reason': 'Elevated packet rate'
        })
    
    if metrics['bytes_rate'] > FLOW_THRESHOLDS['bytes_rate']['high']:
        severity_reasons.append({
            'feature': 'Bytes Rate',
            'value': f"{metrics['bytes_rate']:.2f} bytes/s",
            'severity': 'High',
            'reason': 'Very high data transfer rate'
        })
    elif metrics['bytes_rate'] > FLOW_THRESHOLDS['bytes_rate']['medium']:
        severity_reasons.append({
            'feature': 'Bytes Rate',
            'value': f"{metrics['bytes_rate']:.2f} bytes/s",
            'severity': 'Medium',
            'reason': 'Elevated data transfer rate'
        })
    
    if metrics['flag_ratio'] > FLOW_THRESHOLDS['flags']['high']:
        severity_reasons.append({
            'feature': 'Flag Usage',
            'value': f"{metrics['flag_ratio']:.2%}",
            'severity': 'High',
            'reason': 'Unusual amount of PSH/URG flags'
        })
    elif metrics['flag_ratio'] > FLOW_THRESHOLDS['flags']['medium']:
        severity_reasons.append({
            'feature': 'Flag Usage',
            'value': f"{metrics['flag_ratio']:.2%}",
            'severity': 'Medium',
            'reason': 'Moderate use of PSH/URG flags'
        })
    
    # Determine overall severity based on the highest severity reason
    if any(reason['severity'] == 'High' for reason in severity_reasons):
        overall_severity = 'High'
    elif any(reason['severity'] == 'Medium' for reason in severity_reasons):
        overall_severity = 'Medium'
    else:
        overall_severity = 'Low'
    
    return {
        'severity': overall_severity,
        'explanation': severity_reasons
    }
=======
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




>>>>>>> 9fa7f7a9dc7ea4fb6703c52866d225aad514c139

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

    # Update where we add severity to the DataFrame
    print("Adding severity levels...")
    severity_results = df_sampled.apply(determine_severity, axis=1)
    df_sampled['Severity'] = [result['severity'] for result in severity_results]
    df_sampled['Severity_Explanation'] = [result['explanation'] for result in severity_results]

    # Before data cleaning, convert Severity_Explanation to string representation
    df_sampled['Severity_Explanation'] = df_sampled['Severity_Explanation'].apply(str)

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

# Update the IP column names during processing
def process_csv_file(df):
    # Rename IP columns
    ip_mapping = {
        'source_ip': 'attacker_ip',
        'destination_ip': 'victim_ip'
    }
    df = df.rename(columns=ip_mapping)
    return df

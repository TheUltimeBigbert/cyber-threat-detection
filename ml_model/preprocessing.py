import os
import pandas as pd
import numpy as np
from sklearn.utils import resample

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

# Thresholds for flow metrics
FLOW_THRESHOLDS = {
    'duration': {
        'high': 10000000,
        'medium': 1000000
    },
    'packets_rate': {
        'high': 500,
        'medium': 100
    },
    'bytes_rate': {
        'high': 500000,
        'medium': 50000
    },
    'flags': {
        'high': 0.5,
        'medium': 0.2
    }
}

def calculate_flow_metrics(row):
    duration = max(float(row.get('flow_duration', 1)), 1)
    total_packets = float(row.get('total_fwd_packets', 0)) + float(row.get('total_backward_packets', 0))
    total_bytes = float(row.get('total_length_of_fwd_packets', 0)) + float(row.get('total_length_of_bwd_packets', 0))

    seconds = duration / 1000000
    packets_per_sec = total_packets / seconds if seconds > 0 else 0
    bytes_per_sec = total_bytes / seconds if seconds > 0 else 0

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
    # Safely get and convert attack type to string
    attack_type = str(row.get('label', row.get('attack', row.get('attack_type', 'UNKNOWN'))))
    if pd.isna(attack_type) or attack_type == 'nan':
        attack_type = 'UNKNOWN'

    # First check if traffic is BENIGN
    if attack_type.upper() == "BENIGN":
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

# Settings
dataset_dir = "dataset"
output_file = "dataset/cleaned_merged_data_limited.csv"
max_total_samples = 500000
min_sample_size = 1000

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

merged_df = pd.DataFrame()

for file_name in csv_files:
    file_path = os.path.join(dataset_dir, file_name)
    print(f"\n📂 Loading file: {file_name}")

    try:
        df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, encoding='ISO-8859-1', low_memory=False)

    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    required_columns = ['flow_duration', 'total_fwd_packets', 'total_backward_packets', 'source_ip', 'destination_ip']
    if not all(col in df.columns for col in required_columns):
        print(f"⚠️ Skipping {file_name} - missing required columns.")
        continue

    # IP sampling function
    def sample_with_ip_diversity(df, sample_size):
        df['ip_pair'] = df['source_ip'] + '_' + df['destination_ip']
        unique_ip_pairs = df['ip_pair'].unique()
        samples_per_pair = max(1, sample_size // len(unique_ip_pairs))
        sampled_dfs = []
        for ip_pair in unique_ip_pairs:
            pair_df = df[df['ip_pair'] == ip_pair]
            sampled_dfs.append(pair_df.sample(n=min(samples_per_pair, len(pair_df)), random_state=42))
        result_df = pd.concat(sampled_dfs)
        if len(result_df) < sample_size:
            remaining = df[~df.index.isin(result_df.index)]
            additional = remaining.sample(n=min(sample_size - len(result_df), len(remaining)), random_state=42)
            result_df = pd.concat([result_df, additional])
        return result_df.drop(columns=['ip_pair'])

    sample_size = min(len(df), max_total_samples // len(csv_files))
    df_sampled = sample_with_ip_diversity(df, sample_size)

    # Add severity + explanation
    print(f"✅ Adding severity labels for {file_name}...")
    severity_results = df_sampled.apply(determine_severity, axis=1)
    df_sampled['severity'] = severity_results.apply(lambda x: x['severity'])
    df_sampled['severity_explanation'] = severity_results.apply(lambda x: str(x['explanation']))

    merged_df = pd.concat([merged_df, df_sampled], ignore_index=True)

# Save cleaned data
merged_df.to_csv(output_file, index=False)
print(f"\n✅ Cleaned and labeled dataset saved to: {output_file}")

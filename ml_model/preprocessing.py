import os
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Settings
dataset_dir = "dataset"
output_file = "dataset/cleaned_data.csv"
sample_fraction = 0.01 
max_files_to_check = 10 


csv_files = ["UNSW-NB15_4.csv"]

# Open CSV once to write in chunks
with open(output_file, "w") as f:
    header_written = False  

    for file_name in csv_files:
        file_path = os.path.join(dataset_dir, file_name)
        print(f"📂 Loading file: {file_name}")

        # Load the data from CSV file
        df = pd.read_csv(file_path)

        print(f"Loaded DataFrame shape: {df.shape}")

        # Sample small portion
        df_sampled = df.sample(frac=sample_fraction, random_state=42)

        print(f"Sampled DataFrame shape: {df_sampled.shape}")

        if df_sampled.empty:
            print(f"⚠️ Sampled DataFrame is empty for file: {file_name}")
            continue

        # Clean data
        df_sampled.fillna(0, inplace=True)  # Fill missing values
        df_sampled.drop_duplicates(inplace=True)  # Remove duplicates

        # Normalize numerical data
        numeric_columns = df_sampled.select_dtypes(include=['number']).columns
        scaler = StandardScaler(with_mean=False)
        df_sampled[numeric_columns] = scaler.fit_transform(df_sampled[numeric_columns])

        # Save to CSV (append mode)
        df_sampled.to_csv(f, index=False, header=not header_written, mode="a")
        header_written = True

        print(f"✅ Data Preprocessing Complete for file: {file_name}")
        break  # Stop after processing the first file with data

print(f"✅ Data Preprocessing Complete! Cleaned data saved to: {output_file}")

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import logging
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load trained model
model = joblib.load("ml_model/random_forest_model.pkl")

# Load dataset with details
df_details = pd.read_csv("dataset/cleaned_data_with_details.csv")

# After loading df_details, print the columns to debug
print("Available columns:", df_details.columns.tolist())

# Update column mapping to match the actual column names in the CSV
column_mapping = {
    "source_ip": "Source IP",
    "destination_ip": "Destination IP",
    "original_attack_label": "Attack Type"
}

# Rename columns
df_details = df_details.rename(columns=column_mapping)

# Ensure necessary columns exist
required_columns = ["Source IP", "Destination IP", "Attack Type", "Severity"]
for col in required_columns:
    if col not in df_details.columns:
        raise ValueError(f"Missing required column: {col}")

# Define numeric columns (excluding metadata columns and Severity)
numeric_columns = [col for col in df_details.columns if col not in required_columns and col != "Severity"]

# Convert numeric columns to float (handling errors)
df_details[numeric_columns] = df_details[numeric_columns].apply(pd.to_numeric, errors='coerce').fillna(0.0)

# Ensure Severity remains as string
df_details["Severity"] = df_details["Severity"].astype(str)

# Update the ATTACK_TYPE_MAPPING to match your actual labels
ATTACK_TYPE_MAPPING = {
    "BENIGN": "BENIGN",
    "Bot": "Bot",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS Hulk": "DoS Hulk",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "DoS slowloris": "DoS slowloris",
    "FTP-Patator": "FTP-Patator",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",
    "PortScan": "PortScan",
    "SSH-Patator": "SSH-Patator",
    "Web Attack Brute Force": "Web Attack Brute Force",
    "Web Attack SQL Injection": "Web Attack SQL Injection",
    "Web Attack XSS": "Web Attack XSS"
}

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
app.mount("/static", StaticFiles(directory="dataset"), name="static")

# Define request and response models
class Features(BaseModel):
    features: list

@app.post("/predict")
async def predict(features: Features):
    try:
        logging.info(f"Received features: {features.features}")

        # Get the attack label from the input
        attack_label = features.features[0] if features.features else "Unknown"
        
        # Get a random row from the dataset matching the attack type, preferring unique IP combinations
        matching_rows = df_details[df_details["Attack Type"] == attack_label]
        
        if not matching_rows.empty:
            # Group by IP pairs and sample one group randomly
            ip_groups = matching_rows.groupby(['Source IP', 'Destination IP'])
            random_group = np.random.choice(list(ip_groups.groups.keys()))
            random_row = ip_groups.get_group(random_group).sample(n=1).iloc[0]
            source_ip = random_row["Source IP"]
            destination_ip = random_row["Destination IP"]
            attack_type = random_row["Attack Type"]
            # Try to get severity with original column name
            severity = random_row.get("Severity", "Unknown")  # Use get() method with default value
            logging.info(f"Found severity: {severity}")
        else:
            source_ip = "Unknown"
            destination_ip = "Unknown"
            attack_type = attack_label
            severity = "Unknown"

        logging.info(f"Returning: source_ip={source_ip}, destination_ip={destination_ip}, attack_type={attack_type}, severity={severity}")

        return {
            "prediction": 1 if attack_type != "BENIGN" else 0,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "attack_type": attack_type,
            "severity": severity
        }
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        logging.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# Run the app
if __name__ == "__main__": 
    import uvicorn
    uvicorn.run("predict:app", host="127.0.0.1", port=8000, reload=True)

print("Severity values in dataset:", df_details["Severity"].unique())

# After loading df_details
print("IP address statistics:")
print(f"Number of unique source IPs: {df_details['Source IP'].nunique()}")
print(f"Number of unique destination IPs: {df_details['Destination IP'].nunique()}")
print(f"Number of unique IP pairs: {len(df_details.groupby(['Source IP', 'Destination IP']))}")

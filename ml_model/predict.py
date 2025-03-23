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

# After loading df_details
print("Available columns:", df_details.columns.tolist())
print("Sample data:", df_details.head(1).to_dict('records'))

# Rename specific columns to meaningful names
df_details.rename(columns={
    "Source_IP": "Source IP",
    "Destination_IP": "Destination IP",
    "original_attack_label": "Attack Type"
}, inplace=True)


# Ensure necessary columns exist
required_columns = ["Source IP", "Destination IP", "Attack Type"]
for col in required_columns:
    if col not in df_details.columns:
        raise ValueError(f"Missing required column: {col}")

# Define numeric columns (excluding metadata columns)
numeric_columns = [col for col in df_details.columns if col not in required_columns]

# Convert numeric columns to float (handling errors)
df_details[numeric_columns] = df_details[numeric_columns].apply(pd.to_numeric, errors='coerce').fillna(0.0)

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
        
        # Get a random row from the dataset matching the attack type
        matching_rows = df_details[df_details["Attack Type"] == attack_label]
        
        if not matching_rows.empty:
            random_row = matching_rows.sample(n=1).iloc[0]
            source_ip = random_row["Source IP"]
            destination_ip = random_row["Destination IP"]
            attack_type = random_row["Attack Type"]
        else:
            source_ip = "Unknown"
            destination_ip = "Unknown"
            attack_type = attack_label

        logging.info(f"Returning: source_ip={source_ip}, destination_ip={destination_ip}, attack_type={attack_type}")

        return {
            "prediction": 1 if attack_type != "BENIGN" else 0,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "attack_type": attack_type
        }
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        logging.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# Run the app
if __name__ == "__main__": 
    import uvicorn
    uvicorn.run("predict:app", host="127.0.0.1", port=8000, reload=True)

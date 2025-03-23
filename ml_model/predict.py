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
df_details = pd.read_csv("dataset/cleaned_merged_data_limited.csv")

# Rename specific columns to meaningful names
df_details.rename(columns={
    "Source_IP": "Source IP",
    "Destination_IP": "Destination IP",
    "Label": "Attack Type"
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
        logging.info(f"Received {len(features.features)} features: {features.features}")

        # Ensure features are a valid list
        if not isinstance(features.features, list):
            raise ValueError("Features must be a list")

        # Convert None values to 0.0 before converting to NumPy array
        cleaned_features = [0.0 if f is None else f for f in features.features]
        
        # Ensure the cleaned_features list has the correct length
        expected_features = 41  # The model expects 41 features
        if len(cleaned_features) < expected_features:
            cleaned_features.extend([0.0] * (expected_features - len(cleaned_features)))
        elif len(cleaned_features) > expected_features:
            cleaned_features = cleaned_features[:expected_features]

        features_array = np.array(cleaned_features).reshape(1, -1)
        logging.info(f"Features array shape: {features_array.shape}, Expected: {expected_features}")

        # Handle NaN and infinite values
        features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)

        # Ensure feature length matches expected input
        received_features = features_array.shape[1]
        
        if received_features != expected_features:
            raise ValueError(f"Expected {expected_features} features, but got {received_features}")

        # Make prediction
        prediction = model.predict(features_array)
        logging.info(f"Prediction result: {prediction[0]}")

        # Retrieve attack details based on the predicted attack type
        attack_type = prediction[0]
        
        # Get a random row from the dataset matching the prediction
        matching_rows = df_details[df_details["Attack Type"].astype(str) == str(attack_type)]
        
        if not matching_rows.empty:
            random_row = matching_rows.sample(n=1).iloc[0]
            source_ip = random_row["Source IP"]
            destination_ip = random_row["Destination IP"]
            attack_type = random_row["Attack Type"]
        else:
            source_ip = "Unknown"
            destination_ip = "Unknown"
            attack_type = str(prediction[0])  # Use raw prediction if no match found

        logging.info(f"Returning: source_ip={source_ip}, destination_ip={destination_ip}, attack_type={attack_type}")

        return {
            "prediction": int(prediction[0]),
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

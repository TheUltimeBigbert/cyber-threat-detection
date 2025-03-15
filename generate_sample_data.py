import pandas as pd

# Create sample data
data = {
    "feature1": [0, 1, 0, 1, 1],
    "feature2": [10, 15, 10, 20, 25],
    "feature3": [5, 3, 6, 8, 2],
    "threat_label": [0, 1, 0, 1, 1]  # 0 = No Threat, 1 = Threat
}

df = pd.DataFrame(data)

# Save as CSV file
df.to_csv("cyber_data.csv", index=False)

print("✅ cyber_data.csv created successfully!")

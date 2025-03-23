import pandas as pd

# Load dataset with details
df_details = pd.read_csv("dataset/cleaned_data_with_details.csv")

# Print the number of columns and their names
print(f"Number of columns: {len(df_details.columns)}")
print("Column names:")
print(df_details.columns)
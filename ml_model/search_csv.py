import csv

# Define the target row you are looking for
target_row = [
    0.5591471823290589, 0.3458015308672413, 0.1185787857412005, 1.7314586507179195,
    0.8429649458667993, 0.0121698836681884, 0, 0.0171909246384184, 0.00007375876346406087,
    0.0726045973799701
]

# Path to the CSV file
csv_file_path = 'dataset/cleaned_data_top_10.csv'

# Function to compare two rows with a tolerance for floating-point precision
def rows_match(row1, row2, tolerance=1e-9):
    return all(abs(a - b) < tolerance for a, b in zip(row1, row2))

# Read the CSV file and search for the target row
with open(csv_file_path, mode='r') as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        # Skip header row if present
        if csv_reader.line_num == 1 and not row[0].replace('.', '', 1).isdigit():
            continue
        # Convert the row to a list of floats
        row = [float(value) for value in row[:10]]  # Ensure only the first 10 columns are considered
        if rows_match(row, target_row):
            print("Found the target row:", row)
            break
    else:
        print("Target row not found in the CSV file.")
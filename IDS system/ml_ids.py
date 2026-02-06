import pandas as pd
from sklearn.ensemble import IsolationForest

# Load dataset
data = pd.read_csv("traffic_data.csv")

print("Dataset loaded. Rows:", len(data))

# Train Isolation Forest model
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(data)

print("ML model trained successfully")

# Detect anomalies
predictions = model.predict(data)

anomalies = data[predictions == -1]

print("Total anomalies detected:", len(anomalies))


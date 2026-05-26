import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

def detect_anomalies(df, contamination=0.06):
    """
    Applies Machine Learning (Isolation Forest) to detect anomalies in cybersecurity logs.
    
    Args:
        df (pd.DataFrame): The DataFrame enriched by log_analysis.py.
        contamination (float): The proportion of outliers in the dataset.
        
    Returns:
        pd.DataFrame: DataFrame with an added 'Is_Anomaly' column (0 for normal, 1 for anomaly).
    """
    print(f"Running machine learning anomaly detection (Isolation Forest)...")
    
    df = df.copy()
    
    # 1. Feature Selection & Encoding
    # Select categorical columns and convert them to integers
    categorical_cols = ["Login Status", "Country", "Event Type", "Device"]
    label_encoders = {}
    
    encoded_df = pd.DataFrame()
    for col in categorical_cols:
        le = LabelEncoder()
        # Handle potential NaNs just in case
        non_null_series = df[col].fillna("Unknown").astype(str)
        encoded_df[col + "_enc"] = le.fit_transform(non_null_series)
        label_encoders[col] = le
        
    # Standard numeric features
    encoded_df["Hour"] = df["Hour"]
    encoded_df["Recent_Failures"] = df["Recent_Failures"]
    encoded_df["Is_Unusual_Time"] = df["Is_Unusual_Time"]
    encoded_df["Is_Brute_Force"] = df["Is_Brute_Force"]
    encoded_df["Is_Port_Scan_Attack"] = df["Is_Port_Scan_Attack"]
    
    # Check for NaN and fill
    encoded_df.fillna(0, inplace=True)
    
    # 2. Model Training
    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    
    # Fit and predict
    # Isolation Forest returns -1 for outliers and 1 for inliers
    predictions = model.fit_predict(encoded_df)
    
    # Convert predictions to: 1 for anomaly, 0 for normal
    df["Is_Anomaly"] = np.where(predictions == -1, 1, 0)
    
    # 3. Analyze ML vs Rule-Based Overlap
    total_anomalies = df["Is_Anomaly"].sum()
    rule_high_threats = (df["Severity"] == "High").sum()
    
    overlap = ((df["Is_Anomaly"] == 1) & (df["Severity"] == "High")).sum()
    
    print(f"ML Anomaly Detection Results:")
    print(f" - Total logs: {len(df)}")
    print(f" - ML anomalies detected (outliers): {total_anomalies} ({total_anomalies/len(df)*100:.2f}%)")
    print(f" - Rule-based High severity threats: {rule_high_threats}")
    print(f" - Overlap (ML Anomaly AND High Severity): {overlap}")
    print(f" - ML Anomalies not flagged as High severity: {total_anomalies - overlap}")
    
    # Adjust descriptions for ML-only anomalies
    # If it is an ML anomaly but classified as Low severity, let's append a note to Threat_Description
    for idx, row in df.iterrows():
        if row["Is_Anomaly"] == 1 and row["Severity"] == "Low":
            df.at[idx, "Severity"] = "Medium" # Elevate to Medium since ML flagged it
            df.at[idx, "Threat_Description"] = row["Threat_Description"] + " | ML flagged anomaly"
            
    return df

if __name__ == "__main__":
    from log_analysis import analyze_logs
    from data_cleaning import clean_log_data
    try:
        clean_df = clean_log_data()
        analyzed_df = analyze_logs(clean_df)
        ml_df = detect_anomalies(analyzed_df)
        
        os.makedirs("reports", exist_ok=True)
        ml_df.to_csv("reports/ml_enriched_logs.csv", index=False)
        print("Successfully saved ML-enriched logs to reports/ml_enriched_logs.csv")
    except Exception as e:
        print(f"Error during anomaly detection: {e}")

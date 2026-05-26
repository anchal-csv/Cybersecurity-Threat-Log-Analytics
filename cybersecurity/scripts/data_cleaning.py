import os
import re
import pandas as pd

def clean_log_data(file_path="dataset/sample_logs.csv"):
    """
    Loads raw cybersecurity log CSV, cleans and normalizes it.
    
    Returns:
        pd.DataFrame: Cleaned data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Raw log file not found at {file_path}. Please run generate_logs.py first.")
        
    print(f"Loading raw logs from {file_path}...")
    df = pd.read_csv(file_path)
    
    # 1. Clean column headers (strip spaces, normalize case if necessary)
    df.columns = [col.strip() for col in df.columns]
    
    # Record initial count
    initial_rows = len(df)
    
    # 2. Remove exact duplicates
    df = df.drop_duplicates()
    duplicate_count = initial_rows - len(df)
    if duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate rows.")
        
    # 3. Clean and parse Timestamps
    # If parsing fails, coerce to NaT and drop those rows
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    invalid_dates = df["Timestamp"].isna().sum()
    if invalid_dates > 0:
        print(f"Dropping {invalid_dates} rows with invalid/missing timestamps.")
        df = df.dropna(subset=["Timestamp"])
        
    # Sort by Timestamp
    df = df.sort_values(by="Timestamp").reset_index(drop=True)
    
    # 4. Normalize categorical columns and fill missing values
    df["Username"] = df["Username"].fillna("unknown").astype(str).str.strip().str.lower()
    df["Login Status"] = df["Login Status"].fillna("Unknown").astype(str).str.strip().str.capitalize()
    df["Country"] = df["Country"].fillna("Unknown").astype(str).str.strip()
    df["Event Type"] = df["Event Type"].fillna("Unknown").astype(str).str.strip()
    df["Device"] = df["Device"].fillna("Unknown").astype(str).str.strip()
    df["Severity"] = df["Severity"].fillna("Low").astype(str).str.strip().str.capitalize()
    
    # Validate IP address format (simple regex check for IPv4)
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    
    def validate_ip(ip):
        ip = str(ip).strip()
        if ipv4_pattern.match(ip):
            # Check octet ranges
            parts = ip.split(".")
            if all(0 <= int(part) <= 255 for part in parts):
                return ip
        return "0.0.0.0" # Default/invalid marker
        
    df["IP Address"] = df["IP Address"].apply(validate_ip)
    
    # Log invalid IPs
    invalid_ips = (df["IP Address"] == "0.0.0.0").sum()
    if invalid_ips > 0:
        print(f"Identified {invalid_ips} rows with invalid IP addresses. Marked as '0.0.0.0'.")
        
    print(f"Data cleaning complete. Cleaned rows: {len(df)}")
    return df

if __name__ == "__main__":
    try:
        cleaned_df = clean_log_data()
        # Save a preview of the cleaned dataset
        os.makedirs("reports", exist_ok=True)
        cleaned_df.head(10).to_csv("reports/cleaned_logs_preview.csv", index=False)
        print("Successfully generated cleaned logs preview at reports/cleaned_logs_preview.csv")
    except Exception as e:
        print(f"Error during log cleaning: {e}")

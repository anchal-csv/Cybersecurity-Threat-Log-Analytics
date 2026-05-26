import os
import pandas as pd
import numpy as np

def analyze_logs(df):
    """
    Analyzes log data using security rules.
    Identifies brute-force attacks, port scans, unusual login times, and critical events.
    Enriches the DataFrame with security indicators and calculates threat severity.
    
    Args:
        df (pd.DataFrame): Cleaned DataFrame.
        
    Returns:
        pd.DataFrame: Enriched DataFrame with analysis columns.
    """
    print("Running rule-based threat analysis...")
    
    # Ensure Timestamp is datetime and sorted
    df = df.copy()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df = df.sort_values(by="Timestamp").reset_index(drop=True)
    
    # 1. Feature Engineering: Calculate recent failed logins in a 10-minute window
    # We do a rolling calculation. For each log, we look back 10 minutes and count failed logins from the same IP.
    print("Calculating rolling failed logins window per IP...")
    
    # To do this efficiently:
    # Set the timestamp as the index temporarily
    df_temp = df.copy()
    df_temp.set_index("Timestamp", inplace=True)
    
    # Filter for failed logins only to count them
    failed_logins = df_temp[df_temp["Login Status"] == "Failed"]
    
    # Group by IP and count occurrences within a 10-minute rolling window
    # closed='both' includes both boundaries
    rolling_failures = (
        failed_logins.groupby("IP Address")["Login Status"]
        .rolling("10Min", closed="both")
        .count()
        .reset_index()
    )
    
    # Rename column to Recent_Failures
    rolling_failures.rename(columns={"Login Status": "Recent_Failures"}, inplace=True)
    
    # Merge back to the original df
    # Since rolling failures contains timestamps, we can merge on Timestamp and IP Address
    df = pd.merge(df, rolling_failures, on=["Timestamp", "IP Address"], how="left")
    
    # Fill NaN values (which means 0 failures in that window, or it wasn't a failed login row)
    # Actually, if the current row is a successful login, it wouldn't be in failed_logins,
    # but we still want to know how many failed logins occurred in the last 10 minutes from this IP.
    # Let's write a helper to assign Recent_Failures to all rows, successful or failed.
    # To do this correctly and robustly for all rows:
    ip_groups = df.groupby("IP Address")
    
    recent_failures_all = []
    # Loop over each row to find count of failures in past 10 minutes from same IP
    # Since we sorted by timestamp, we can optimize this.
    # For small to medium datasets (~5000 rows), a direct rolling index or bisect is very fast.
    # Let's implement an efficient vector/index search for each IP group.
    for ip, group in ip_groups:
        times = group["Timestamp"].values
        is_fail = (group["Login Status"] == "Failed").values
        
        # Calculate for each index in the group
        group_failures = []
        for i in range(len(group)):
            current_time = times[i]
            ten_mins_ago = current_time - np.timedelta64(10, 'm')
            
            # Find elements within [ten_mins_ago, current_time]
            # Since the array is sorted, we can slice it
            # We only count where is_fail is True
            mask = (times >= ten_mins_ago) & (times <= current_time) & is_fail
            group_failures.append(np.sum(mask))
            
        group_df = group.copy()
        group_df["Recent_Failures"] = group_failures
        recent_failures_all.append(group_df)
        
    df = pd.concat(recent_failures_all).sort_values(by="Timestamp").reset_index(drop=True)
    
    # 2. Rule Checks
    df["Hour"] = df["Timestamp"].dt.hour
    
    # Unusual Time: 11:00 PM (23) to 5:00 AM (5)
    df["Is_Unusual_Time"] = ((df["Hour"] >= 23) | (df["Hour"] < 5)).astype(int)
    
    # Brute-force threshold: >= 5 failures in 10 minutes
    df["Is_Brute_Force"] = (df["Recent_Failures"] >= 5).astype(int)
    
    # Port scan threshold: Check if IP performed >= 5 port scans overall or recently
    # Let's count rolling port scans in a 10-minute window
    recent_scans_all = []
    for ip, group in df.groupby("IP Address"):
        times = group["Timestamp"].values
        is_scan = (group["Event Type"] == "Port Scan").values
        
        group_scans = []
        for i in range(len(group)):
            current_time = times[i]
            ten_mins_ago = current_time - np.timedelta64(10, 'm')
            mask = (times >= ten_mins_ago) & (times <= current_time) & is_scan
            group_scans.append(np.sum(mask))
            
        group_df = group.copy()
        group_df["Recent_Scans"] = group_scans
        recent_scans_all.append(group_df)
        
    df = pd.concat(recent_scans_all).sort_values(by="Timestamp").reset_index(drop=True)
    df["Is_Port_Scan_Attack"] = (df["Recent_Scans"] >= 5).astype(int)
    
    # 3. Determine threat severity levels and descriptions
    severities = []
    descriptions = []
    
    for idx, row in df.iterrows():
        # Default description and severity
        sev = "Low"
        desc = "Normal event"
        
        # High Risk Conditions
        if row["Is_Brute_Force"] == 1:
            sev = "High"
            desc = f"Brute Force Attack: {row['Recent_Failures']} failed logins in 10m from IP {row['IP Address']}"
        elif row["Is_Port_Scan_Attack"] == 1:
            sev = "High"
            desc = f"Active Port Scan: Multiple ports scanned from IP {row['IP Address']}"
        elif row["Event Type"] == "Privilege Escalation" and row["Login Status"] == "Success":
            sev = "High"
            desc = f"Critical: Successful Privilege Escalation by user '{row['Username']}'"
        elif row["Event Type"] == "Data Export" and row["Is_Unusual_Time"] == 1:
            sev = "High"
            desc = f"Critical: Bulk Data Export at unusual hour ({row['Hour']}:00) by '{row['Username']}'"
            
        # Medium Risk Conditions (if not already High)
        elif sev == "Low":
            if row["Event Type"] == "Privilege Escalation" and row["Login Status"] == "Failed":
                sev = "Medium"
                desc = f"Suspicious: Failed Privilege Escalation by user '{row['Username']}'"
            elif row["Event Type"] == "Data Export":
                sev = "Medium"
                desc = f"Data Export by '{row['Username']}'"
            elif row["Login Status"] == "Failed" and row["Recent_Failures"] >= 2:
                sev = "Medium"
                desc = f"Suspicious: Multiple failed logins ({row['Recent_Failures']}) from IP {row['IP Address']}"
            elif row["Is_Unusual_Time"] == 1 and row["Username"] in ["admin", "root", "db_admin"]:
                sev = "Medium"
                desc = f"Suspicious: Admin login activity at unusual hour ({row['Hour']}:00)"
            elif row["Event Type"] == "Port Scan":
                sev = "Medium"
                desc = f"Suspicious: Port scan activity detected"
                
        # Low Risk (but failed)
        elif sev == "Low" and row["Login Status"] == "Failed":
            desc = "Single failed login attempt"
            
        severities.append(sev)
        descriptions.append(desc)
        
    df["Calculated_Severity"] = severities
    df["Threat_Description"] = descriptions
    
    # Overwrite the original Severity column with the Calculated one
    df["Severity"] = df["Calculated_Severity"]
    
    # Clean up intermediate analysis columns we don't need to write to DB,
    # but keep them if they are useful for ML (e.g. Hour, Recent_Failures)
    df.drop(columns=["Calculated_Severity", "Recent_Scans"], inplace=True)
    
    print(f"Analysis complete. Detected {sum(df['Severity'] == 'High')} High-severity threats and {sum(df['Severity'] == 'Medium')} Medium-severity events.")
    return df

if __name__ == "__main__":
    from data_cleaning import clean_log_data
    try:
        clean_df = clean_log_data()
        analyzed_df = analyze_logs(clean_df)
        os.makedirs("reports", exist_ok=True)
        analyzed_df.to_csv("reports/analyzed_logs.csv", index=False)
        print("Successfully saved analyzed logs to reports/analyzed_logs.csv")
    except Exception as e:
        print(f"Error during log analysis: {e}")

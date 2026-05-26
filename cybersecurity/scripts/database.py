import os
import sqlite3
import pandas as pd

DEFAULT_DB_PATH = "dataset/security_logs.db"

def get_connection(db_path=DEFAULT_DB_PATH):
    """
    Establishes and returns an SQLite database connection.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return sqlite3.connect(db_path)

def init_db(db_path=DEFAULT_DB_PATH):
    """
    Initializes the SQLite database structure and creates indexes.
    """
    print(f"Initializing SQLite database at {db_path}...")
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Create security_logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        ip_address TEXT NOT NULL,
        username TEXT NOT NULL,
        login_status TEXT NOT NULL,
        country TEXT NOT NULL,
        event_type TEXT NOT NULL,
        device TEXT NOT NULL,
        severity TEXT NOT NULL,
        is_anomaly INTEGER NOT NULL,
        threat_description TEXT,
        hour INTEGER,
        recent_failures INTEGER
    )
    """)
    
    # Create indexes for analytical performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON security_logs (ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON security_logs (severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly ON security_logs (is_anomaly)")
    
    conn.commit()
    conn.close()
    print("Database and indexes successfully initialized.")

def save_logs_to_db(df, db_path=DEFAULT_DB_PATH, if_exists="replace"):
    """
    Saves the analyzed/ML-enriched log DataFrame to the SQLite database.
    """
    init_db(db_path)
    
    print(f"Writing {len(df)} records to security_logs table...")
    conn = get_connection(db_path)
    
    # Ensure Timestamp column is standard string format for SQL storage
    df_db = df.copy()
    df_db["Timestamp"] = df_db["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    
    # Map pandas columns to match SQL snake_case/lowercase
    # Column mapping:
    # 'Timestamp' -> 'timestamp'
    # 'IP Address' -> 'ip_address'
    # 'Username' -> 'username'
    # 'Login Status' -> 'login_status'
    # 'Country' -> 'country'
    # 'Event Type' -> 'event_type'
    # 'Device' -> 'device'
    # 'Severity' -> 'severity'
    # 'Is_Anomaly' -> 'is_anomaly'
    # 'Threat_Description' -> 'threat_description'
    # 'Hour' -> 'hour'
    # 'Recent_Failures' -> 'recent_failures'
    
    df_db.rename(columns={
        "Timestamp": "timestamp",
        "IP Address": "ip_address",
        "Username": "username",
        "Login Status": "login_status",
        "Country": "country",
        "Event Type": "event_type",
        "Device": "device",
        "Severity": "severity",
        "Is_Anomaly": "is_anomaly",
        "Threat_Description": "threat_description",
        "Hour": "hour",
        "Recent_Failures": "recent_failures"
    }, inplace=True)
    
    # Drop columns that are not part of the database schema (e.g. Is_Brute_Force, Is_Port_Scan_Attack, Is_Unusual_Time)
    # Actually let's include Is_Brute_Force, Is_Port_Scan_Attack, Is_Unusual_Time if we want,
    # or keep the schema clean. Let's make sure the DataFrame columns match the SQLite columns.
    allowed_cols = [
        "timestamp", "ip_address", "username", "login_status", "country",
        "event_type", "device", "severity", "is_anomaly", "threat_description",
        "hour", "recent_failures"
    ]
    
    # Filter for allowed columns
    df_db = df_db[[col for col in allowed_cols if col in df_db.columns]]
    
    # Write to SQL
    # If if_exists="replace", pandas drops the table. We then need to recreate indexes.
    df_db.to_sql("security_logs", conn, if_exists=if_exists, index=False)
    
    # Re-apply indexes just in case pandas replaced the table structure
    if if_exists == "replace":
        cursor = conn.cursor()
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs (timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON security_logs (ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON security_logs (severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly ON security_logs (is_anomaly)")
        conn.commit()
        
    conn.close()
    print("Log insertion complete.")

# ----------------- ANALYTICAL QUERIES (SQL) -----------------

def get_kpis_sql(db_path=DEFAULT_DB_PATH):
    """
    Executes SQL query to fetch key metrics:
    Total Logs, Failed Logins, High Severity Threats, ML Anomalies.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE login_status = 'Failed'")
    failed_logins = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE severity = 'High'")
    high_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE is_anomaly = 1")
    ml_anomalies = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "Total Logs": total_logs,
        "Failed Logins": failed_logins,
        "High Threats": high_threats,
        "ML Anomalies": ml_anomalies
    }

def get_top_attacking_ips_sql(limit=10, db_path=DEFAULT_DB_PATH):
    """
    SQL query to get the top IP addresses that triggered High or Medium severity,
    or have failed logins.
    """
    conn = get_connection(db_path)
    query = f"""
    SELECT ip_address, COUNT(*) as threat_count, country, severity
    FROM security_logs
    WHERE severity IN ('High', 'Medium') OR login_status = 'Failed'
    GROUP BY ip_address
    ORDER BY threat_count DESC
    LIMIT {limit}
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_attack_trends_sql(db_path=DEFAULT_DB_PATH):
    """
    SQL query to retrieve the count of threats and normal logs grouped by day.
    """
    conn = get_connection(db_path)
    query = """
    SELECT date(timestamp) as log_date, severity, COUNT(*) as log_count
    FROM security_logs
    GROUP BY log_date, severity
    ORDER BY log_date
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_severity_distribution_sql(db_path=DEFAULT_DB_PATH):
    """
    SQL query to retrieve the severity counts.
    """
    conn = get_connection(db_path)
    query = """
    SELECT severity, COUNT(*) as count
    FROM security_logs
    GROUP BY severity
    ORDER BY count DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def load_all_logs(db_path=DEFAULT_DB_PATH):
    """
    Loads all logs from database into a pandas DataFrame.
    """
    conn = get_connection(db_path)
    df = pd.read_sql_query("SELECT * FROM security_logs ORDER BY timestamp DESC", conn)
    conn.close()
    
    # Parse timestamps back to datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

if __name__ == "__main__":
    from anomaly_detection import detect_anomalies
    from log_analysis import analyze_logs
    from data_cleaning import clean_log_data
    
    try:
        # Run local test pipeline to check database insertion
        clean_df = clean_log_data()
        analyzed_df = analyze_logs(clean_df)
        ml_df = detect_anomalies(analyzed_df)
        
        # Save to database
        save_logs_to_db(ml_df)
        
        # Test analytical queries
        kpis = get_kpis_sql()
        print("\nTest SQL KPI Query Results:")
        for k, v in kpis.items():
            print(f" - {k}: {v}")
            
        top_ips = get_top_attacking_ips_sql(3)
        print("\nTest SQL Top Attacking IPs:")
        print(top_ips)
        
    except Exception as e:
        print(f"Error during database execution: {e}")

import os
import sys
import argparse
import subprocess

# Ensure project root is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scripts.generate_logs import generate_sample_logs
from scripts.data_cleaning import clean_log_data
from scripts.log_analysis import analyze_logs
from scripts.anomaly_detection import detect_anomalies
from scripts.database import save_logs_to_db

def run_pipeline(force_generate=False):
    """
    Runs the complete cybersecurity data ingestion and analysis pipeline.
    """
    print("=" * 60)
    print("STARTING CYBERSECURITY THREAT LOG ANALYTICS PIPELINE")
    print("=" * 60)
    
    csv_path = "dataset/sample_logs.csv"
    
    # 1. Log Generation
    if force_generate or not os.path.exists(csv_path):
        print("\n[Step 1/5] Generating fresh cybersecurity logs...")
        generate_sample_logs(csv_path)
    else:
        print(f"\n[Step 1/5] Using existing logs from {csv_path}")
        
    # 2. Data Cleaning
    print("\n[Step 2/5] Cleaning and normalizing log data...")
    cleaned_df = clean_log_data(csv_path)
    
    # 3. Rule-based analysis
    print("\n[Step 3/5] Performing rule-based threat analysis...")
    analyzed_df = analyze_logs(cleaned_df)
    
    # 4. Machine learning anomaly detection
    print("\n[Step 4/5] Running Isolation Forest anomaly detection...")
    ml_df = detect_anomalies(analyzed_df)
    
    # 5. Database storage
    print("\n[Step 5/5] Storing processed logs in SQLite database...")
    save_logs_to_db(ml_df)
    
    print("\n" + "=" * 60)
    print("DATA PIPELINE RUN COMPLETED SUCCESSFULLY")
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Threat Log Analytics CLI")
    parser.add_argument("--generate", action="store_true", help="Force regeneration of raw sample logs")
    parser.add_argument("--pipeline-only", action="store_true", help="Only run data pipeline, do not launch dashboard")
    args = parser.parse_args()
    
    # Run the backend data pipeline
    run_pipeline(force_generate=args.generate)
    
    # Run the dashboard
    if not args.pipeline_only:
        print("\nLaunching Streamlit dashboard...")
        dashboard_path = os.path.join("dashboard", "dashboard.py")
        
        try:
            # Launch streamlit run dashboard/dashboard.py
            # Using sys.executable to run streamlit to ensure correct environment
            cmd = ["streamlit", "run", dashboard_path]
            print(f"Executing: {' '.join(cmd)}")
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nDashboard server terminated by user.")
        except Exception as e:
            print(f"\nFailed to launch dashboard automatically: {e}")
            print("You can run it manually using:")
            print("  streamlit run dashboard/dashboard.py")
    else:
        print("\nSkipping dashboard launch as requested.")
        print("To launch it manually, run:")
        print("  streamlit run dashboard/dashboard.py")

if __name__ == "__main__":
    main()

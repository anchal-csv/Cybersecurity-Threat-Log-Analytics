import os
import sys
import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, time

# Add the project root to the python path to allow importing from scripts
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

import scripts.database as db

# Page Configuration
st.set_page_config(
    page_title="CyberEye - Security Threat Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyberpunk Dark CSS for the Dashboard
st.markdown("""
<style>
    /* Main container background */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0f172a !important;
        border-right: 1px solid #1e293b;
    }
    
    /* Card design with glassmorphism and subtle glowing borders */
    .kpi-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        text-align: center;
        transition: transform 0.2s, border-color 0.2s;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
    }
    
    /* Glowing card headers */
    .kpi-title {
        font-size: 0.9rem;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin-top: 5px;
        font-family: 'Courier New', monospace;
    }
    
    /* KPI specific colors */
    .kpi-total { border-left: 5px solid #3b82f6; box-shadow: 0 0 10px rgba(59, 130, 246, 0.1); }
    .kpi-total .kpi-value { color: #60a5fa; }
    
    .kpi-failed { border-left: 5px solid #eab308; box-shadow: 0 0 10px rgba(234, 179, 8, 0.1); }
    .kpi-failed .kpi-value { color: #facc15; }
    
    .kpi-threats { border-left: 5px solid #ef4444; box-shadow: 0 0 10px rgba(239, 68, 68, 0.2); }
    .kpi-threats .kpi-value { color: #f87171; }
    
    .kpi-anomalies { border-left: 5px solid #a855f7; box-shadow: 0 0 10px rgba(168, 85, 247, 0.2); }
    .kpi-anomalies .kpi-value { color: #c084fc; }
    
    /* Ticker or Terminal style alert box */
    .terminal-box {
        background-color: #030712;
        border: 1px solid #10b981;
        border-radius: 8px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        color: #10b981;
        height: 200px;
        overflow-y: scroll;
        box-shadow: inset 0 0 10px rgba(16, 185, 129, 0.2);
    }
    
    .ticker-item {
        margin-bottom: 8px;
        border-bottom: 1px solid rgba(16, 185, 129, 0.1);
        padding-bottom: 4px;
        font-size: 0.85rem;
    }
    
    .ticker-high { color: #f87171; font-weight: bold; }
    .ticker-med { color: #fbbf24; }
    .ticker-low { color: #34d399; }
</style>
""", unsafe_allow_html=True)

# App Title & Header
col1, col2 = st.columns([0.8, 0.2])
with col1:
    st.markdown("<h1 style='color: #3b82f6; margin-bottom: 0px;'>🛡️ CyberEye</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #64748b; font-size: 1.1rem; margin-top: 0px;'>Cybersecurity Threat Log Analytics System</p>", unsafe_allow_html=True)
with col2:
    st.markdown("<div style='text-align: right; padding-top: 15px;'><span style='background-color: #1e293b; color: #10b981; padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; border: 1px solid #10b981;'>● SYSTEM ONLINE</span></div>", unsafe_allow_html=True)

st.markdown("---")

# ----------------- DATA LOADING -----------------
@st.cache_data(ttl=10) # Cache for 10 seconds to allow simulated live updates
def load_data():
    try:
        # Load all logs from the database
        return db.load_all_logs()
    except Exception as e:
        st.error(f"Error loading from database: {e}")
        # Return empty DataFrame with matching structure
        return pd.DataFrame(columns=[
            "timestamp", "ip_address", "username", "login_status", "country",
            "event_type", "device", "severity", "is_anomaly", "threat_description",
            "hour", "recent_failures"
        ])

df = load_data()

# Ensure we have logs
if df.empty:
    st.warning("No security logs found in the database. Please make sure the data pipeline has run.")
    st.stop()

# ----------------- SIDEBAR FILTERS -----------------
st.sidebar.markdown("<h2 style='color: #3b82f6; margin-top: 0px;'>🔍 Operations Console</h2>", unsafe_allow_html=True)

# Date Range Filter
min_date = df["timestamp"].min().date()
max_date = df["timestamp"].max().date()
st.sidebar.subheader("Time Window")
date_range = st.sidebar.date_input(
    "Select Range",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date
)

# Severity Filter
st.sidebar.subheader("Severity Level")
severities = df["severity"].unique().tolist()
selected_severities = st.sidebar.multiselect(
    "Select Severity",
    options=severities,
    default=severities
)

# Anomaly Status Filter
st.sidebar.subheader("Machine Learning Filter")
ml_filter = st.sidebar.radio(
    "ML Anomaly Tag",
    options=["All Events", "ML Anomalies Only", "Normal Events Only"],
    index=0
)

# Advanced filters
st.sidebar.subheader("Context Constraints")
countries = ["All"] + sorted(df["country"].unique().tolist())
selected_country = st.sidebar.selectbox("Country Origin", countries)

event_types = ["All"] + sorted(df["event_type"].unique().tolist())
selected_event = st.sidebar.selectbox("Event Action", event_types)

devices = ["All"] + sorted(df["device"].unique().tolist())
selected_device = st.sidebar.selectbox("Access Device", devices)

# Apply filters
filtered_df = df.copy()

# Date range filtering
if len(date_range) == 2:
    start_dt = datetime.combine(date_range[0], time.min)
    end_dt = datetime.combine(date_range[1], time.max)
    filtered_df = filtered_df[(filtered_df["timestamp"] >= start_dt) & (filtered_df["timestamp"] <= end_dt)]

# Severity filtering
if selected_severities:
    filtered_df = filtered_df[filtered_df["severity"].isin(selected_severities)]
else:
    filtered_df = pd.DataFrame(columns=filtered_df.columns) # empty if nothing selected

# ML Filtering
if ml_filter == "ML Anomalies Only":
    filtered_df = filtered_df[filtered_df["is_anomaly"] == 1]
elif ml_filter == "Normal Events Only":
    filtered_df = filtered_df[filtered_df["is_anomaly"] == 0]

# Advanced categorical filtering
if selected_country != "All":
    filtered_df = filtered_df[filtered_df["country"] == selected_country]
if selected_event != "All":
    filtered_df = filtered_df[filtered_df["event_type"] == selected_event]
if selected_device != "All":
    filtered_df = filtered_df[filtered_df["device"] == selected_device]

# ----------------- KPI CARDS -----------------
kpi_total, kpi_failed, kpi_threats, kpi_anomalies = st.columns(4)

with kpi_total:
    st.markdown(f"""
    <div class="kpi-card kpi-total">
        <div class="kpi-title">Total Logs Ingested</div>
        <div class="kpi-value">{len(filtered_df):,}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_failed:
    failed_count = len(filtered_df[filtered_df["login_status"] == "Failed"])
    failed_pct = (failed_count / len(filtered_df) * 100) if len(filtered_df) > 0 else 0
    st.markdown(f"""
    <div class="kpi-card kpi-failed">
        <div class="kpi-title">Failed Logins</div>
        <div class="kpi-value">{failed_count:,} <span style='font-size:1.1rem; color:#ca8a04;'>({failed_pct:.1f}%)</span></div>
    </div>
    """, unsafe_allow_html=True)

with kpi_threats:
    high_count = len(filtered_df[filtered_df["severity"] == "High"])
    st.markdown(f"""
    <div class="kpi-card kpi-threats">
        <div class="kpi-title">High Threats</div>
        <div class="kpi-value">{high_count:,}</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_anomalies:
    anomaly_count = len(filtered_df[filtered_df["is_anomaly"] == 1])
    anomaly_pct = (anomaly_count / len(filtered_df) * 100) if len(filtered_df) > 0 else 0
    st.markdown(f"""
    <div class="kpi-card kpi-anomalies">
        <div class="kpi-title">ML Anomalies</div>
        <div class="kpi-value">{anomaly_count:,} <span style='font-size:1.1rem; color:#7c3aed;'>({anomaly_pct:.1f}%)</span></div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ----------------- CHARTS ROW 1: ATTACK TRENDS & SEVERITY -----------------
col_trend, col_sev, col_pie = st.columns([0.5, 0.25, 0.25])

with col_trend:
    st.subheader("📈 Attack Trends Over Time")
    if not filtered_df.empty:
        # Group by day and severity
        trend_data = filtered_df.copy()
        trend_data["date"] = trend_data["timestamp"].dt.date
        trend_grouped = trend_data.groupby(["date", "severity"]).size().reset_index(name="count")
        
        # Color mapping matching severity
        color_map = {"High": "#f87171", "Medium": "#facc15", "Low": "#4ade80"}
        
        fig_trend = px.area(
            trend_grouped,
            x="date",
            y="count",
            color="severity",
            color_discrete_map=color_map,
            labels={"date": "Date", "count": "Event Count", "severity": "Severity"},
            height=320,
            category_orders={"severity": ["High", "Medium", "Low"]}
        )
        
        fig_trend.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e2e8f0',
            margin=dict(l=20, r=20, t=10, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            xaxis=dict(showgrid=True, gridcolor='#1e293b'),
            yaxis=dict(showgrid=True, gridcolor='#1e293b')
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("No data available for selected filters.")

with col_sev:
    st.subheader("📊 Severity Levels")
    if not filtered_df.empty:
        sev_counts = filtered_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        
        color_map = {"High": "#f87171", "Medium": "#facc15", "Low": "#4ade80"}
        
        fig_sev = px.pie(
            sev_counts,
            values="count",
            names="severity",
            color="severity",
            color_discrete_map=color_map,
            hole=0.5,
            height=320,
            category_orders={"severity": ["High", "Medium", "Low"]}
        )
        
        fig_sev.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e2e8f0',
            margin=dict(l=20, r=20, t=10, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No data.")

with col_pie:
    st.subheader("🔑 Login Audits")
    if not filtered_df.empty:
        login_counts = filtered_df["login_status"].value_counts().reset_index()
        login_counts.columns = ["login_status", "count"]
        
        color_map = {"Success": "#34d399", "Failed": "#f87171", "Unknown": "#64748b"}
        
        fig_login = px.pie(
            login_counts,
            values="count",
            names="login_status",
            color="login_status",
            color_discrete_map=color_map,
            height=320
        )
        
        fig_login.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e2e8f0',
            margin=dict(l=20, r=20, t=10, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_login, use_container_width=True)
    else:
        st.info("No data.")

# ----------------- CHARTS ROW 2: TOP IPS, COUNTRIES & TICKER -----------------
col_ips, col_geo = st.columns(2)

with col_ips:
    st.subheader("💀 Top Threat-Triggering IP Addresses")
    # Identify IPs with the most High or Medium severity events
    threat_ips = filtered_df[filtered_df["severity"].isin(["High", "Medium"])]
    if not threat_ips.empty:
        top_ips = threat_ips["ip_address"].value_counts().reset_index().head(10)
        top_ips.columns = ["ip_address", "count"]
        
        # Merge back to get country info
        top_ips = top_ips.merge(
            filtered_df[["ip_address", "country"]].drop_duplicates(subset=["ip_address"]),
            on="ip_address",
            how="left"
        )
        
        fig_ips = px.bar(
            top_ips,
            x="count",
            y="ip_address",
            orientation="h",
            color="count",
            color_continuous_scale="Reds",
            labels={"count": "Incident Count", "ip_address": "IP Address"},
            height=320,
            hover_data=["country"]
        )
        
        fig_ips.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e2e8f0',
            coloraxis_showscale=False,
            margin=dict(l=20, r=20, t=10, b=20),
            xaxis=dict(showgrid=True, gridcolor='#1e293b'),
            yaxis=dict(autorange="reversed")
        )
        st.plotly_chart(fig_ips, use_container_width=True)
    else:
        st.info("No High/Medium severity incidents matching filters.")

with col_geo:
    st.subheader("🌍 Attack Vectors by Geolocation")
    if not filtered_df.empty:
        country_counts = filtered_df.groupby("country").size().reset_index(name="Incident Count")
        
        fig_map = px.choropleth(
            country_counts,
            locations="country",
            locationmode="country names",
            color="Incident Count",
            color_continuous_scale="Turbo",
            height=320
        )
        
        fig_map.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#e2e8f0',
            margin=dict(l=0, r=0, t=0, b=0),
            coloraxis_colorbar=dict(title="Events", thickness=15, len=0.8),
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='equirectangular',
                bgcolor='#0b0f19',
                landcolor='#1e293b',
                lakecolor='#0b0f19',
                coastlinecolor='#475569'
            )
        )
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No data.")

# ----------------- REAL-TIME LOG TICKER -----------------
st.subheader("🚨 Live Event Stream (Latest Incidents)")

# Select last 20 logs that have warnings or anomalies
ticker_df = filtered_df.sort_values(by="timestamp", ascending=False).head(20)

ticker_html = "<div class='terminal-box'>"
if not ticker_df.empty:
    for idx, row in ticker_df.iterrows():
        t_str = row["timestamp"].strftime("%H:%M:%S")
        sev_class = "ticker-low"
        if row["severity"] == "High":
            sev_class = "ticker-high"
        elif row["severity"] == "Medium":
            sev_class = "ticker-med"
            
        desc = row["threat_description"] or f"Event {row['event_type']} from {row['ip_address']}"
        anomaly_tag = " [ML ANOMALY]" if row["is_anomaly"] == 1 else ""
        
        ticker_html += f"""
        <div class='ticker-item'>
            [{t_str}] <span class='{sev_class}'>[{row['severity']}]</span> {row['ip_address']} ({row['country']}) - <b>{row['username']}</b>: {desc}<span style='color: #a855f7;'>{anomaly_tag}</span>
        </div>
        """
else:
    ticker_html += "<div class='ticker-item'>No events currently streaming.</div>"
ticker_html += "</div>"

st.markdown(ticker_html, unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# ----------------- DATA TABLE & REPORT EXPORT -----------------
col_tbl_header, col_export = st.columns([0.7, 0.3])

with col_tbl_header:
    st.subheader("🕵️ Ingested Security Logs Database")
with col_export:
    # CSV Download Button
    if not filtered_df.empty:
        csv_data = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Current View (CSV)",
            data=csv_data,
            file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="download-csv"
        )
        
        # Save to reports directory as well when exported
        if st.session_state.get("download-csv"):
            reports_path = os.path.join(project_root, "reports", "threat_report.csv")
            os.makedirs(os.path.dirname(reports_path), exist_ok=True)
            filtered_df.to_csv(reports_path, index=False)
            st.success(f"Report also backed up to {reports_path}")

# Format dataframe display
if not filtered_df.empty:
    display_df = filtered_df.copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    
    # Reorder/rename for nice viewing
    display_df = display_df[[
        "timestamp", "ip_address", "username", "login_status",
        "country", "event_type", "device", "severity", "is_anomaly", "threat_description"
    ]]
    
    display_df.columns = [
        "Timestamp", "IP Address", "Username", "Status",
        "Country", "Event Type", "Device", "Severity", "ML Anomaly?", "Details"
    ]
    
    # Styled color coding helper for dataframe
    def color_severity(val):
        color = '#ffffff'
        if val == 'High':
            color = '#f87171'
        elif val == 'Medium':
            color = '#facc15'
        elif val == 'Low':
            color = '#4ade80'
        return f'color: {color}'

    # Use streamlit datatable with styling
    st.dataframe(
        display_df.style.map(color_severity, subset=['Severity']),
        use_container_width=True,
        height=350
    )
else:
    st.info("No security logs available for current filter criteria.")

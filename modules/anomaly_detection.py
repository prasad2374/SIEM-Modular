import pandas as pd

def extract_feature_matrix(logs, feature="hour"):
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
    df = df.dropna(subset=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    counts = df["hour"].value_counts().sort_index()
    full_range = pd.Series([0]*24, index=range(24))
    full_range.update(counts)
    return full_range

def calculate_z_scores(data_series):
    mean = data_series.mean()
    std = data_series.std()
    if std == 0: std = 1e-6
    return (data_series - mean) / std

def detect_anomalies(logs, z_threshold, st):
    freq_series = extract_feature_matrix(logs)
    z_scores = calculate_z_scores(freq_series)
    anomalies = z_scores[abs(z_scores) > z_threshold]

    st.write("Log counts by hour (UTC):")
    st.bar_chart(freq_series)

    st.write("Z-scores by hour:")
    st.bar_chart(z_scores)

    if not anomalies.empty:
        st.error(f"Anomalies detected at hours: {list(anomalies.index)}")
        df = pd.DataFrame(logs)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
        df_anomalous_logs = df[df["timestamp"].dt.hour.isin(anomalies.index)]

        st.subheader("🚨 Logs During Anomalous Hours")
        if not df_anomalous_logs.empty:
            st.dataframe(df_anomalous_logs, use_container_width=True)
        else:
            st.info("No logs found during anomalous hours.")
    else:
        st.success("✅ No behavioral anomalies detected.")

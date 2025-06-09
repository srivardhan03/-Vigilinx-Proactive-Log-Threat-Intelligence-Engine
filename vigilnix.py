import streamlit as st
import pandas as pd
import numpy as np
import re
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import logging
import threading
import queue
import time

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("vigilinx_log_analyzer.log", mode='a')  # renamed log file
    ]
)

ALLOWED_FILE_TYPES = ["log", "txt", "LOG", "TXT"]

class LogParser:
    log_pattern = re.compile(
        r'(?P<ip>[\d\.]+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<url>[^ ]+) HTTP/[\d\.]+" '
        r'(?P<status>\d{3}) (?P<size>\d+) '
        r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
    )

    @staticmethod
    def parse_line(log_line: str):
        match = LogParser.log_pattern.match(log_line)
        if not match:
            logging.debug(f"Failed to parse line: {log_line}")
            return None
        data = match.groupdict()
        try:
            data['datetime'] = datetime.strptime(data['datetime'], "%d/%b/%Y:%H:%M:%S %z")
            data['status'] = int(data['status'])
            data['size'] = int(data['size'])
            data['url_length'] = len(data['url'])
            data['agent_lower'] = data['agent'].lower()
            return data
        except Exception as e:
            logging.warning(f"Error parsing fields: {log_line} - {e}")
            return None

    @staticmethod
    def detect_bot(user_agent: str) -> bool:
        keywords = ['bot', 'spider', 'crawler', 'scanner', 'curl', 'wget', 'python-requests', 'scrapy', 'httpclient']
        return any(k in user_agent.lower() for k in keywords)

    @staticmethod
    def suspicious_method(method: str) -> bool:
        allowed = {'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'}
        return method.upper() not in allowed

    @staticmethod
    def extract_features(df: pd.DataFrame) -> pd.DataFrame:
        df['is_bot'] = df['agent_lower'].apply(LogParser.detect_bot)
        df['suspicious_method'] = df['method'].apply(LogParser.suspicious_method)
        df['hour'] = df['datetime'].dt.hour
        df['day_of_week'] = df['datetime'].dt.dayofweek
        df['size_log'] = np.log1p(df['size'])
        return df

    @staticmethod
    def parse_log_text(log_text: str) -> pd.DataFrame:
        lines = log_text.strip().split('\n')
        parsed = [LogParser.parse_line(line) for line in lines]
        parsed = [p for p in parsed if p is not None]
        if not parsed:
            raise ValueError("No valid log entries found.")
        df = pd.DataFrame(parsed)
        df = LogParser.extract_features(df)
        return df

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        self.contamination = contamination
        self.encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')

    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        method_encoded = self.encoder.fit_transform(df[['method']])
        method_cols = self.encoder.get_feature_names_out(['method'])
        df_methods = pd.DataFrame(method_encoded, columns=method_cols, index=df.index)
        numeric = df[['status', 'url_length', 'is_bot', 'suspicious_method', 'hour', 'day_of_week', 'size_log']].astype(float)
        return pd.concat([df_methods, numeric], axis=1)

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        features = self.prepare_features(df)
        model = IsolationForest(contamination=self.contamination, random_state=42)
        labels = model.fit_predict(features)
        df['anomaly'] = labels
        return df

class BruteForceDetector:
    def __init__(self, threshold=20, minutes_window=1):
        self.threshold = threshold
        self.minutes_window = minutes_window
        self.model = RandomForestClassifier(random_state=42)
        self.encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.is_trained = False

    def compute_requests_per_minute(self, df: pd.DataFrame) -> pd.DataFrame:
        df['minute'] = df['datetime'].dt.floor(f'{self.minutes_window}T')
        rpm = df.groupby(['ip', 'minute']).size().reset_index(name='requests_per_minute')
        df = df.merge(rpm, how='left', on=['ip', 'minute'])
        return df

    def label_brute_force(self, df: pd.DataFrame) -> pd.DataFrame:
        df['brute_force_label'] = (df['requests_per_minute'] > self.threshold).astype(int)
        return df

    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        method_encoded = self.encoder.transform(df[['method']])
        method_cols = self.encoder.get_feature_names_out(['method'])
        df_methods = pd.DataFrame(method_encoded, columns=method_cols, index=df.index)
        numeric = df[['status', 'url_length', 'is_bot', 'suspicious_method', 'hour', 'day_of_week', 'size_log', 'requests_per_minute']].astype(float)
        return pd.concat([df_methods, numeric], axis=1)

    def train(self, df: pd.DataFrame):
        df = self.compute_requests_per_minute(df)
        df = self.label_brute_force(df)
        self.encoder.fit(df[['method']])
        X = self.prepare_features(df)
        y = df['brute_force_label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred, zero_division=0)
        logging.info("Brute Force Classifier training report:\n" + report)
        self.is_trained = True
        return report

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        df = self.compute_requests_per_minute(df)
        X = self.prepare_features(df)
        preds = self.model.predict(X)
        df['brute_force_pred'] = preds
        return df

def main():
    st.set_page_config(page_title="Vigilinx: Proactive Log Threat Intelligence Engine", layout="wide")
    st.title("🛡️ Vigilinx: Proactive Log Threat Intelligence Engine")

    st.markdown("""
    Upload your `.log` or `.txt` Apache-style log file or paste log lines in real-time to analyze for anomalies and brute force attempts.
    Use the sidebar to configure detection parameters.
    """)

    with st.sidebar:
        st.header("Configuration")
        contamination = st.slider("Anomaly Contamination (Isolation Forest)", 0.01, 0.20, 0.05, step=0.01)
        bf_threshold = st.slider("Brute Force Requests/Minute Threshold", 1, 100, 20)
        bf_minutes = st.slider("Brute Force Detection Window (minutes)", 1, 10, 1)
        st.markdown("---")
        st.markdown("**About:** Vigilinx is a proactive security log analyzer using heuristic and machine learning detection.")

    uploaded_file = st.file_uploader("Upload Log File", type=ALLOWED_FILE_TYPES)

    real_time_logs = []
    if uploaded_file:
        try:
            text = uploaded_file.read().decode("utf-8")
            real_time_logs.append(text)
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")

    # Text area for real-time logs input (multi-line)
    realtime_input = st.text_area("Paste Real-Time Log Lines Here (optional):", height=200)
    if realtime_input:
        real_time_logs.append(realtime_input)

    if real_time_logs:
        combined_logs = "\n".join(real_time_logs)
        try:
            df_logs = LogParser.parse_log_text(combined_logs)

            tabs = st.tabs(["Summary", "Suspicious Activity", "Anomaly Detection", "Brute Force Detection"])

            with tabs[0]:
                st.subheader("Summary")
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Total Entries", f"{len(df_logs):,}")
                c2.metric("Unique IPs", f"{df_logs['ip'].nunique():,}")
                c3.metric("Bot Requests", f"{df_logs['is_bot'].sum():,}")
                c4.metric("Suspicious Methods", f"{df_logs['suspicious_method'].sum():,}")
                c5.metric("Time Range", f"{df_logs['datetime'].min().strftime('%Y-%m-%d')} to {df_logs['datetime'].max().strftime('%Y-%m-%d')}")

                with st.expander("HTTP Status Distribution"):
                    status_counts = df_logs['status'].value_counts().sort_index()
                    st.bar_chart(status_counts)

                with st.expander("Top 10 IPs by Request Count"):
                    top_ips = df_logs['ip'].value_counts().head(10)
                    st.bar_chart(top_ips)

                with st.expander("Request Volume Over Time (Hourly)"):
                    hourly = df_logs.set_index('datetime').resample('H').size()
                    st.line_chart(hourly)

            with tabs[1]:
                st.subheader("Suspicious Activity")
                bots = df_logs[df_logs['is_bot']]
                suspicious_methods = df_logs[df_logs['suspicious_method']]

                st.markdown(f"**Bots Detected:** {len(bots):,}")
                with st.expander("Bot Requests Table"):
                    st.dataframe(bots[['datetime', 'ip', 'method', 'agent']].sort_values(by='datetime'), use_container_width=True)

                st.markdown(f"**Suspicious Methods Detected:** {len(suspicious_methods):,}")
                with st.expander("Suspicious Methods Table"):
                    st.dataframe(suspicious_methods[['datetime', 'ip', 'method', 'url']].sort_values(by='datetime'), use_container_width=True)

            with tabs[2]:
                st.subheader("Anomaly Detection (Isolation Forest)")
                anomaly_detector = AnomalyDetector(contamination=contamination)
                df_anomaly = anomaly_detector.detect(df_logs)
                anomalies = df_anomaly[df_anomaly['anomaly'] == -1]

                st.markdown(f"**Anomalies Detected:** {len(anomalies):,}")

                with st.expander("Anomalies Table"):
                    st.dataframe(anomalies[['datetime', 'ip', 'method', 'url', 'status']].sort_values(by='datetime'), use_container_width=True)

                with st.expander("Anomaly Status Distribution"):
                    st.bar_chart(df_anomaly['anomaly'].value_counts().sort_index())

                with st.expander("Anomaly Count by Hour"):
                    hourly_anom = anomalies.set_index('datetime').resample('H').size()
                    st.line_chart(hourly_anom)

            with tabs[3]:
                st.subheader("Brute Force Detection")
                bf_detector = BruteForceDetector(threshold=bf_threshold, minutes_window=bf_minutes)

                # Train before prediction
                bf_detector.train(df_logs)

                df_bf = bf_detector.predict(df_logs)
                brute_forces = df_bf[df_bf['brute_force_pred'] == 1]

                st.markdown(f"**Brute Force Attempts Detected:** {len(brute_forces):,}")

                with st.expander("Brute Force Attempts Details"):
                    st.dataframe(brute_forces[['datetime', 'ip', 'method', 'url', 'requests_per_minute']].sort_values(by='datetime'), use_container_width=True)

                with st.expander("Requests per Minute Distribution"):
                    st.bar_chart(df_bf['requests_per_minute'].value_counts().sort_index())

        except Exception as e:
            st.error(f"Failed to parse logs or analyze: {e}")
    else:
        st.info("Please upload a log file or paste log lines above to start analysis.")

if __name__ == "__main__":
    main()

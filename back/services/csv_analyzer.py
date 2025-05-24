import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from io import StringIO
import re
import asyncio


async def analyze_csv_logs(content):
    try:
        chunk_size = 50000
        df_list = []
        required_columns = ["eventid", "systemtime", "ipaddress", "eventdescription", "scriptcontent"]

        try:
            chunks = pd.read_csv(StringIO(content), chunksize=chunk_size, skipinitialspace=True, on_bad_lines='warn')
        except pd.errors.ParserError as pe:
            print(f"CSV parsing error: {pe}. Skipping problematic lines.")
            chunks = pd.read_csv(StringIO(content), chunksize=chunk_size, skipinitialspace=True, on_bad_lines='skip')

        for chunk in chunks:
            headers = chunk.columns.tolist()
            print(f"Original columns in chunk: {headers}")

            chunk.columns = chunk.columns.str.strip().str.lower().str.replace(" ", "_")
            processed_headers = chunk.columns.tolist()
            print(f"Processed columns in chunk: {processed_headers}")

            missing_columns = [col for col in required_columns if col not in processed_headers]
            if missing_columns:
                print(f"Warning: missing columns after processing {missing_columns}. Continuing with available data.")
            available_columns = [col for col in required_columns if col in processed_headers]
            if not available_columns:
                print("Error: required columns not found. Returning default response.")
                return {
                    "suspicious_events": [],
                    "issues": {
                        "Errors": [],
                        "Warnings": [],
                        "Failures": [],
                        "IP_Addresses": [],
                        "PowerShell_Scripts": []
                    },
                    "time_series": {},
                    "heatmap_data": {},
                    "anomaly_prob": []
                }

            chunk = chunk.dropna(subset=available_columns)
            if not chunk.empty:
                df_list.append(chunk)

        if not df_list:
            print("Warning: no valid data after cleaning. Returning default response.")
            return {
                "suspicious_events": [],
                "issues": {
                    "Errors": [],
                    "Warnings": [],
                    "Failures": [],
                    "IP_Addresses": [],
                    "PowerShell_Scripts": []
                },
                "time_series": {},
                "heatmap_data": {},
                "anomaly_prob": []
            }

        df = pd.concat(df_list)
        print(f"Row count after cleaning: {len(df)}")

        df['systemtime'] = pd.to_datetime(df['systemtime'])
        df['hour'] = df['systemtime'].dt.hour

        df['failed_logon'] = (df['eventid'] == 4625).astype(int)

        suspicious_patterns = [
            r'Invoke-WebRequest.*http',
            r'TCPClient',
            r'Invoke-Command.*ComputerName'
        ]
        df['suspicious_script'] = df.apply(
            lambda row: 1 if row['eventid'] == 4104 and pd.notna(row['scriptcontent']) and any(
                re.search(pattern, str(row['scriptcontent']), re.IGNORECASE)
                for pattern in suspicious_patterns
            ) else 0,
            axis=1
        )

        df['network_anomaly'] = df.apply(
            lambda row: 1 if row['eventid'] == 5156 and (
                    str(row['ipaddress']).startswith('192.168.1.2') or
                    str(row['destinationport']) == '80' and str(row['sourceport']).startswith('543')
            ) else 0,
            axis=1
        )

        features = df[['hour', 'failed_logon', 'suspicious_script', 'network_anomaly']].values
        print(f"Feature shape: {features.shape}")

        try:
            kmeans = KMeans(n_clusters=2, random_state=42)
            df['cluster'] = kmeans.fit_predict(features)
            print(f"Unique clusters: {df['cluster'].value_counts().to_dict()}")
        except Exception as e:
            print(f"Warning: K-Means failed with error {e}. Skipping clustering.")
            df['cluster'] = 0

        minority_cluster = df['cluster'].value_counts().idxmin()
        df['anomaly'] = (df['cluster'] == minority_cluster).astype(int)
        print(f"Anomalies detected: {df['anomaly'].sum()}")

        suspicious_events = df[df['anomaly'] == 1]['systemtime'].astype(str).unique().tolist()

        errors = df[df['failed_logon'] > 0]['eventdescription'].unique().tolist()

        warnings = df[df['suspicious_script'] > 0]['eventdescription'].unique().tolist()

        failures = df[df['network_anomaly'] > 0]['eventdescription'].unique().tolist()
        anomalous_ips = df[df['network_anomaly'] > 0]['ipaddress'].dropna().unique()
        suspicious_scripts = df[df['suspicious_script'] > 0]['scriptcontent'].dropna().unique()
        failures.extend([f"Suspicious IP Address: {ip}" for ip in anomalous_ips])
        failures.extend(
            [f"Suspicious PowerShell Script: {script}" for script in suspicious_scripts if script and script != '-'])

        time_series = df[df['anomaly'] == 1].groupby(df['systemtime'].dt.floor('h')).size().to_dict()
        heatmap_data = df.groupby([df['systemtime'].dt.hour, 'eventid']).size().unstack(fill_value=0).to_dict()

        return {
            "suspicious_events": suspicious_events,
            "issues": {
                "Errors": errors,
                "Warnings": warnings,
                "Failures": failures,
                "IP_Addresses": df[df['anomaly'] == 1]['ipaddress'].dropna().unique().tolist(),
                "PowerShell_Scripts": df[df['suspicious_script'] > 0]['scriptcontent'].dropna().unique().tolist()
            },
            "time_series": time_series,
            "heatmap_data": heatmap_data,
            "anomaly_prob": []
        }
    except Exception as e:
        print(f"Error analyzing CSV: {e}. Returning default response.")
        return {
            "suspicious_events": [],
            "issues": {
                "Errors": [],
                "Warnings": [],
                "Failures": [],
                "IP_Addresses": [],
                "PowerShell_Scripts": []
            },
            "time_series": {},
            "heatmap_data": {},
            "anomaly_prob": []
        }
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
import re
import asyncio

async def analyze_log_file(content):
    try:
        log_entries = []
        for line in content.splitlines():
            match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (\w+), (CBS|CSI), (.+)', line)
            if match:
                timestamp, level, component, message = match.groups()
                event_id_match = re.search(r'EventID: (\d+)', message)
                user_match = re.search(r'TargetUserName: ([^\s,]+)', message)
                ip_match = re.search(r'IpAddress: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                workstation_match = re.search(r'WorkstationName: ([^\s,]+)', message)
                process_match = re.search(r'ProcessName: ([^\s,]+)', message)
                desc_match = re.search(r'EventDescription: ([^,]+)', message)
                script_match = re.search(r'ScriptContent: ([^,]+)', message)
                sport_match = re.search(r'SourcePort: (\d+)', message)
                dport_match = re.search(r'DestinationPort: (\d+)', message)

                event_id = event_id_match.group(1) if event_id_match else None
                target_user = user_match.group(1) if user_match else None
                ip_address = ip_match.group(1) if ip_match else None
                workstation = workstation_match.group(1) if workstation_match else None
                process_name = process_match.group(1) if process_match else None
                event_desc = desc_match.group(1) if desc_match else message
                script_content = script_match.group(1) if script_match else None
                source_port = sport_match.group(1) if sport_match else None
                dest_port = dport_match.group(1) if dport_match else None

                if timestamp and event_id:
                    log_entries.append({
                        'eventid': event_id,
                        'systemtime': timestamp,
                        'targetusername': target_user,
                        'ipaddress': ip_address,
                        'workstationname': workstation,
                        'processname': process_name,
                        'eventdescription': event_desc,
                        'scriptcontent': script_content,
                        'sourceport': source_port,
                        'destinationport': dest_port
                    })

        if not log_entries:
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

        df = pd.DataFrame(log_entries)
        df['systemtime'] = pd.to_datetime(df['systemtime'], errors='coerce')
        df = df.dropna(subset=['systemtime'])
        if df.empty:
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

        df['hour'] = df['systemtime'].dt.hour
        df['failed_logon'] = (df['eventid'] == '4625').astype(int)

        suspicious_patterns = [
            r'Invoke-WebRequest.*http',
            r'TCPClient',
            r'Invoke-Command.*ComputerName'
        ]
        df['suspicious_script'] = df.apply(
            lambda row: 1 if row['eventid'] == '4104' and pd.notna(row['scriptcontent']) and any(
                re.search(pattern, str(row['scriptcontent']), re.IGNORECASE)
                for pattern in suspicious_patterns
            ) else 0,
            axis=1
        )

        df['network_anomaly'] = df.apply(
            lambda row: 1 if row['eventid'] == '5156' and (
                pd.notna(row['ipaddress']) and str(row['ipaddress']).startswith('192.168.1.2') or
                pd.notna(row['destinationport']) and str(row['destinationport']) == '80' and
                pd.notna(row['sourceport']) and str(row['sourceport']).startswith('543')
            ) else 0,
            axis=1
        )

        features = df[['hour', 'failed_logon', 'suspicious_script', 'network_anomaly']].values
        if features.shape[0] > 1:
            try:
                kmeans = KMeans(n_clusters=2, random_state=42)
                df['cluster'] = kmeans.fit_predict(features)
            except Exception:
                df['cluster'] = 0
        else:
            df['cluster'] = 0

        minority_cluster = df['cluster'].value_counts().idxmin() if df['cluster'].nunique() > 1 else 0
        df['anomaly'] = (df['cluster'] == minority_cluster).astype(int)

        suspicious_events = df[df['anomaly'] == 1]['systemtime'].astype(str).unique().tolist()
        errors = df[df['failed_logon'] > 0]['eventdescription'].unique().tolist()
        warnings = df[df['suspicious_script'] > 0]['eventdescription'].unique().tolist()
        failures = df[df['network_anomaly'] > 0]['eventdescription'].unique().tolist()
        anomalous_ips = df[df['network_anomaly'] > 0]['ipaddress'].dropna().unique()
        suspicious_scripts = df[df['suspicious_script'] > 0]['scriptcontent'].dropna().unique()
        failures.extend([f"Suspicious IP Address: {ip}" for ip in anomalous_ips])
        failures.extend([f"Suspicious PowerShell Script: {script}" for script in suspicious_scripts if script and script != '-'])

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
    except Exception:
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
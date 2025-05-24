import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
import re
import tempfile
import os
import Evtx.Evtx as evtx
import asyncio

async def analyze_evt_file(content):
    try:
        if not content or not isinstance(content, bytes):
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

        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        log_entries = []
        try:
            with evtx.Evtx(temp_file_path) as log:
                for record in log.records():
                    event_xml = record.xml()
                    time_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', event_xml)
                    event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', event_xml)
                    user_match = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', event_xml)
                    ip_match = re.search(r'<Data Name="(SourceIpAddress|IpAddress)">([^<]+)</Data>', event_xml)
                    workstation_match = re.search(r'<Data Name="WorkstationName">([^<]+)</Data>', event_xml)
                    process_match = re.search(r'<Data Name="Image">([^<]+)</Data>', event_xml)
                    command_match = re.search(r'<Data Name="CommandLine">([^<]+)</Data>', event_xml)
                    port_match = re.search(r'<Data Name="SourcePort">([^<]+)</Data>', event_xml)
                    dest_port_match = re.search(r'<Data Name="DestinationPort">([^<]+)</Data>', event_xml)
                    desc_match = re.search(r'<Data Name="EventDescription">([^<]+)</Data>', event_xml)

                    timestamp = time_match.group(1) if time_match else None
                    event_id = event_id_match.group(1) if event_id_match else None
                    target_user = user_match.group(1) if user_match else None
                    ip_address = ip_match.group(2) if ip_match else None
                    workstation = workstation_match.group(1) if workstation_match else None
                    process_name = process_match.group(1) if process_match else None
                    script_content = command_match.group(1) if command_match else None
                    source_port = port_match.group(1) if port_match else None
                    dest_port = dest_port_match.group(1) if dest_port_match else None
                    event_desc = desc_match.group(1) if desc_match else event_xml

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
        finally:
            os.unlink(temp_file_path)

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
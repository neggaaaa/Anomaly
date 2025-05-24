from services.csv_analyzer import analyze_csv_logs
from services.log_analyzer import analyze_log_file
from services.evtx_analyzer import analyze_evt_file

async def analyze_logs(content, file_type):
    try:
        if file_type.lower() in ['.csv']:
            return await analyze_csv_logs(content)
        elif file_type.lower() in ['.log']:
            return await analyze_log_file(content)
        elif file_type.lower() in ['.evtx']:
            return await analyze_evt_file(content)
        else:
            raise ValueError("Unsupported file type. Only .csv, .log, or .evtx are supported")
    except Exception:
        return {
            "suspicious_events": [],
            "issues": {"Errors": [], "Warnings": [], "Failures": []},
            "time_series": {},
            "heatmap_data": {},
            "anomaly_prob": []
        }

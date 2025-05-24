async def generate_report(analysis):
    if "suspicious_ports" in analysis:
        recommendations = [
            f"Block suspicious ports: {', '.join(map(str, analysis['suspicious_ports']))}",
            "Enable MFA for affected users",
            "Monitor and restrict PowerShell use from external IPs",
            "Implement rate limiting to prevent brute-force attacks"
        ]
        report = {
            "suspicious_ports": analysis["suspicious_ports"],
            "attacks_detected": analysis["attacks"],
            "time_series_data": analysis["time_series"],
            "heatmap_data": analysis["heatmap_data"],
            "recommendations": recommendations,
            "anomaly_probabilities": analysis["anomaly_prob"]
        }
    else:
        recommendations = [
            f"Investigate suspicious events: {', '.join(analysis['suspicious_events'])}",
            "Check error codes and eliminate root causes",
            "Monitor repeated warnings",
            "Set alerts for critical failures"
        ]
        report = {
            "suspicious_events": analysis["suspicious_events"],
            "issues_detected": analysis["issues"],
            "time_series_data": analysis["time_series"],
            "recommendations": recommendations,
            "anomaly_probabilities": analysis["anomaly_prob"]
        }
    return report

import { useState, useEffect } from "react";
import { useData } from "../../context/DataContext";

const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
  </svg>
);

const RecommendationsPanel = () => {
  const { data } = useData();
  const [recommendations, setRecommendations] = useState([]);

  useEffect(() => {
    if (!data) {
      setRecommendations(["Upload log files to see recommendations"]);
      return;
    }

    if (data.recommendations && data.recommendations.length > 0) {
      setRecommendations(data.recommendations);
      return;
    }

    const generatedRecommendations = [];

    if (data.suspicious_events && data.suspicious_events.length > 0) {
      const heatmapData = data.suspicious_events.reduce((acc, event) => {
        const date = new Date(event);
        const minute = date.getMinutes();
        const key = `${minute}`;
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});

      const highFrequencyEvents = Object.values(heatmapData).some(count => count > 5);
      if (highFrequencyEvents) {
        generatedRecommendations.push("Check system for overload or errors due to high event frequency");
      }

      const eventSpikes = Object.values(heatmapData).some(count => count > 10);
      if (eventSpikes) {
        generatedRecommendations.push("Monitor system performance for event spikes");
      }

      const totalEvents = data.suspicious_events.length;
      if (totalEvents > 20) {
        generatedRecommendations.push("Consider implementing additional security layers to reduce suspicious activities");
      }
    }

    const issuesSource = data.issues_detected || data.issues;
    if (issuesSource) {
      if (issuesSource.Errors && issuesSource.Errors.length > 0) {
        generatedRecommendations.push("Review and fix detected errors to prevent potential security breaches");
      }

      if (issuesSource.Failures && issuesSource.Failures.length > 0) {
        generatedRecommendations.push("Investigate system failures that could lead to vulnerability exploitation");
      }
    }

    if (data.attacks) {
      if (data.attacks["Brute Force"] && data.attacks["Brute Force"].length > 0) {
        generatedRecommendations.push("Implement rate limiting to prevent brute force attacks");
        generatedRecommendations.push("Consider adding CAPTCHA to login forms");
      }

      if (data.attacks["Credential Stuffing"] && data.attacks["Credential Stuffing"].length > 0) {
        generatedRecommendations.push("Enforce strong password policies");
        generatedRecommendations.push("Implement multi-factor authentication");
      }
    }

    if (generatedRecommendations.length === 0) {
      generatedRecommendations.push("Continue monitoring system for security issues");
    }

    setRecommendations(generatedRecommendations);
  }, [data]);

  return (
    <div className="dashboard-card h-80">
      <h2 className="text-danger-500 text-lg font-semibold mb-4">Recommendations</h2>
      <div className="h-60 overflow-y-auto">
        {recommendations.length > 0 ? (
          <ul className="space-y-3">
            {recommendations.map((rec, index) => (
              <li key={index} className="flex items-start space-x-2 p-2 hover:bg-dark-700 rounded-md transition-colors">
                <div className="mt-0.5 flex-shrink-0 text-success-500">
                  <CheckIcon />
                </div>
                <span className="text-gray-300 text-sm">{rec}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="h-full flex items-center justify-center">
            <p className="text-gray-500">No recommendations available</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default RecommendationsPanel;
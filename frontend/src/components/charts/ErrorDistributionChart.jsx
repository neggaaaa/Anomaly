import { useState, useEffect } from "react";
import Chart from "react-apexcharts";
import { useData } from "../../context/DataContext";

const ErrorDistributionChart = () => {
  const { data } = useData();
  const [chartData, setChartData] = useState({
    options: {
      chart: { 
        type: "pie", 
        background: "#1e293b", 
        foreColor: "#cbd5e1",
        animations: {
          enabled: true,
          speed: 500,
          animateGradually: {
            enabled: true,
            delay: 150
          },
          dynamicAnimation: {
            enabled: true,
            speed: 350
          }
        }
      },
      colors: ["#ef4444", "#f59e0b", "#3b82f6"],
      labels: ["Errors", "Warnings", "Failures"],
      title: { 
        text: "Issue Distribution", 
        style: { color: "#e2e8f0", fontSize: "16px", fontWeight: 600 }
      },
      legend: { 
        position: "bottom", 
        horizontalAlign: "center",
        fontSize: "14px",
        markers: {
          width: 12,
          height: 12,
          radius: 12
        },
        itemMargin: {
          horizontal: 10,
          vertical: 5
        },
        onItemClick: {
          toggleDataSeries: true
        },
        onItemHover: {
          highlightDataSeries: true
        }
      },
      dataLabels: {
        enabled: true,
        formatter: function(val, opts) {
          return opts.w.config.series[opts.seriesIndex];
        },
        style: {
          fontSize: '14px',
          fontWeight: 'bold',
          colors: ["#1e293b"]
        },
        dropShadow: {
          enabled: false
        }
      },
      responsive: [
        { 
          breakpoint: 640, 
          options: { 
            chart: { height: "200px" }, 
            legend: { position: "bottom", fontSize: "12px" },
            dataLabels: {
              fontSize: '12px'
            }
          } 
        },
        { 
          breakpoint: 1024, 
          options: { 
            chart: { height: "300px" }, 
            legend: { position: "bottom" } 
          } 
        },
      ],
      tooltip: {
        enabled: true,
        theme: 'dark',
        y: {
          formatter: function(value) {
            return value + " issues";
          }
        }
      },
    },
    series: []
  });

  useEffect(() => {
    if (!data) return;

    try {
      let issues;
      if (data.issues_detected) {
        issues = data.issues_detected;
      } else if (data.issues) {
        issues = data.issues;
      } else {
        return;
      }

      const { Errors = [], Warnings = [], Failures = [] } = issues;
      const series = [Errors.length, Warnings.length, Failures.length];
      
      setChartData(prev => ({
        ...prev,
        series
      }));
    } catch (error) {
      console.error('Error processing error distribution data:', error);
    }
  }, [data]);

  if (!data || (!data.issues_detected && !data.issues)) {
    return (
      <div className="dashboard-card h-80 flex items-center justify-center">
        <p className="text-gray-400 text-sm">No error data available</p>
      </div>
    );
  }

  const totalIssues = chartData.series.reduce((acc, val) => acc + val, 0);
  
  if (totalIssues === 0) {
    return (
      <div className="dashboard-card h-80 flex items-center justify-center">
        <p className="text-gray-400 text-sm">No issues detected</p>
      </div>
    );
  }

  return (
    <div className="dashboard-card h-80 chart-container">
      <Chart 
        options={chartData.options} 
        series={chartData.series} 
        type="pie" 
        height="100%" 
      />
    </div>
  );
};

export default ErrorDistributionChart;
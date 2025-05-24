import { useState, useEffect } from "react";
import Chart from "react-apexcharts";
import { useData } from "../../context/DataContext";

const AnomalyChart = () => {
  const { data } = useData();
  const [chartData, setChartData] = useState({
    options: {
      chart: { 
        type: "line", 
        height: 300, 
        background: "#1e293b", 
        foreColor: "#fff",
        toolbar: {
          show: true,
          tools: {
            download: true,
            selection: true,
            zoom: true,
            zoomin: true,
            zoomout: true,
            pan: true,
            reset: true
          }
        },
        animations: {
          enabled: true,
          easing: 'easeinout',
          speed: 800,
          animateGradually: {
            enabled: true,
            delay: 150
          },
          dynamicAnimation: {
            enabled: true,
            speed: 350
          }
        },
        zoom: {
          autoScaleYaxis: true
        }
      },
      xaxis: {
        type: "datetime",
        labels: { 
          style: { colors: "#fff", fontSize: "10px" }, 
          format: "HH:mm" 
        },
        axisBorder: { color: "#4b5563" },
      },
      yaxis: { 
        labels: { style: { colors: "#fff", fontSize: "10px" } }, 
        axisBorder: { color: "#4b5563" },
        title: {
          text: 'Number of Events',
          style: {
            color: '#cbd5e1',
            fontSize: '12px',
            fontWeight: 500
          }
        }
      },
      stroke: { curve: "smooth", width: 3 },
      colors: ["#ef4444"],
      title: { 
        text: "Anomalies Timeline", 
        style: { color: "#fff", fontSize: "16px", fontWeight: 600 } 
      },
      grid: { 
        show: true, 
        borderColor: "#4b5563", 
        strokeDashArray: 3,
        position: 'back'
      },
      noData: { 
        text: "No data available", 
        style: { color: "#fff", fontSize: "14px" } 
      },
      tooltip: {
        theme: 'dark',
        x: {
          format: 'HH:mm:ss'
        }
      },
      markers: {
        size: 5,
        colors: ['#ef4444'],
        strokeColors: '#fff',
        strokeWidth: 2,
        hover: {
          size: 7,
        }
      },
    },
    series: [{ name: "Anomalies", data: [] }]
  });

  useEffect(() => {
    if (!data || !data.suspicious_events || data.suspicious_events.length === 0) return;

    try {
      const timeSeries = [];
      const timestamps = data.suspicious_events.map(event => new Date(event).getTime());
      const minTime = Math.min(...timestamps);
      const maxTime = Math.max(...timestamps);
      const centerTime = minTime + (maxTime - minTime) / 2;
      const range = (maxTime - minTime) * 1.5;
      const viewMin = centerTime - range / 2;
      const viewMax = centerTime + range / 2;

      const eventsBySecond = data.suspicious_events.reduce((acc, event) => {
        const date = new Date(event);
        const time = date.getTime();
        acc[time] = (acc[time] || 0) + 1;
        return acc;
      }, {});

      Object.keys(eventsBySecond).forEach(time => {
        timeSeries.push({
          x: parseInt(time),
          y: eventsBySecond[time]
        });
      });

      setChartData(prev => ({
        ...prev,
        options: {
          ...prev.options,
          xaxis: {
            ...prev.options.xaxis,
            min: viewMin,
            max: viewMax,
          }
        },
        series: [{ name: "Anomalies", data: timeSeries }]
      }));
    } catch (error) {
      console.error('Error processing anomaly chart data:', error);
    }
  }, [data]);

  return (
    <div className="dashboard-card h-80 chart-container">
      <Chart 
        options={chartData.options} 
        series={chartData.series} 
        type="line" 
        height="100%" 
      />
    </div>
  );
};

export default AnomalyChart;
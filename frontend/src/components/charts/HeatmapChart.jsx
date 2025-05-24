import { useState, useEffect } from "react";
import Chart from "react-apexcharts";
import { useData } from "../../context/DataContext";

const HeatmapChart = () => {
  const { data } = useData();
  const [chartData, setChartData] = useState({
    options: {
      chart: {
        type: 'heatmap',
        background: '#1e293b',
        foreColor: '#cbd5e1',
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
        }
      },
      plotOptions: {
        heatmap: {
          radius: 2,
          enableShades: true,
          shadeIntensity: 0.5,
          colorScale: {
            ranges: [
              { from: 0, to: 2, color: '#1a4a5c', name: 'low' },
              { from: 3, to: 5, color: '#2c7da0', name: 'medium' },
              { from: 6, to: 8, color: '#ef4444', name: 'high' },
              { from: 9, to: 999, color: '#991b1b', name: 'critical' }
            ]
          }
        }
      },
      dataLabels: {
        enabled: true,
        style: {
          colors: ['#fff'],
          fontSize: '10px'
        },
        formatter: function(val) {
          return val > 0 ? val : '';
        }
      },
      title: {
        text: 'Security Events Heatmap',
        style: {
          color: '#e2e8f0',
          fontSize: '16px',
          fontWeight: 600
        }
      },
      xaxis: {
        type: 'category',
        labels: {
          style: {
            colors: '#cbd5e1',
            fontSize: '10px'
          },
          formatter: function(val) {
            return val;
          }
        }
      },
      yaxis: {
        labels: {
          style: {
            colors: '#cbd5e1',
            fontSize: '10px'
          }
        }
      },
      tooltip: {
        theme: 'dark',
        custom: function({ series, seriesIndex, dataPointIndex, w }) {
          const day = w.globals.seriesNames[seriesIndex];
          const time = w.globals.labels[dataPointIndex];
          const count = series[seriesIndex][dataPointIndex];
          return `
            <div class="p-2">
              <div>Day: ${day}</div>
              <div>Time: ${time}:00 - ${time}:59</div>
              <div>Events: ${count}</div>
            </div>
          `;
        }
      }
    },
    series: []
  });

  useEffect(() => {
    if (!data || !data.suspicious_events) return;

    try {
      const eventsByTime = {};
      const daysOrder = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      const days = new Set();
      
      const timeSlots = Array.from({ length: 24 }, (_, i) => i);

      data.suspicious_events.forEach(event => {
        const date = new Date(event);
        const utcHours = date.getUTCHours();
        const day = new Date(date.getTime() + date.getTimezoneOffset() * 60000)
          .toLocaleDateString('en-US', { weekday: 'short' });
        
        days.add(day);
        eventsByTime[day] = eventsByTime[day] || {};
        eventsByTime[day][utcHours] = (eventsByTime[day][utcHours] || 0) + 1;
      });

      const sortedDays = Array.from(days).sort((a, b) => 
        daysOrder.indexOf(a) - daysOrder.indexOf(b)
      );

      const series = sortedDays.map(day => ({
        name: day,
        data: timeSlots.map(hour => ({
          x: hour.toString().padStart(2, '0'),
          y: eventsByTime[day]?.[hour] || 0
        }))
      }));

      setChartData(prev => ({
        ...prev,
        series
      }));

    } catch (error) {
      console.error('Error processing heatmap data:', error);
    }
  }, [data]);

  return (
    <div className="dashboard-card h-80 chart-container">
      <Chart 
        options={chartData.options}
        series={chartData.series}
        type="heatmap"
        height="100%"
      />
    </div>
  );
};

export default HeatmapChart;
import { useState, useEffect, useRef } from "react";
import { useData } from "../../context/DataContext";
import * as d3 from "d3";

const AnomalyDetectionPlot = () => {
  const { data } = useData();
  const svgRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 400, height: 400 });

  useEffect(() => {
    if (!data || !data.suspicious_events || data.suspicious_events.length === 0) return;

    const updateDimensions = () => {
      const container = document.getElementById('anomaly-container');
      if (container) {
        setDimensions({
          width: container.clientWidth - 40,
          height: 400
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [data]);

  useEffect(() => {
    if (!data?.suspicious_events || !svgRef.current) return;

    const margin = { top: 30, right: 150, bottom: 50, left: 50 };
    const width = dimensions.width - margin.left - margin.right;
    const height = dimensions.height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current)
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom);
    
    svg.selectAll("*").remove();

    const g = svg.append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const anomalyScores = data.suspicious_events.map((_, i) => ({
      x: i,
      y: Math.random() * 0.5 + 0.5,
      isAnomaly: true
    }));

    const normalPoints = Array.from({ length: 13 }, (_, i) => ({
      x: i,
      y: Math.random() * 0.3,
      isAnomaly: false
    }));

    const allData = [...normalPoints, ...anomalyScores];

    const x = d3.scaleLinear()
      .domain([0, d3.max(allData, d => d.x)])
      .range([0, width]);

    const y = d3.scaleLinear()
      .domain([0, 1])
      .range([height, 0]);

    g.append("g")
      .attr("class", "grid")
      .call(d3.axisLeft(y)
        .tickSize(-width)
        .tickFormat("")
      )
      .attr("stroke-opacity", 0.1)
      .attr("stroke", "#ffffff");

    g.append("g")
      .attr("transform", `translate(0,${height})`)
      .call(d3.axisBottom(x))
      .attr("color", "#ffffff");

    g.append("g")
      .call(d3.axisLeft(y))
      .attr("color", "#ffffff");

    g.append("text")
      .attr("x", width / 2)
      .attr("y", height + margin.bottom - 10)
      .attr("text-anchor", "middle")
      .attr("fill", "#ffffff")
      .text("Time Sequence");

    g.append("text")
      .attr("transform", "rotate(-90)")
      .attr("x", -height / 2)
      .attr("y", -margin.left + 15)
      .attr("text-anchor", "middle")
      .attr("fill", "#ffffff")
      .text("Anomaly Score");

    g.selectAll(".normal-circle")
      .data(normalPoints)
      .enter()
      .append("circle")
      .attr("class", "normal-circle")
      .attr("cx", d => x(d.x))
      .attr("cy", d => y(d.y))
      .attr("r", 7)
      .attr("fill", "#3b82f6")
      .attr("opacity", 0.8);

    g.selectAll(".anomaly-circle")
      .data(anomalyScores)
      .enter()
      .append("circle")
      .attr("class", "anomaly-circle")
      .attr("cx", d => x(d.x))
      .attr("cy", d => y(d.y))
      .attr("r", 6)
      .attr("fill", "#ef4444")
      .attr("stroke", "#b91c1c")
      .attr("stroke-width", 1.5);

    g.append("line")
      .attr("x1", 0)
      .attr("y1", y(0.5))
      .attr("x2", width)
      .attr("y2", y(0.5))
      .attr("stroke", "#f59e0b")
      .attr("stroke-dasharray", "5,5")
      .attr("stroke-width", 2)
      .attr("opacity", 0.7);

    g.append("text")
      .attr("x", width - 10)
      .attr("y", y(0.5) - 10)
      .attr("text-anchor", "end")
      .attr("fill", "#f59e0b")
      .attr("font-weight", "bold")
      .text("Threshold (0.5)");

    const legend = svg.append("g")
      .attr("transform", `translate(${width + margin.left + 20}, 20)`);

    legend.append("circle")
      .attr("r", 7)
      .attr("fill", "#3b82f6")
      .attr("opacity", 0.8);

    legend.append("text")
      .attr("x", 20)
      .attr("y", 5)
      .attr("fill", "#ffffff")
      .text("Normal events");

    legend.append("circle")
      .attr("r", 6)
      .attr("cy", 30)
      .attr("fill", "#ef4444")
      .attr("stroke", "#b91c1c")
      .attr("stroke-width", 1.5);

    legend.append("text")
      .attr("x", 20)
      .attr("y", 35)
      .attr("fill", "#ffffff")
      .text("Anomalies");

  }, [data, dimensions]);

  if (!data || !data.suspicious_events || data.suspicious_events.length === 0) {
    return (
      <div className="dashboard-card h-110 pb-20">
        <h2 className="text-gray-300 text-lg font-semibold mb-4">Anomaly Detection</h2>
        <div className="h-80 flex items-center justify-center">
          <p className="text-gray-500">No anomaly data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-card h-110 pb-20">
      <h2 className="text-gray-300 text-lg font-semibold mb-4">Anomaly Detection</h2>
      <div id="anomaly-container" className="h-80">
        <svg ref={svgRef} width={dimensions.width} height={dimensions.height}></svg>
      </div>
    </div>
  );
};

export default AnomalyDetectionPlot;
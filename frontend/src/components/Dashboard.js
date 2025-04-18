import React, { useState, useEffect } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar } from "recharts";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import "../styles.css";

function Dashboard({ detectedThreats = [], totalThreats = 0, modelMetrics }) {
  const [chartData, setChartData] = useState([{ name: "Start", threats: 0 }]);
  const [tooltipVisible, setTooltipVisible] = useState(null);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });

  const formatSeverityExplanation = (explanation) => {
    if (typeof explanation === 'string') {
      try {
        const data = JSON.parse(explanation);
        return Object.entries(data).map(([key, value]) => {
          const formattedKey = key
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
          
          let formattedValue = value;
          if (typeof value === 'number') {
            formattedValue = value.toLocaleString();
          }
          
          return `${formattedKey}: ${formattedValue}`;
        }).join('\n');
      } catch (e) {
        return explanation;
      }
    }
    return explanation;
  };

  const handleMouseEnter = (index, event) => {
    const rect = event.target.getBoundingClientRect();
    setTooltipPosition({
      x: rect.left + rect.width / 2,
      y: rect.top
    });
    setTooltipVisible(index);
  };

  // Update chart data when threats change
  useEffect(() => {
    const newDataPoint = {
      name: new Date().toLocaleTimeString(),
      threats: totalThreats
    };
    setChartData(prev => [...prev, newDataPoint].slice(-10)); // Keep last 10 data points
  }, [totalThreats]);

  return (
    <div className="dashboard-container">
      <h1>Cyber Threat Dashboard</h1>
      
      {/* Threat Overview */}
      <div className="threat-overview">
        <h2>Threat Overview</h2>
        <p>Total Threats Detected: {totalThreats}</p>
        <LineChart width={500} height={200} data={chartData}>
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <CartesianGrid strokeDasharray="3 3" />
          <Line type="monotone" dataKey="threats" stroke="#ffcc00" />
        </LineChart>
      </div>

      {/* Model Performance Metrics */}
      <div className="performance-metrics">
        <h2>Model Performance Metrics</h2>
        <div className="metrics-container">
          <div className="model-metrics">
            <h3>Random Forest</h3>
            {modelMetrics.randomForest ? (
              <BarChart width={300} height={200} data={[
                { name: "Accuracy", value: modelMetrics.randomForest.accuracy },
                { name: "Precision", value: modelMetrics.randomForest.precision },
                { name: "Recall", value: modelMetrics.randomForest.recall }
              ]}>
                <XAxis dataKey="name" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Bar dataKey="value" fill="#0074D9" />
              </BarChart>
            ) : (
              <p>Random Forest metrics not available.</p>
            )}
          </div>

          <div className="model-metrics">
            <h3>SVM</h3>
            {modelMetrics.svm ? (
              <BarChart width={300} height={200} data={[
                { name: "Accuracy", value: modelMetrics.svm.accuracy },
                { name: "Precision", value: modelMetrics.svm.precision },
                { name: "Recall", value: modelMetrics.svm.recall }
              ]}>
                <XAxis dataKey="name" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Bar dataKey="value" fill="#FF4136" />
              </BarChart>
            ) : (
              <p>SVM metrics not available.</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="recent-incidents">
        <h2>Recent Incidents</h2>
        <div className="table-responsive">
          <table className="table table-striped">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Attacker IP</th>
                <th>Victim IP</th>
                <th>Attack Type</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {detectedThreats.slice(0, 5).map((threat, index) => (
                <tr key={index} className={
                  threat.severity === 'High' ? 'table-danger' :
                  threat.severity === 'Medium' ? 'table-warning' :
                  threat.severity === 'Low' ? 'table-info' :
                  'table-success'
                }>
                  <td>{threat.timestamp}</td>
                  <td>
                    <div className="severity-container">
                      <span 
                        className={`severity-badge severity-${threat.severity.toLowerCase()}`}
                        onMouseEnter={(e) => handleMouseEnter(index, e)}
                        onMouseLeave={() => setTooltipVisible(null)}
                      >
                        {threat.severity}
                      </span>
                      {tooltipVisible === index && (
                        <div 
                          className="custom-tooltip"
                          style={{
                            left: `${tooltipPosition.x}px`,
                            top: `${tooltipPosition.y}px`
                          }}
                        >
                          <strong>Severity Explanation:</strong><br />
                          <div className="severity-details">
                            {formatSeverityExplanation(threat.severity_explanation).split('\n').map((line, i) => (
                              <div key={i}>{line}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </td>
                  <td>{threat.attacker_ip}</td>
                  <td>{threat.victim_ip}</td>
                  <td>{threat.attack_type}</td>
                  <td>{threat.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;

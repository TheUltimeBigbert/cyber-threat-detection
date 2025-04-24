import React, { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar } from "recharts";
import "leaflet/dist/leaflet.css";
import "react-toastify/dist/ReactToastify.css";
import "../styles.css";
import { useThreatContext } from "../context/ThreatContext";

function CustomTooltip({ threat, onClose }) {
  const formatSeverityExplanation = (explanation) => {
    if (typeof explanation === 'string') {
      try {
        const data = JSON.parse(explanation);
        
        // If there's an error, return it directly
        if (data.error) {
          return data.error;
        }

        // Start with the main explanation
        let formattedText = [`${data.explanation || ''}`];

        // Format feature importance information
        const featureImportance = data.feature_importance || {};
        
        // Sort features by importance
        const sortedFeatures = Object.entries(featureImportance)
          .sort(([, a], [, b]) => b.importance - a.importance);

        sortedFeatures.forEach(([feature, details]) => {
          const featureName = feature
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
          
          // Add feature name and context
          formattedText.push(
            `\n${featureName}:`,
            `  ${details.context}`,
            `  Impact: ${details.impact} severity (${details.importance.toFixed(1)}% importance)`
          );
        });

        return formattedText.join('\n');
      } catch (e) {
        console.error("Error parsing severity explanation:", e);
        return explanation;
      }
    }
    return explanation;
  };

  const explanation = formatSeverityExplanation(threat.severity_explanation);
  const lines = explanation.split('\n');
  const [header, ...details] = lines;

  return (
    <div className="severity-tooltip">
      <div className="severity-tooltip-header">
        <strong>{header}</strong>
        <span className="close-button" onClick={onClose}>×</span>
      </div>
      <div className="severity-tooltip-content">
        {details.map((line, i) => (
          <div 
            key={i} 
            className={
              line.startsWith('  ') ? 'severity-tooltip-detail' : 
              'severity-tooltip-feature'
            }
          >
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}

function Dashboard() {
  const { displayedThreats, totalThreats } = useThreatContext();
  const [chartData, setChartData] = useState([{ name: "Start", threats: 0 }]);
  const [selectedThreatIndex, setSelectedThreatIndex] = useState(null);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  const [modelMetrics, setModelMetrics] = useState({
    randomForest: { accuracy: 0, precision: 0, recall: 0 },
    svm: { accuracy: 0, precision: 0, recall: 0 }
  });

  // Fetch model metrics
  useEffect(() => {
    const fetchModelMetrics = async () => {
      try {
        const response = await axios.get("http://127.0.0.1:8000/model-metrics");
        setModelMetrics(response.data);
      } catch (error) {
        console.error("Error fetching model metrics:", error);
        toast.error("Error fetching model metrics");
      }
    };
    fetchModelMetrics();

    // Refresh metrics every minute
    const interval = setInterval(fetchModelMetrics, 60000);
    return () => clearInterval(interval);
  }, []);

  const handleThreatClick = (index, event) => {
    const rect = event.target.getBoundingClientRect();
    setTooltipPosition({
      x: rect.left + rect.width / 2,
      y: rect.top
    });
    setSelectedThreatIndex(selectedThreatIndex === index ? null : index);
  };

  const handleCloseTooltip = () => {
    setSelectedThreatIndex(null);
  };

  // Update chart data when threats change
  useEffect(() => {
    const newDataPoint = {
      name: new Date().toLocaleTimeString(),
      threats: totalThreats
    };
    setChartData(prev => {
      const updated = [...prev, newDataPoint].slice(-10); // Keep last 10 data points
      console.log('Updated chart data:', updated);
      return updated;
    });
  }, [totalThreats]);

  // Debug logging for updates
  useEffect(() => {
    console.log('Dashboard component state:', {
      displayedThreatsCount: displayedThreats.length,
      totalThreats,
      displayedThreats,
      chartDataPoints: chartData.length
    });
  }, [displayedThreats, totalThreats, chartData]);

  return (
    <div className="dashboard-container">
      <h1>Cyber Threat Dashboard</h1>

      {/* Threat Overview */}
      <div className="threat-overview">
        <h2>Threat Overview</h2>
        <div className="alert alert-warning">
          <h4>Actual Threats Detected: {totalThreats}</h4>
          <p>Real-time monitoring of cyber threats (excluding benign traffic)</p>
        </div>
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
            <BarChart width={300} height={200} data={[
              { name: "Accuracy", value: modelMetrics?.randomForest?.accuracy || 0 },
              { name: "Precision", value: modelMetrics?.randomForest?.precision || 0 },
              { name: "Recall", value: modelMetrics?.randomForest?.recall || 0 }
            ]}>
              <XAxis dataKey="name" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Bar dataKey="value" fill="#0074D9" />
            </BarChart>
          </div>

          <div className="model-metrics">
            <h3>SVM</h3>
            <BarChart width={300} height={200} data={[
              { name: "Accuracy", value: modelMetrics?.svm?.accuracy || 0 },
              { name: "Precision", value: modelMetrics?.svm?.precision || 0 },
              { name: "Recall", value: modelMetrics?.svm?.recall || 0 }
            ]}>
              <XAxis dataKey="name" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Bar dataKey="value" fill="#FF4136" />
            </BarChart>
          </div>
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="recent-incidents">
        <h2>Recent Incidents</h2>
        <div className="alert alert-info mb-3">
          <p className="mb-0">Showing the {displayedThreats.length} most recent non-benign threats detected</p>
        </div>
        <div className="table-responsive">
          <table className="table table-striped border">
            <thead className="thead-dark bg-dark text-white">
              <tr>
                <th className="px-3 py-2">Timestamp</th>
                <th className="px-3 py-2">Attacker IP</th>
                <th className="px-3 py-2">Victim IP</th>
                <th className="px-3 py-2">Attack Type</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {displayedThreats.length > 0 ? (
                displayedThreats.map((threat, index) => (
                  <tr key={`${threat.timestamp}-${threat.attack_type}-${index}`} className={
                    threat.severity === 'High' ? 'table-danger' :
                    threat.severity === 'Medium' ? 'table-warning' :
                    'table-info'
                  }>
                    <td className="px-3 py-2">{threat.timestamp}</td>
                    <td className="px-3 py-2">{threat.attacker_ip}</td>
                    <td className="px-3 py-2">{threat.victim_ip}</td>
                    <td className="px-3 py-2">{threat.attack_type}</td>
                    <td className="px-3 py-2">
                      <div className="severity-container">
                        <span 
                          className={`severity-badge severity-${threat.severity.toLowerCase()}`}
                          onClick={(e) => handleThreatClick(index, e)}
                        >
                          {threat.severity}
                        </span>
                        {selectedThreatIndex === index && (
                          <div 
                            className="custom-tooltip"
                            style={{
                              left: `${tooltipPosition.x}px`,
                              top: `${tooltipPosition.y}px`
                            }}
                          >
                            <CustomTooltip threat={threat} onClose={handleCloseTooltip} />
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2">{threat.result}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-3">No recent threats detected</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <style jsx>{`
        .table {
          background-color: white;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .thead-dark th {
          background-color: #343a40 !important;
          color: white !important;
          font-weight: 600;
          border-bottom: 2px solid #343a40;
        }
        .severity-badge {
          display: inline-block;
          padding: 0.25em 0.8em;
          font-size: 0.875em;
          font-weight: 600;
          border-radius: 0.25rem;
          cursor: pointer;
        }
        .severity-high {
          background-color: #dc3545;
          color: white;
        }
        .severity-medium {
          background-color: #ffc107;
          color: #000;
        }
        .severity-low {
          background-color: #17a2b8;
          color: white;
        }
        .table-danger {
          background-color: rgba(220, 53, 69, 0.15) !important;
        }
        .table-warning {
          background-color: rgba(255, 193, 7, 0.15) !important;
        }
        .table-info {
          background-color: rgba(23, 162, 184, 0.15) !important;
        }
        .table-success {
          background-color: rgba(40, 167, 69, 0.15) !important;
        }
        .table td, .table th {
          vertical-align: middle;
        }
      `}</style>
    </div>
  );
}

export default Dashboard;

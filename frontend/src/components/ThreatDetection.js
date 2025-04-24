import React, { useState } from "react";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import 'bootstrap/dist/css/bootstrap.min.css';
import { useThreatContext } from "../context/ThreatContext";

const ThreatDetection = () => {
    const { detectedThreats, totalThreats } = useThreatContext();
    const [tooltipVisible, setTooltipVisible] = useState(null);
    const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });

    // Calculate traffic stats
    const actualThreats = detectedThreats.filter(t => t.isThreat);
    const benignTraffic = detectedThreats.filter(t => t.attack_type === "BENIGN");
    const unknownTraffic = detectedThreats.filter(t => !t.isThreat && t.attack_type !== "BENIGN");

    const formatSeverityExplanation = (explanation) => {
        if (typeof explanation === 'string') {
            try {       
                const data = JSON.parse(explanation);
                
                if (data.error) {
                    return data.error;
                }

                let formattedText = [`${data.explanation || ''}`];
                const featureImportance = data.feature_importance || {};
                
                const sortedFeatures = Object.entries(featureImportance)
                    .sort(([, a], [, b]) => b.importance - a.importance);

                sortedFeatures.forEach(([feature, details]) => {
                    const featureName = feature
                        .split('_')
                        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                        .join(' ');
                    
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

    const handleMouseEnter = (index, event) => {
        const rect = event.target.getBoundingClientRect();
        setTooltipPosition({
            x: rect.left + rect.width / 2,
            y: rect.top
        });
        setTooltipVisible(index);
    };

    const handleCloseTooltip = () => {
        setTooltipVisible(null);
    };

    const CustomTooltip = ({ threat }) => {
        const explanation = formatSeverityExplanation(threat.severity_explanation);
        const lines = explanation.split('\n');
        const [header, ...details] = lines;

        return (
            <div className="severity-tooltip">
                <div className="severity-tooltip-header">
                    <strong>{header}</strong>
                    <span className="close-button" onClick={handleCloseTooltip}>×</span>
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
    };

    return (
        <div className="container">
            <h2>Threat Detection History</h2>
            <ToastContainer />

            <div className="alert alert-info mb-3">
                <h4>Traffic Analysis</h4>
                <div className="row">
                    <div className="col-md-3">
                        <strong>Confirmed Threats:</strong> {totalThreats}
                        <small className="d-block text-muted">Known attack patterns</small>
                    </div>
                    <div className="col-md-3">
                        <strong>Benign Traffic:</strong> {benignTraffic.length}
                        <small className="d-block text-muted">Safe network activity</small>
                    </div>
                    <div className="col-md-3">
                        <strong>Unknown Traffic:</strong> {unknownTraffic.length}
                        <small className="d-block text-muted">Unclassified patterns</small>
                    </div>
                    <div className="col-md-3">
                        <strong>Total Traffic:</strong> {detectedThreats.length}
                        <small className="d-block text-muted">All network activity</small>
                    </div>
                </div>
                <p className="mt-2 mb-0">This view shows the complete history of all network traffic, including both threats and normal activity</p>
            </div>

            <div className="table-responsive">
                <table className="table table-striped border">
                    <thead className="thead-dark bg-dark text-white">
                        <tr>
                            <th className="px-3 py-2">Timestamp</th>  
                            <th className="px-3 py-2">Attacker IP</th>
                            <th className="px-3 py-2">Victim IP</th>
                            <th className="px-3 py-2">Type</th>
                            <th className="px-3 py-2">Severity</th>
                            <th className="px-3 py-2">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {detectedThreats.length > 0 ? (
                            detectedThreats.map((threat, index) => (
                                <tr key={`${threat.timestamp}-${threat.attack_type}-${index}`} className={
                                    threat.isThreat ? (
                                        threat.severity === 'High' ? 'table-danger' :
                                        threat.severity === 'Medium' ? 'table-warning' :
                                        'table-info'
                                    ) : (
                                        threat.attack_type === 'BENIGN' ? 'table-success' : ''
                                    )
                                }>
                                    <td className="px-3 py-2">{threat.timestamp}</td>
                                    <td className="px-3 py-2">{threat.attacker_ip}</td>
                                    <td className="px-3 py-2">{threat.victim_ip}</td>
                                    <td className="px-3 py-2">
                                        <span className={`badge ${threat.isThreat ? 'bg-danger' : (threat.attack_type === 'BENIGN' ? 'bg-success' : 'bg-secondary')}`}>
                                            {threat.attack_type}
                                        </span>
                                    </td>
                                    <td className="px-3 py-2">
                                        {threat.isThreat && (
                                            <div className="severity-container">
                                                <span 
                                                    className={`severity-badge severity-${threat.severity.toLowerCase()}`}
                                                    onClick={(e) => handleMouseEnter(index, e)}
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
                                                        <CustomTooltip threat={threat} />
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </td>
                                    <td className="px-3 py-2">{threat.result}</td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="6" className="text-center py-3">No traffic detected yet</td>
                            </tr>
                        )}
                    </tbody>
                </table>
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
                .badge {
                    padding: 0.4em 0.8em;
                    font-weight: 500;
                }
            `}</style>
        </div>
    );
};  

export default ThreatDetection;
import { useState, useEffect } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Papa from "papaparse";
import Dashboard from './Dashboard';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

const ThreatDetection = () => {
    const [result, setResult] = useState(null);
    const [detectedThreats, setDetectedThreats] = useState([]); 
    const [dataset, setDataset] = useState([]); 
    const [totalThreats, setTotalThreats] = useState(0); 
    const [modelMetrics, setModelMetrics] = useState({});
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

    useEffect(() => {
        const loadDataset = async () => {
            try {
                const response = await fetch("http://localhost:8000/static/cleaned_data_with_details.csv");
                const csvText = await response.text();
                Papa.parse(csvText, {
                    header: true,
                    dynamicTyping: true,
                    complete: (results) => {
                        // Filter out rows with missing or invalid data
                        const validData = results.data.filter(row => 
                            row && Object.keys(row).length > 0 && !Object.values(row).every(val => val === null)
                        );
                        setDataset(validData);
                        console.log("Dataset loaded:", validData);
                    },
                });
            } catch (error) {
                console.error("Error loading dataset:", error);
                toast.error("Error loading dataset");
            }
        };
        loadDataset();
    }, []);

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
    }, []);

    const handleDetectThreat = async (inputArray) => {
        try {
            console.log("Input array:", inputArray);

            const response = await axios.post("http://127.0.0.1:8000/predict", {
                features: inputArray
            });

            const { prediction, attacker_ip, victim_ip, attack_type, severity, severity_explanation } = response.data;
            const resultText = attack_type === "BENIGN" ? "Safe" : attack_type;
            setResult(resultText);

            // Only show toast for actual threats
            if (resultText !== "Safe") {
                toast.warning(`Threat Detected: ${resultText}`);
            }

            // Add new threat to the list with all available information
            setDetectedThreats(prevThreats => [
                {
                    timestamp: new Date().toLocaleString(),
                    attacker_ip,
                    victim_ip,
                    attack_type,
                    severity,
                    severity_explanation,
                    result: resultText
                },
                ...prevThreats
            ].slice(0, 100)); // Keep only the last 100 threats

            if (attack_type !== "BENIGN") {
                setTotalThreats(prevCount => prevCount + 1);
            }
        } catch (error) {
            console.error("Error detecting threat:", error);
            toast.error("Error detecting threat");
        }
    };

    useEffect(() => {
        const interval = setInterval(() => {
            if (dataset.length > 0) {
                const randomIndex = Math.floor(Math.random() * dataset.length);
                const randomRow = dataset[randomIndex];
                
                // Send both attack label and severity
                const attackLabel = randomRow.original_attack_label;
                console.log("Selected random row:", randomRow);
                console.log("Attack label:", attackLabel);
                console.log("Severity:", randomRow.attack_severity);  // Changed from Severity to attack_severity
                
                handleDetectThreat([attackLabel]);
            } else {
                console.log("Dataset is empty");
            }
        }, 3000);

        return () => clearInterval(interval);
    }, [dataset]);

    const handleMouseEnter = (index, event) => {
        const rect = event.target.getBoundingClientRect();
        setTooltipPosition({
            x: rect.left + rect.width / 2,
            y: rect.top
        });
        setTooltipVisible(index);
    };

    return (
        <div className="container">
            <Dashboard 
                detectedThreats={detectedThreats}
                totalThreats={totalThreats}
                modelMetrics={modelMetrics}
            />
            
            <h2>Cyber Threat Detection</h2>
            {result && (
                <h3 className={result === "Safe" ? "text-success" : "text-danger"}>
                    Detection Result: {result}
                </h3>
            )}
            <ToastContainer />

            <h3>Total Detected Threats: {totalThreats}</h3>

            <div className="table-responsive">
                <table className="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Attacker IP</th>
                            <th>Victim IP</th>
                            <th>Attack Type</th>
                            <th>Severity</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {detectedThreats.map((threat, index) => (
                            <tr key={index} className={
                                threat.severity === 'High' ? 'table-danger' :
                                threat.severity === 'Medium' ? 'table-warning' :
                                threat.severity === 'Low' ? 'table-info' :
                                'table-success'
                            }>
                                <td>{threat.timestamp}</td>
                                <td>{threat.attacker_ip}</td>
                                <td>{threat.victim_ip}</td>
                                <td>{threat.attack_type}</td>
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
                                <td>{threat.result}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ThreatDetection;
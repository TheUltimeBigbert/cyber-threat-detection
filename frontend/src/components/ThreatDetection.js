import { useState, useEffect } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Papa from "papaparse";

const ThreatDetection = () => {
    const [result, setResult] = useState(null);
    const [detectedThreats, setDetectedThreats] = useState([]); 
    const [dataset, setDataset] = useState([]); 
    const [totalThreats, setTotalThreats] = useState(0); 

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

    const handleDetectThreat = async (inputArray) => {
        try {
            console.log("Input array:", inputArray);

            const response = await axios.post("http://127.0.0.1:8000/predict", {
                features: inputArray
            });

            const { prediction, source_ip, destination_ip, attack_type, severity } = response.data;
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
                    source_ip,
                    destination_ip,
                    attack_type,
                    severity,
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
        }, 5000);

        return () => clearInterval(interval);
    }, [dataset]);

    return (
        <div className="container">
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
                            <th>Source IP</th>
                            <th>Destination IP</th>
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
                                <td>{threat.source_ip}</td>
                                <td>{threat.destination_ip}</td>
                                <td>{threat.attack_type}</td>
                                <td>{threat.severity}</td>
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

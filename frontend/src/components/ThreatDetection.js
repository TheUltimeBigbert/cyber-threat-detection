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
                const response = await fetch("http://localhost:8000/static/cleaned_data_top_10.csv");
                const csvText = await response.text();
                Papa.parse(csvText, {
                    header: true,
                    dynamicTyping: true,
                    complete: (results) => {
                        const filteredData = results.data.map(row => {
                            return Object.fromEntries(Object.entries(row).slice(0, 10));
                        });
                        setDataset(filteredData);
                        console.log("Dataset loaded:", filteredData); 
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

            const detectionResult = response.data.prediction;
            const resultText = detectionResult === 1 ? "Threat Detected" : "Safe";
            setResult(resultText);
            toast.success(`Result: ${resultText}`);

            setDetectedThreats(prevThreats => [
                ...prevThreats,
                { features: inputArray, result: resultText, timestamp: new Date().toLocaleString() }
            ]);


            if (detectionResult === 1) {
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
                // Randomly select a row from the dataset
                const randomIndex = Math.floor(Math.random() * dataset.length);
                const randomRow = dataset[randomIndex];
                const inputArray = Object.values(randomRow).slice(0, 10).map(Number); 
                console.log("Selected random row:", randomRow); 
                console.log("Converted input array:", inputArray);
                handleDetectThreat(inputArray);
            } else {
                console.log("Dataset is empty"); 
            }
        }, 5000);

        return () => clearInterval(interval); // Clear interval on component unmount
    }, [dataset]); 

    return (
        <div className="container">
            <h2>Cyber Threat Detection</h2>
            {result && <h3>Detection Result: {result}</h3>}
            <ToastContainer />

            {/* Display count of detected threats */}
            <h3>Total Detected Threats: {totalThreats}</h3>

            {/* Display detected threats in a table */}
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Features</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    {detectedThreats.map((threat, index) => (
                        <tr key={index}>
                            <td>{threat.timestamp}</td>
                            <td>{threat.features.join(", ")}</td>
                            <td>{threat.result}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default ThreatDetection;
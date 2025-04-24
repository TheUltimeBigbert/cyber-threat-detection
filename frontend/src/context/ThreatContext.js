import React, { createContext, useState, useCallback, useContext, useEffect } from 'react';
import axios from 'axios';
import Papa from 'papaparse';
import { toast } from 'react-toastify';

const ThreatContext = createContext();

const isActualThreat = (attackType) => {
    // List of known attack types that should be counted as threats
    const knownAttackTypes = [
        'DDoS',
        'DoS',
        'DoS Hulk',
        'DoS GoldenEye',
        'DoS Slowloris',
        'DoS Slowhttptest',
        'FTP-Patator',
        'SSH-Patator',
        'Web Attack',
        'Web Attack – Brute Force',
        'Web Attack – XSS',
        'Web Attack – SQL Injection',
        'Infiltration',
        'Bot',
        'PortScan',
        'Heartbleed'
    ];
    
    // Return true only if it's a known attack type
    return knownAttackTypes.some(type => 
        attackType.toLowerCase().includes(type.toLowerCase())
    );
};

export const ThreatProvider = ({ children }) => {
    const [detectedThreats, setDetectedThreats] = useState([]);
    const [displayedThreats, setDisplayedThreats] = useState([]);
    const [totalThreats, setTotalThreats] = useState(0);
    const [dataset, setDataset] = useState([]);

    // Load the dataset when the provider mounts
    useEffect(() => {
        const loadDataset = async () => {
            try {
                const response = await fetch("http://localhost:8000/static/cleaned_data_with_details.csv");
                const csvText = await response.text();
                Papa.parse(csvText, {
                    header: true,
                    dynamicTyping: true,
                    complete: (results) => {
                        const validData = results.data.filter(row => 
                            row && Object.keys(row).length > 0 && !Object.values(row).every(val => val === null)
                        );
                        setDataset(validData);
                        console.log("Dataset loaded in context:", validData.length, "rows");
                    },
                });
            } catch (error) {
                console.error("Error loading dataset:", error);
                toast.error("Error loading dataset");
            }
        };
        loadDataset();
    }, []);

    const handleDetectThreat = useCallback(async (inputArray) => {
        try {
            const response = await axios.post("http://127.0.0.1:8000/predict", {
                features: inputArray
            });

            const { prediction, attacker_ip, victim_ip, attack_type, severity, severity_explanation } = response.data;
            
            // Determine if this is an actual threat
            const isThreat = isActualThreat(attack_type);
            const resultText = isThreat ? attack_type : (attack_type === "BENIGN" ? "Safe" : "Unknown");

            const newThreat = {
                timestamp: new Date().toLocaleString(),
                attacker_ip,
                victim_ip,
                attack_type,
                severity: isThreat ? severity : 'Low',
                severity_explanation,
                result: resultText,
                isThreat
            };

            console.log('Processing traffic:', {
                type: attack_type,
                isThreat,
                result: resultText
            });

            // Update detected threats (full history)
            setDetectedThreats(prevThreats => {
                const updated = [newThreat, ...prevThreats].slice(0, 100); // Keep last 100 threats
                console.log('Updated detectedThreats:', updated.length);
                return updated;
            });

            // Only increment total threats and display for actual threats
            if (isThreat) {
                setTotalThreats(prev => {
                    const newTotal = prev + 1;
                    console.log('Updated total threats:', newTotal);
                    return newTotal;
                });

                // Add to dashboard display
                setDisplayedThreats(prevDisplayed => {
                    // Ensure we don't add duplicate threats
                    const isDuplicate = prevDisplayed.some(
                        existing => 
                            existing.timestamp === newThreat.timestamp && 
                            existing.attack_type === newThreat.attack_type &&
                            existing.attacker_ip === newThreat.attacker_ip
                    );

                    if (isDuplicate) {
                        console.log('Duplicate threat detected, skipping dashboard update');
                        return prevDisplayed;
                    }

                    const updated = [newThreat, ...prevDisplayed].slice(0, 5); // Keep last 5 threats
                    console.log('Updated displayedThreats:', updated.length);
                    return updated;
                });

                // Show toast notification only for actual threats
                toast.warning(`Threat Detected: ${attack_type}`);
            }
        } catch (error) {
            console.error("Error detecting threat:", error);
            toast.error("Error detecting threat");
        }
    }, []);

    // Start the threat detection polling when dataset is loaded
    useEffect(() => {
        if (dataset.length > 0) {
            console.log("Starting threat detection polling...");
            const interval = setInterval(() => {
                const randomIndex = Math.floor(Math.random() * dataset.length);
                const randomRow = dataset[randomIndex];
                
                const attackLabel = randomRow.original_attack_label;
                console.log("Selected random row for detection:", {
                    attackLabel,
                    severity: randomRow.attack_severity
                });
                
                handleDetectThreat([attackLabel]);
            }, 8000);

            return () => {
                console.log("Cleaning up threat detection interval");
                clearInterval(interval);
            };
        }
    }, [dataset, handleDetectThreat]);

    const clearThreats = useCallback(() => {
        console.log('Clearing all threats');
        setDetectedThreats([]);
        setDisplayedThreats([]);
        setTotalThreats(0);
    }, []);

    // Debug logging for state changes
    useEffect(() => {
        const stats = {
            total: detectedThreats.length,
            actualThreats: detectedThreats.filter(t => t.isThreat).length,
            benign: detectedThreats.filter(t => t.attack_type === "BENIGN").length,
            unknown: detectedThreats.filter(t => !t.isThreat && t.attack_type !== "BENIGN").length
        };

        console.log('ThreatContext state updated:', {
            ...stats,
            displayedThreatsCount: displayedThreats.length,
            totalThreatsCount: totalThreats,
            datasetLoaded: dataset.length > 0
        });
    }, [detectedThreats, displayedThreats, totalThreats, dataset]);

    const contextValue = {
        detectedThreats,
        displayedThreats,
        totalThreats,
        addThreat: handleDetectThreat,
        clearThreats
    };

    return (
        <ThreatContext.Provider value={contextValue}>
            {children}
        </ThreatContext.Provider>
    );
};

export const useThreatContext = () => {
    const context = useContext(ThreatContext);
    if (!context) {
        throw new Error('useThreatContext must be used within a ThreatProvider');
    }
    return context;
};


import { createContext, useState, useContext } from 'react';

const ThreatContext = createContext();

export function ThreatProvider({ children }) {
    const [detectedThreats, setDetectedThreats] = useState([]);
    const [totalThreats, setTotalThreats] = useState(0);

    const addThreat = (threat) => {
        setDetectedThreats(prev => [threat, ...prev].slice(0, 100));
        if (threat.attack_type !== "BENIGN") {
            setTotalThreats(prev => prev + 1);
        }
    };

    return (
        <ThreatContext.Provider value={{ detectedThreats, totalThreats, addThreat }}>
            {children}
        </ThreatContext.Provider>
    );
}

export function useThreatContext() {
    return useContext(ThreatContext);
}
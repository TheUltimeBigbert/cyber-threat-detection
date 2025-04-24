import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Navigation from './components/Navigation';
import ThreatDetection from './components/ThreatDetection';
import Dashboard from './components/Dashboard';
import LandingPage from './pages/LandingPage';
import { ThreatProvider } from './context/ThreatContext';

function App() {
    return (
        <ThreatProvider>
            <div className="app-container">
                <Navigation />
                <div className="content-container">
                    <Routes>
                        <Route path="/detection" element={<ThreatDetection />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/landing" element={<LandingPage />} />
                        <Route path="/" element={<LandingPage />} />
                    </Routes>
                </div>
            </div>
        </ThreatProvider>
    );
}

export default App;


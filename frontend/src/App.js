import React, { useState } from "react";
import { Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import LoginModal from "./components/LoginModal";
import Dashboard from "./components/Dashboard";
import ForgotPassword from "./pages/ForgotPassword";
import SignUp from "./components/SignUp";
import ThreatDetection from "./components/ThreatDetection";
import "./styles.css";

function App() {
  const [isLoginOpen, setIsLoginOpen] = useState(false);

  return (
    <>
      <Routes>
        <Route path="/" element={<LandingPage openLogin={() => setIsLoginOpen(true)} />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/threat-detection" element={<ThreatDetection />} /> {/* Add route for ThreatDetection */}
      </Routes>

      <LoginModal isOpen={isLoginOpen} onClose={() => setIsLoginOpen(false)} />
    </>
  );
}

export default App;


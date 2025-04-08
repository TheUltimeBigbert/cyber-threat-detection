import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import LoginModal from "../components/LoginModal";
import "../styles.css"; 

function LandingPage() {
    const navigate = useNavigate();
    const [modalIsOpen, setModalIsOpen] = useState(false);
  
    return (
      <div className="landing-container">
        <div className="overlay">
          <h1>Enhancing Cybersecurity with Machine Learning</h1>
          <p>Detect, Analyze, and Prevent Cyber Threats in Real-Time.</p>

          <button className="monitoring-btn" onClick={() => navigate("/threat-detection")}>
            START MONITORING
          </button>

          {/* LOGIN Button (Now Below "START MONITORING") */}
          {/* <button className="login-btn" onClick={() => setModalIsOpen(true)}>
            LOGIN
          </button> */}
        </div>

        {/* Login Modal */}
        <LoginModal isOpen={modalIsOpen} onClose={() => setModalIsOpen(false)} />
      </div>
    );
}

export default LandingPage;

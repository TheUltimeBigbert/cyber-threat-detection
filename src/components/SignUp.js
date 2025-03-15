import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles.css";

function SignUp() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSignUp = (e) => {
    e.preventDefault();
    if (formData.password !== formData.confirmPassword) {
      alert("Passwords do not match!");
      return;
    }
    // TODO: Implement backend request for signup
    alert("Account created successfully!");
    navigate("/login");
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Sign Up</h2>
        <form onSubmit={handleSignUp}>
          <label>Name:</label>
          <input type="text" name="name" placeholder="Enter your name" value={formData.name} onChange={handleChange} required />

          <label>Email:</label>
          <input type="email" name="email" placeholder="Enter your email" value={formData.email} onChange={handleChange} required />

          <label>Password:</label>
          <input type="password" name="password" placeholder="Enter your password" value={formData.password} onChange={handleChange} required />

          <label>Confirm Password:</label>
          <input type="password" name="confirmPassword" placeholder="Confirm your password" value={formData.confirmPassword} onChange={handleChange} required />

          <button type="submit">Sign Up</button>
        </form>
        <p onClick={() => navigate("/login")} style={{ cursor: "pointer", color: "blue" }}>
          Already have an account? Log in
        </p>
      </div>
    </div>
  );
}

export default SignUp;

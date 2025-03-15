import React, { useState } from "react";
import "../styles.css";

function LoginModal({ isOpen, onClose }) {
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [showSignUp, setShowSignUp] = useState(false);

  return (
    isOpen && (
      <div className="modal-overlay">
        <div className="modal-content">
          {/* Close Button (X) */}
          <button className="close-btn" onClick={onClose}>
            &times;
          </button>

          {!showForgotPassword && !showSignUp ? (
            <>
              <h2>Login</h2>
              <label>Email:</label>
              <input type="email" placeholder="Enter email" />
              <label>Password:</label>
              <input type="password" placeholder="Enter password" />
              <button>SIGN IN</button>
              <p
                className="switch-auth"
                onClick={() => setShowForgotPassword(true)}
              >
                Forgot Password?
              </p>
              <p>
                Don't have an account?{" "}
                <span
                  className="switch-auth"
                  onClick={() => setShowSignUp(true)}
                >
                  Sign up
                </span>
              </p>
            </>
          ) : showForgotPassword ? (
            <>
              <h2>Reset Your Password</h2>
              <p>Enter your email to receive a password reset link.</p>
              <input type="email" placeholder="Enter your email" required />
              <button>Send Reset Link</button>
              <p className="switch-auth" onClick={() => setShowForgotPassword(false)}>
                Back to Login
              </p>
            </>
          ) : (
            <>
              <h2>Sign Up</h2>
              <label>Full Name:</label>
              <input type="text" placeholder="Enter your name" />
              <label>Email:</label>
              <input type="email" placeholder="Enter email" />
              <label>Password:</label>
              <input type="password" placeholder="Enter password" />
              <button>REGISTER</button>
              <p className="switch-auth" onClick={() => setShowSignUp(false)}>
                Already have an account? Log in
              </p>
            </>
          )}
        </div>
      </div>
    )
  );
}

export default LoginModal;

import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerUser } from "../api";

export default function Register() {
  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      // Call the registerUser function passing in email and password from state
      const response = await registerUser({ email, password });
      console.log("responi",response)
      const { token } = response;
      console.log("Registration successful! Token:", token);
      localStorage.setItem('userToken', token); // Store the token in local storage
      navigate("/");
    } catch (error) {
      console.error(error);
      setErrorMessage(error.message);
    }
  };
  

  return (
    <div className="login-form">
      <div className="login-input">
        <h1 className="login-title">Register your account</h1>
        <form onSubmit={handleSubmit}>
          {errorMessage && <h3>{errorMessage}</h3>}
          <input
            id="email"
            className="login-field"
            type="email"
            placeholder="Email address"
            name="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <input
            id="password"
            className="login-field"
            type="password"
            placeholder="Password"
            name="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />

          <button className="login-btn" type="submit">
            Register
          </button>
        </form>
        <p className="login-text">
          Already have an account? <a href="/login">Sign in</a>
        </p>
      </div>
    </div>
  );
}

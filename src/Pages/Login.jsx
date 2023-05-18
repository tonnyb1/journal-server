import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser } from "../api";

export default function Login() {
  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      // Call the loginUser function passing in email and password from state
      const data = await loginUser({ email, password });
      console.log("returnDAta",data);
      localStorage.setItem("userToken", data.token)
      // Redirect user to home page after successful login
      navigate("/");
    } catch (error) {
      console.error("hapana",error);
      setErrorMessage(error.message);
    }
  };

  return (
    <div className="login-form">
      <div className="login-input">
        <h1 className="login-title">Sign in to your account</h1>
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
            Sign in
          </button>
        </form>
        <p className="login-text">
          Don't have an account? <a href="/register">Create one now</a>
        </p>
      </div>
    </div>
  );
}

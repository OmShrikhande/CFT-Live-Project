import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function LoginA() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (username && password) {
      navigate('/dashboardA');
    } else {
      alert('Please enter username and password');
    }
  };

  const handleSSO = () => {
    // Demo-only: simulate SSO by showing a message and navigating to the dashboard
    
    navigate('/dashboardA');
  };

  return (
    <div className="login-container">
      <h2>Dashboard A - Login</h2>
      <form onSubmit={handleLogin}>
        <div className="form-group">
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
          />
        </div>
        <div className="form-group">
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
          />
        </div>
        <button type="submit">Login</button>
        <button type="button" className="sso-button" onClick={handleSSO}>🔐 Login with SSO</button>
      </form>
      <p className="demo-hint">Demo: Enter any username and password to continue</p>
    </div>
  );
}

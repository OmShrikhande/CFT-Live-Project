import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

export default function LoginB() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const { login, loading, error, isAuthenticated } = useAuth('B');

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboardB');
    }
  }, [isAuthenticated, navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      return;
    }

    const result = await login(username, password);
    if (result.success) {
      navigate('/dashboardB');
    }
  };

  const handleSSO = () => {
    navigate('/dashboardB');
  };

  return (
    <div className="login-container">
      <h2>Dashboard B - Login (SSO)</h2>
      {error && <div className="error-message">{error}</div>}
      <form onSubmit={handleLogin}>
        <div className="form-group">
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            disabled={loading}
            required
          />
        </div>
        <div className="form-group">
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            disabled={loading}
            required
          />
        </div>
        <button type="submit" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
        <button type="button" className="sso-button" onClick={handleSSO} disabled={loading}>
          🔐 Login with SSO
        </button>
      </form>
      <p className="demo-hint">Secure JWT-based SSO Authentication System</p>
    </div>
  );
}

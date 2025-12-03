import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

export default function DashboardA() {
  const navigate = useNavigate();
  const { user, logout } = useAuth('A');

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <div className="dashboard-container">
      <h1>Welcome to Dashboard A</h1>
      {user && (
        <div className="user-info">
          <p>Logged in as: <strong>{user.username}</strong></p>
          <p className="user-id">User ID: {user.id}</p>
        </div>
      )}
      <p>You are now logged into Dashboard A with secure JWT-based SSO authentication</p>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
}

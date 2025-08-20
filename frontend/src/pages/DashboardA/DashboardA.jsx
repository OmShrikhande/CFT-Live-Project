import { useNavigate } from 'react-router-dom';

export default function DashboardA() {
  const navigate = useNavigate();

  const handleLogout = () => {
    navigate('/');
  };

  return (
    <div className="dashboard-container">
      <h1>Welcome to Dashboard A</h1>
      <p>You are now logged into Dashboard A</p>
      <button onClick={handleLogout}>Back to Home</button>
    </div>
  );
}

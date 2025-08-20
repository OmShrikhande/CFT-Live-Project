import { useNavigate } from 'react-router-dom';

export default function DashboardB() {
  const navigate = useNavigate();

  const handleLogout = () => {
    navigate('/');
  };

  return (
    <div className="dashboard-container">
      <h1>Welcome to Dashboard B</h1>
      <p>You are now logged into Dashboard B</p>
      <button onClick={handleLogout}>Back to Home</button>
    </div>
  );
}

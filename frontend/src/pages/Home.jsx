import { useNavigate } from 'react-router-dom';

export default function Home() {
  const navigate = useNavigate();

  return (
    <div className="home-container">
      <h1>Welcome Home</h1>
      <p>Select a dashboard to continue:</p>
      <div className="button-container">
        <button onClick={() => navigate('/dashboardA/login')}>Dashboard A</button>
        <button onClick={() => navigate('/dashboardB/login')}>Dashboard B</button>
      </div>
    </div>
  );
}

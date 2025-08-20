import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import Home from './pages/Home';
import LoginA from './pages/DashboardA/LoginA';
import DashboardA from './pages/DashboardA/DashboardA';
import LoginB from './pages/DashboardB/LoginB';
import DashboardB from './pages/DashboardB/DashboardB';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/dashboardA/login" element={<LoginA />} />
        <Route path="/dashboardA" element={<DashboardA />} />
        <Route path="/dashboardB/login" element={<LoginB />} />
        <Route path="/dashboardB" element={<DashboardB />} />
      </Routes>
    </Router>
  );
}

export default App;

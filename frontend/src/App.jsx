import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import { SSOProvider } from './context/SSOContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import Home from './pages/Home';
import LoginA from './pages/DashboardA/LoginA';
import DashboardA from './pages/DashboardA/DashboardA';
import LoginB from './pages/DashboardB/LoginB';
import DashboardB from './pages/DashboardB/DashboardB';

function App() {
  return (
    <SSOProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/dashboardA/login" element={<LoginA />} />
          <Route
            path="/dashboardA"
            element={
              <ProtectedRoute dashboard="A">
                <DashboardA />
              </ProtectedRoute>
            }
          />
          <Route path="/dashboardB/login" element={<LoginB />} />
          <Route
            path="/dashboardB"
            element={
              <ProtectedRoute dashboard="B">
                <DashboardB />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Router>
    </SSOProvider>
  );
}

export default App;

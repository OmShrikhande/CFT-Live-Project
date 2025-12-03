import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export const ProtectedRoute = ({ children, dashboard }) => {
  const auth = useAuth(dashboard);

  if (!auth.isAuthenticated) {
    return <Navigate to={`/dashboard${dashboard}/login`} replace />;
  }

  return children;
};

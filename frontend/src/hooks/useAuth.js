import { useSSO } from '../context/SSOContext';
import { getToken } from '../utils/tokenStorage';

export const useAuth = (dashboard) => {
  const sso = useSSO();
  const dashboardState = dashboard === 'A' ? sso.dashboardA : sso.dashboardB;

  const login = async (username, password) => {
    return sso.login(dashboard, username, password);
  };

  const logout = () => {
    sso.logout(dashboard);
  };

  const isAuthenticated = () => {
    const token = getToken(dashboard === 'A' ? 'dashboardA' : 'dashboardB');
    return !!token && dashboardState.isAuthenticated;
  };

  const getToken_ = () => {
    return getToken(dashboard === 'A' ? 'dashboardA' : 'dashboardB');
  };

  return {
    isAuthenticated: isAuthenticated(),
    user: dashboardState.user,
    token: dashboardState.token,
    loading: dashboardState.loading,
    error: dashboardState.error,
    login,
    logout,
    getToken: getToken_,
  };
};

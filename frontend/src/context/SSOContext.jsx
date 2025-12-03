import React, { createContext, useState, useCallback, useEffect } from 'react';
import { setToken, getToken, removeToken, setUser, getUser, removeUser, clearAll } from '../utils/tokenStorage';

const SSOContext = createContext();

export const SSOProvider = ({ children }) => {
  const [dashboardA, setDashboardA] = useState({
    isAuthenticated: false,
    user: null,
    token: null,
    loading: false,
    error: null,
  });

  const [dashboardB, setDashboardB] = useState({
    isAuthenticated: false,
    user: null,
    token: null,
    loading: false,
    error: null,
  });

  useEffect(() => {
    const initializeAuth = () => {
      const tokenA = getToken('dashboardA');
      const userA = getUser('dashboardA');
      if (tokenA && userA) {
        setDashboardA({
          isAuthenticated: true,
          user: userA,
          token: tokenA,
          loading: false,
          error: null,
        });
      }

      const tokenB = getToken('dashboardB');
      const userB = getUser('dashboardB');
      if (tokenB && userB) {
        setDashboardB({
          isAuthenticated: true,
          user: userB,
          token: tokenB,
          loading: false,
          error: null,
        });
      }
    };

    initializeAuth();
  }, []);

  const login = useCallback(async (dashboard, username, password) => {
    const dashboardName = dashboard === 'A' ? 'dashboardA' : 'dashboardB';
    const setter = dashboard === 'A' ? setDashboardA : setDashboardB;

    setter((prev) => ({ ...prev, loading: true, error: null }));

    try {
      const response = await fetch(`http://localhost:5000/api/auth/${dashboardName}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      setToken(dashboardName, data.token);
      setUser(dashboardName, data.user);

      setter({
        isAuthenticated: true,
        user: data.user,
        token: data.token,
        loading: false,
        error: null,
      });

      return { success: true, token: data.token, user: data.user };
    } catch (error) {
      const errorMsg = error.message || 'Login failed. Check if backend is running.';
      setter((prev) => ({ ...prev, loading: false, error: errorMsg }));
      return { success: false, error: errorMsg };
    }
  }, []);

  const logout = useCallback((dashboard) => {
    const dashboardName = dashboard === 'A' ? 'dashboardA' : 'dashboardB';
    const setter = dashboard === 'A' ? setDashboardA : setDashboardB;

    clearAll(dashboardName);
    setter({
      isAuthenticated: false,
      user: null,
      token: null,
      loading: false,
      error: null,
    });
  }, []);

  const verifyToken = useCallback(async (dashboard) => {
    const dashboardName = dashboard === 'A' ? 'dashboardA' : 'dashboardB';
    const token = getToken(dashboardName);

    if (!token) {
      return false;
    }

    try {
      const response = await fetch('http://localhost:5000/api/auth/verify-token', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        clearAll(dashboardName);
        const setter = dashboard === 'A' ? setDashboardA : setDashboardB;
        setter({
          isAuthenticated: false,
          user: null,
          token: null,
          loading: false,
          error: 'Token expired',
        });
        return false;
      }

      return true;
    } catch (error) {
      return false;
    }
  }, []);

  const value = {
    dashboardA,
    dashboardB,
    login,
    logout,
    verifyToken,
  };

  return <SSOContext.Provider value={value}>{children}</SSOContext.Provider>;
};

export const useSSO = () => {
  const context = React.useContext(SSOContext);
  if (!context) {
    throw new Error('useSSO must be used within SSOProvider');
  }
  return context;
};

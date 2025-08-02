import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { authService } from '../services/auth';
import toast from 'react-hot-toast';

// Initial state
const initialState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
};

// Action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  SET_LOADING: 'SET_LOADING',
  SET_USER: 'SET_USER',
  CLEAR_ERROR: 'CLEAR_ERROR',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
};

// Reducer
const authReducer = (state, action) => {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
      return {
        ...state,
        isLoading: true,
        error: null,
      };
    
    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };
    
    case AUTH_ACTIONS.LOGIN_FAILURE:
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload.error,
      };
    
    case AUTH_ACTIONS.LOGOUT:
    case AUTH_ACTIONS.SESSION_EXPIRED:
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.type === AUTH_ACTIONS.SESSION_EXPIRED ? 'Session expired' : null,
      };
    
    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload,
      };
    
    case AUTH_ACTIONS.SET_USER:
      return {
        ...state,
        user: action.payload,
        isAuthenticated: !!action.payload,
        isLoading: false,
      };
    
    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null,
      };
    
    default:
      return state;
  }
};

// Create context
const AuthContext = createContext(null);

// Auth provider component
export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Initialize authentication state
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: true });
        
        // Check if user is authenticated
        if (authService.isAuthenticated()) {
          // Validate session
          const isValid = await authService.validateSession();
          
          if (isValid) {
            const user = authService.getCurrentUser();
            dispatch({ 
              type: AUTH_ACTIONS.SET_USER, 
              payload: user 
            });
          } else {
            dispatch({ type: AUTH_ACTIONS.SESSION_EXPIRED });
          }
        } else {
          dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        dispatch({ type: AUTH_ACTIONS.SESSION_EXPIRED });
      }
    };

    initializeAuth();
  }, []);

  // Login function
  const login = async (credentials) => {
    try {
      dispatch({ type: AUTH_ACTIONS.LOGIN_START });
      
      const result = await authService.login(credentials);
      
      dispatch({ 
        type: AUTH_ACTIONS.LOGIN_SUCCESS, 
        payload: { user: result.user } 
      });
      
      toast.success(`Welcome back, ${result.user.firstName}!`);
      
      return result;
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message || 'Login failed';
      
      dispatch({ 
        type: AUTH_ACTIONS.LOGIN_FAILURE, 
        payload: { error: errorMessage } 
      });
      
      toast.error(errorMessage);
      throw error;
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await authService.logout();
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
      toast.success('Logged out successfully');
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear local state even if server logout fails
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
    }
  };

  // Update profile function
  const updateProfile = async (profileData) => {
    try {
      const updatedUser = await authService.updateProfile(profileData);
      
      dispatch({ 
        type: AUTH_ACTIONS.SET_USER, 
        payload: updatedUser 
      });
      
      toast.success('Profile updated successfully');
      return updatedUser;
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Profile update failed';
      toast.error(errorMessage);
      throw error;
    }
  };

  // Change password function
  const changePassword = async (passwordData) => {
    try {
      await authService.changePassword(passwordData);
      
      // Clear auth state to force re-login
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
      
      toast.success('Password changed successfully. Please log in again.');
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Password change failed';
      toast.error(errorMessage);
      throw error;
    }
  };

  // Clear error function
  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  };

  // Check permissions
  const hasPermission = (permission) => {
    return authService.hasPermission(permission);
  };

  // Check if user is admin
  const isAdmin = () => {
    return authService.isAdmin();
  };

  // Check if user is super admin
  const isSuperAdmin = () => {
    return authService.isSuperAdmin();
  };

  // Session management
  const refreshSession = async () => {
    try {
      await authService.refreshAuth();
      const user = authService.getCurrentUser();
      dispatch({ 
        type: AUTH_ACTIONS.SET_USER, 
        payload: user 
      });
    } catch (error) {
      dispatch({ type: AUTH_ACTIONS.SESSION_EXPIRED });
      throw error;
    }
  };

  // Context value
  const value = {
    // State
    user: state.user,
    isAuthenticated: state.isAuthenticated,
    isLoading: state.isLoading,
    error: state.error,
    
    // Actions
    login,
    logout,
    updateProfile,
    changePassword,
    clearError,
    refreshSession,
    
    // Utilities
    hasPermission,
    isAdmin,
    isSuperAdmin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
};

// HOC for protected routes
export const withAuth = (Component) => {
  return function AuthenticatedComponent(props) {
    const { isAuthenticated, isLoading } = useAuth();
    
    if (isLoading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="spinner w-8 h-8"></div>
        </div>
      );
    }
    
    if (!isAuthenticated) {
      window.location.href = '/login';
      return null;
    }
    
    return <Component {...props} />;
  };
};

// HOC for admin-only routes
export const withAdminAuth = (Component) => {
  return function AdminAuthenticatedComponent(props) {
    const { isAuthenticated, isLoading, isAdmin } = useAuth();
    
    if (isLoading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="spinner w-8 h-8"></div>
        </div>
      );
    }
    
    if (!isAuthenticated || !isAdmin()) {
      window.location.href = '/login';
      return null;
    }
    
    return <Component {...props} />;
  };
};

export default AuthContext;
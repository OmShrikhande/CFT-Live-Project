import Cookies from 'js-cookie';
import { authAPI } from './api';

// Token management with security best practices
const TOKEN_KEY = 'admin_token';
const REFRESH_TOKEN_KEY = 'admin_refresh_token';
const USER_KEY = 'admin_user';

// Cookie options for security
const COOKIE_OPTIONS = {
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  httpOnly: false, // We need to access from JS
};

export const authService = {
  // Login user
  async login(credentials) {
    try {
      const response = await authAPI.login(credentials);
      const { user, token, refreshToken } = response.data.data;
      
      // Validate user role
      if (!['admin', 'super_admin'].includes(user.role)) {
        throw new Error('Unauthorized: Admin access required');
      }
      
      // Store tokens and user data securely
      Cookies.set(TOKEN_KEY, token, { 
        expires: 1, // 1 day
        ...COOKIE_OPTIONS 
      });
      
      Cookies.set(REFRESH_TOKEN_KEY, refreshToken, { 
        expires: 7, // 7 days
        ...COOKIE_OPTIONS 
      });
      
      // Store user data (without sensitive information)
      const userData = {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        organization: user.organization,
        permissions: user.permissions,
        lastLogin: user.lastLogin,
      };
      
      Cookies.set(USER_KEY, JSON.stringify(userData), { 
        expires: 1,
        ...COOKIE_OPTIONS 
      });
      
      return { user: userData, token, refreshToken };
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  },
  
  // Logout user
  async logout() {
    try {
      const refreshToken = Cookies.get(REFRESH_TOKEN_KEY);
      if (refreshToken) {
        await authAPI.logout(refreshToken);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all auth data
      this.clearAuthData();
    }
  },
  
  // Clear authentication data
  clearAuthData() {
    Cookies.remove(TOKEN_KEY);
    Cookies.remove(REFRESH_TOKEN_KEY);
    Cookies.remove(USER_KEY);
    
    // Clear any cached data
    localStorage.removeItem('admin_cache');
    sessionStorage.clear();
  },
  
  // Get current user
  getCurrentUser() {
    try {
      const userData = Cookies.get(USER_KEY);
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Error parsing user data:', error);
      return null;
    }
  },
  
  // Get access token
  getToken() {
    return Cookies.get(TOKEN_KEY);
  },
  
  // Get refresh token
  getRefreshToken() {
    return Cookies.get(REFRESH_TOKEN_KEY);
  },
  
  // Check if user is authenticated
  isAuthenticated() {
    const token = this.getToken();
    const user = this.getCurrentUser();
    return !!(token && user);
  },
  
  // Check if user has admin role
  isAdmin() {
    const user = this.getCurrentUser();
    return user && ['admin', 'super_admin'].includes(user.role);
  },
  
  // Check if user has super admin role
  isSuperAdmin() {
    const user = this.getCurrentUser();
    return user && user.role === 'super_admin';
  },
  
  // Check if user has specific permission
  hasPermission(permission) {
    const user = this.getCurrentUser();
    if (!user || !user.permissions) return false;
    
    return user.permissions.includes(permission) || user.role === 'super_admin';
  },
  
  // Refresh authentication token
  async refreshAuth() {
    try {
      const refreshToken = this.getRefreshToken();
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }
      
      const response = await authAPI.refreshToken(refreshToken);
      const { token, refreshToken: newRefreshToken } = response.data.data;
      
      // Update tokens
      Cookies.set(TOKEN_KEY, token, { 
        expires: 1,
        ...COOKIE_OPTIONS 
      });
      
      Cookies.set(REFRESH_TOKEN_KEY, newRefreshToken, { 
        expires: 7,
        ...COOKIE_OPTIONS 
      });
      
      return token;
    } catch (error) {
      console.error('Token refresh error:', error);
      this.clearAuthData();
      throw error;
    }
  },
  
  // Update user profile
  async updateProfile(profileData) {
    try {
      const response = await authAPI.updateProfile(profileData);
      const { user } = response.data.data;
      
      // Update stored user data
      const userData = {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        organization: user.organization,
        permissions: user.permissions,
        lastLogin: user.lastLogin,
      };
      
      Cookies.set(USER_KEY, JSON.stringify(userData), { 
        expires: 1,
        ...COOKIE_OPTIONS 
      });
      
      return userData;
    } catch (error) {
      console.error('Profile update error:', error);
      throw error;
    }
  },
  
  // Change password
  async changePassword(passwordData) {
    try {
      const response = await authAPI.changePassword(passwordData);
      
      // Clear tokens to force re-login with new password
      this.clearAuthData();
      
      return response.data;
    } catch (error) {
      console.error('Password change error:', error);
      throw error;
    }
  },
  
  // Validate session
  async validateSession() {
    try {
      if (!this.isAuthenticated()) {
        return false;
      }
      
      const response = await authAPI.getProfile();
      const { user } = response.data.data;
      
      // Update user data
      const userData = {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        organization: user.organization,
        permissions: user.permissions,
        lastLogin: user.lastLogin,
      };
      
      Cookies.set(USER_KEY, JSON.stringify(userData), { 
        expires: 1,
        ...COOKIE_OPTIONS 
      });
      
      return true;
    } catch (error) {
      console.error('Session validation error:', error);
      this.clearAuthData();
      return false;
    }
  },
  
  // Security utilities
  security: {
    // Generate secure random string
    generateSecureRandom(length = 32) {
      const array = new Uint8Array(length);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },
    
    // Hash sensitive data (client-side hashing for additional security)
    async hashData(data) {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);
      const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },
    
    // Validate password strength
    validatePasswordStrength(password) {
      const minLength = 8;
      const hasUpperCase = /[A-Z]/.test(password);
      const hasLowerCase = /[a-z]/.test(password);
      const hasNumbers = /\d/.test(password);
      const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
      
      const score = [
        password.length >= minLength,
        hasUpperCase,
        hasLowerCase,
        hasNumbers,
        hasSpecialChar,
      ].filter(Boolean).length;
      
      return {
        isValid: score >= 4,
        score,
        requirements: {
          minLength: password.length >= minLength,
          hasUpperCase,
          hasLowerCase,
          hasNumbers,
          hasSpecialChar,
        },
      };
    },
    
    // Check for common passwords
    isCommonPassword(password) {
      const commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
      ];
      return commonPasswords.includes(password.toLowerCase());
    },
  },
};

export default authService;
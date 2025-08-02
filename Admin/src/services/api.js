import axios from 'axios';
import Cookies from 'js-cookie';
import toast from 'react-hot-toast';

// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5001/api/v1';

// Create axios instance with security configurations
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds timeout
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  },
});

// Security headers
api.defaults.headers.common['X-Frame-Options'] = 'DENY';
api.defaults.headers.common['X-Content-Type-Options'] = 'nosniff';
api.defaults.headers.common['X-XSS-Protection'] = '1; mode=block';

// Request interceptor for authentication
api.interceptors.request.use(
  (config) => {
    const token = Cookies.get('admin_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // Add CSRF token if available
    const csrfToken = Cookies.get('csrf_token');
    if (csrfToken) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    
    // Add request timestamp for security
    config.headers['X-Request-Time'] = Date.now();
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = Cookies.get('admin_refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refreshToken,
          });
          
          const { token, refreshToken: newRefreshToken } = response.data.data;
          
          // Update tokens
          Cookies.set('admin_token', token, { 
            expires: 1, // 1 day
            secure: true,
            sameSite: 'strict',
            httpOnly: false // We need to access this from JS
          });
          
          Cookies.set('admin_refresh_token', newRefreshToken, { 
            expires: 7, // 7 days
            secure: true,
            sameSite: 'strict',
            httpOnly: false
          });
          
          // Retry original request
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        Cookies.remove('admin_token');
        Cookies.remove('admin_refresh_token');
        Cookies.remove('admin_user');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    // Handle different error types
    if (error.response) {
      const { status, data } = error.response;
      
      switch (status) {
        case 400:
          toast.error(data.message || 'Bad request');
          break;
        case 401:
          toast.error('Unauthorized access');
          // Clear tokens and redirect to login
          Cookies.remove('admin_token');
          Cookies.remove('admin_refresh_token');
          Cookies.remove('admin_user');
          window.location.href = '/login';
          break;
        case 403:
          toast.error('Access forbidden');
          break;
        case 404:
          toast.error('Resource not found');
          break;
        case 422:
          // Validation errors
          if (data.errors && Array.isArray(data.errors)) {
            data.errors.forEach(err => toast.error(err.msg || err.message));
          } else {
            toast.error(data.message || 'Validation error');
          }
          break;
        case 429:
          toast.error('Too many requests. Please try again later.');
          break;
        case 500:
          toast.error('Internal server error');
          break;
        default:
          toast.error(data.message || 'An error occurred');
      }
    } else if (error.request) {
      toast.error('Network error. Please check your connection.');
    } else {
      toast.error('An unexpected error occurred');
    }
    
    return Promise.reject(error);
  }
);

// Auth API endpoints
export const authAPI = {
  login: (credentials) => api.post('/auth/login', credentials),
  logout: (refreshToken) => api.post('/auth/logout', { refreshToken }),
  refreshToken: (refreshToken) => api.post('/auth/refresh', { refreshToken }),
  getProfile: () => api.get('/auth/me'),
  updateProfile: (data) => api.put('/auth/profile', data),
  changePassword: (data) => api.put('/auth/change-password', data),
  forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
  resetPassword: (data) => api.post('/auth/reset-password', data),
};

// Admin API endpoints
export const adminAPI = {
  getDashboard: () => api.get('/admin/dashboard'),
  
  // User management
  getUsers: (params) => api.get('/admin/users', { params }),
  getUser: (userId) => api.get(`/admin/users/${userId}`),
  createUser: (userData) => api.post('/admin/users', userData),
  updateUser: (userId, userData) => api.put(`/admin/users/${userId}`, userData),
  deleteUser: (userId) => api.delete(`/admin/users/${userId}`),
  
  // Transfer requests
  getTransfers: (params) => api.get('/admin/transfers', { params }),
  getTransfer: (transferId) => api.get(`/admin/transfers/${transferId}`),
  requestTransfer: (userId, transferData) => api.post(`/admin/users/${userId}/transfer`, transferData),
  cancelTransfer: (transferId) => api.put(`/admin/transfers/${transferId}/cancel`),
  
  // Reports and analytics
  getUserStats: () => api.get('/admin/stats/users'),
  getTransferStats: () => api.get('/admin/stats/transfers'),
  getActivityLogs: (params) => api.get('/admin/logs', { params }),
  
  // Security
  getSecurityLogs: (params) => api.get('/admin/security/logs', { params }),
  getLoginAttempts: (params) => api.get('/admin/security/login-attempts', { params }),
  lockUser: (userId) => api.put(`/admin/users/${userId}/lock`),
  unlockUser: (userId) => api.put(`/admin/users/${userId}/unlock`),
};

// Utility functions
export const apiUtils = {
  // Handle file uploads with progress
  uploadFile: (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    
    return api.post('/admin/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        const percentCompleted = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total
        );
        onProgress?.(percentCompleted);
      },
    });
  },
  
  // Export data
  exportUsers: (format = 'csv') => api.get(`/admin/export/users?format=${format}`, {
    responseType: 'blob',
  }),
  
  exportTransfers: (format = 'csv') => api.get(`/admin/export/transfers?format=${format}`, {
    responseType: 'blob',
  }),
  
  // Health check
  healthCheck: () => api.get('/health'),
};

// Error handling utility
export const handleApiError = (error, customMessage) => {
  console.error('API Error:', error);
  
  if (customMessage) {
    toast.error(customMessage);
    return;
  }
  
  if (error.response?.data?.message) {
    toast.error(error.response.data.message);
  } else if (error.message) {
    toast.error(error.message);
  } else {
    toast.error('An unexpected error occurred');
  }
};

// Request retry utility
export const retryRequest = async (requestFn, maxRetries = 3, delay = 1000) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await requestFn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
    }
  }
};

export default api;
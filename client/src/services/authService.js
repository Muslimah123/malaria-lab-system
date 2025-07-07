// src/services/authService.js
import api from './api';

const authService = {
  // Login user
  login: async (credentials) => {
    const response = await api.post('/auth/login', credentials);
    
    if (response.data.success && response.data.data.token) {
      // Store token in localStorage and set default header
      const { token, user } = response.data.data;
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));
      
      // Set default authorization header for future requests
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    
    return response;
  },

  // Logout user
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      // Even if server logout fails, we should clear local storage
      console.error('Server logout failed:', error);
    } finally {
      // Clear local storage and headers
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      delete api.defaults.headers.common['Authorization'];
    }
  },

  // Verify current session
  verifySession: async () => {
    const response = await api.get('/auth/verify-session');
    return response;
  },

  // Register new user (if needed)
  register: async (userData) => {
    const response = await api.post('/auth/register', userData);
    return response;
  },

  // Get current user
  getCurrentUser: () => {
    try {
      const user = localStorage.getItem('user');
      return user ? JSON.parse(user) : null;
    } catch (error) {
      console.error('Error parsing user from localStorage:', error);
      return null;
    }
  },

  // Get current token
  getToken: () => {
    return localStorage.getItem('token');
  },

  // Check if user is authenticated
  isAuthenticated: () => {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    return !!(token && user);
  },

  // Refresh token (if your backend supports it)
  refreshToken: async () => {
    try {
      const response = await api.post('/auth/refresh');
      if (response.data.success && response.data.data.token) {
        const { token } = response.data.data;
        localStorage.setItem('token', token);
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      }
      return response;
    } catch (error) {
      // If refresh fails, user needs to login again
      authService.logout();
      throw error;
    }
  },

  // Check user role
  hasRole: (role) => {
    const user = authService.getCurrentUser();
    return user && user.role === role;
  },

  // Check user permissions
  hasPermission: (permission) => {
    const user = authService.getCurrentUser();
    return user && user.permissions && user.permissions[permission];
  },
};

export default authService;
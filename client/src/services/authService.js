// src/services/authService.js
import api, { tokenManager } from './api';

const authService = {
  // Login user
  login: async (credentials) => {
    const response = await api.post('/auth/login', credentials);
    if (response.data.success && response.data.data.token) {
      const { token, user } = response.data.data;
      tokenManager.setToken(token);
      tokenManager.setUser(user);
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    return response;
  },

  // Logout user
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Server logout failed:', error);
    } finally {
      tokenManager.clearAll();
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
  getCurrentUser: () => tokenManager.getUser(),

  // Get current token
  getToken: () => tokenManager.getToken(),

  // Check if user is authenticated
  isAuthenticated: () => {
    return !!(tokenManager.getToken() && tokenManager.getUser());
  },

  // Refresh token (if your backend supports it)
  refreshToken: async () => {
    try {
      const response = await api.post('/auth/refresh');
      if (response.data.success && response.data.data.token) {
        const { token } = response.data.data;
        tokenManager.setToken(token);
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      }
      return response;
    } catch (error) {
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
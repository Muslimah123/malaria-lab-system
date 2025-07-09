// 📁 client/src/services/api.js
/**
 * API Module for Malaria Diagnosis Lab System
 * Handles all backend interactions with JWT auth, token refresh, and error handling
 */

import axios from 'axios';

// Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
const TOKEN_KEY = 'authToken';
const REFRESH_TOKEN_KEY = 'refreshToken';
const USER_KEY = 'user';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 seconds
});

// Token management utilities
const tokenManager = {
  getToken: () => localStorage.getItem(TOKEN_KEY),
  setToken: (token) => localStorage.setItem(TOKEN_KEY, token),
  removeToken: () => localStorage.removeItem(TOKEN_KEY),
  
  getRefreshToken: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  setRefreshToken: (token) => localStorage.setItem(REFRESH_TOKEN_KEY, token),
  removeRefreshToken: () => localStorage.removeItem(REFRESH_TOKEN_KEY),
  
  getUser: () => {
    try {
      const user = localStorage.getItem(USER_KEY);
      return user ? JSON.parse(user) : null;
    } catch {
      return null;
    }
  },
  setUser: (user) => localStorage.setItem(USER_KEY, JSON.stringify(user)),
  removeUser: () => localStorage.removeItem(USER_KEY),
  
  clearAll: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
};

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = tokenManager.getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh and errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 errors (token expired or invalid)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = tokenManager.getRefreshToken();
        if (refreshToken) {
          const response = await api.post('/auth/refresh', { refreshToken });
          
          if (response.data.success && response.data.data.token) {
            tokenManager.setToken(response.data.data.token);
            if (response.data.data.refreshToken) {
              tokenManager.setRefreshToken(response.data.data.refreshToken);
            }
            
            // Retry original request with new token
            originalRequest.headers.Authorization = `Bearer ${response.data.data.token}`;
            return api(originalRequest);
          }
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        tokenManager.clearAll();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Handle other errors
    if (error.response?.status === 403) {
      // Forbidden - insufficient permissions
      console.error('Access denied:', error.response.data.message);
    }

    if (error.response?.status === 429) {
      // Rate limit exceeded
      console.error('Rate limit exceeded:', error.response.data.message);
    }

    return Promise.reject(error);
  }
);

// API Service Class
class ApiService {
  // Auth endpoints
  auth = {
    login: async (credentials) => {
      const response = await api.post('/auth/login', credentials);
      
      if (response.data.success && response.data.data) {
        const { token, refreshToken, user } = response.data.data;
        tokenManager.setToken(token);
        if (refreshToken) {
          tokenManager.setRefreshToken(refreshToken);
        }
        tokenManager.setUser(user);
      }
      
      return response.data;
    },

    register: async (userData) => {
      const response = await api.post('/auth/register', userData);
      return response.data;
    },

    logout: async () => {
      try {
        await api.post('/auth/logout');
      } finally {
        tokenManager.clearAll();
      }
    },

    getCurrentUser: async () => {
      const response = await api.get('/auth/me');
      return response.data;
    },

    refreshToken: async () => {
      const refreshToken = tokenManager.getRefreshToken();
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await api.post('/auth/refresh', { refreshToken });
      
      if (response.data.success && response.data.data) {
        const { token, refreshToken: newRefreshToken } = response.data.data;
        tokenManager.setToken(token);
        if (newRefreshToken) {
          tokenManager.setRefreshToken(newRefreshToken);
        }
      }
      
      return response.data;
    },

    changePassword: async (passwordData) => {
      const response = await api.put('/auth/change-password', passwordData);
      return response.data;
    },

    forgotPassword: async (email) => {
      const response = await api.post('/auth/forgot-password', { email });
      return response.data;
    },

    resetPassword: async (token, newPassword) => {
      const response = await api.post('/auth/reset-password', { token, newPassword });
      return response.data;
    },

    verifySession: async () => {
      const response = await api.get('/auth/verify-session');
      return response.data;
    }
  };

  // User management endpoints (admin only)
  users = {
    getAll: async (params = {}) => {
      const response = await api.get('/users', { params });
      return response.data;
    },

    search: async (query, params = {}) => {
      const response = await api.get('/users/search', { 
        params: { query, ...params } 
      });
      return response.data;
    },

    updateRole: async (userId, role) => {
      const response = await api.put(`/users/${userId}/role`, { role });
      return response.data;
    },

    resetPassword: async (userId, newPassword) => {
      const response = await api.post(`/users/${userId}/reset-password`, { newPassword });
      return response.data;
    },

    delete: async (userId) => {
      const response = await api.delete(`/users/${userId}`);
      return response.data;
    }
  };

  // Patient endpoints
  patients = {
    getAll: async (params = {}) => {
      const response = await api.get('/patients', { params });
      return response.data;
    },

    getById: async (patientId) => {
      const response = await api.get(`/patients/${patientId}`);
      return response.data;
    },

    create: async (patientData) => {
      const response = await api.post('/patients', patientData);
      return response.data;
    },

    update: async (patientId, patientData) => {
      const response = await api.put(`/patients/${patientId}`, patientData);
      return response.data;
    },

    delete: async (patientId) => {
      const response = await api.delete(`/patients/${patientId}`);
      return response.data;
    },

    search: async (q, limit = 10) => {
      const response = await api.get('/patients/search', { 
        params: { q, limit } 
      });
      return response.data;
    },

    getTests: async (patientId, params = {}) => {
      const response = await api.get(`/patients/${patientId}/tests`, { params });
      return response.data;
    },

    getHistory: async (patientId, params = {}) => {
      const response = await api.get(`/patients/${patientId}/history`, { params });
      return response.data;
    },

    exportData: async (patientId, format = 'pdf', includeTestImages = false) => {
      const response = await api.get(`/patients/${patientId}/export`, {
        params: { format, includeTestImages },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/patients/statistics', { params });
      return response.data;
    },

    bulkImport: async (file, validateOnly = false) => {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('validateOnly', validateOnly);
      
      const response = await api.post('/patients/bulk-import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return response.data;
    }
  };

  // Test endpoints
  tests = {
    getAll: async (params = {}) => {
      const response = await api.get('/tests', { params });
      return response.data;
    },

    getById: async (testId) => {
      const response = await api.get(`/tests/${testId}`);
      return response.data;
    },

    create: async (testData) => {
      const response = await api.post('/tests', testData);
      return response.data;
    },

    update: async (testId, testData) => {
      const response = await api.put(`/tests/${testId}`, testData);
      return response.data;
    },

    delete: async (testId) => {
      const response = await api.delete(`/tests/${testId}`);
      return response.data;
    },

    updateStatus: async (testId, status, notes = null) => {
      const response = await api.patch(`/tests/${testId}/status`, { status, notes });
      return response.data;
    },

    assignTest: async (testId, technicianId) => {
      const response = await api.patch(`/tests/${testId}/assign`, { technicianId });
      return response.data;
    },

    getMyTests: async (params = {}) => {
      const response = await api.get('/tests/technician/my-tests', { params });
      return response.data;
    },

    getByPatient: async (patientId, params = {}) => {
      const response = await api.get(`/tests/patient/${patientId}`, { params });
      return response.data;
    },

    getPending: async (params = {}) => {
      const response = await api.get('/tests/pending', { params });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/tests/statistics', { params });
      return response.data;
    }
  };

  // Upload endpoints
  upload = {
    createSession: async (testId, config = {}) => {
      const response = await api.post('/upload/session', { testId, ...config });
      return response.data;
    },

    getSession: async (sessionId) => {
      const response = await api.get(`/upload/session/${sessionId}`);
      return response.data;
    },

    uploadFiles: async (sessionId, files, onProgress) => {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await api.post(`/upload/files/${sessionId}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (progressEvent) => {
          if (onProgress) {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            onProgress(percentCompleted);
          }
        }
      });
      return response.data;
    },

    processFiles: async (sessionId) => {
      const response = await api.post(`/upload/process/${sessionId}`);
      return response.data;
    },

    validateFiles: async (files) => {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await api.post('/upload/validate-files', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return response.data;
    },

    getMySessions: async (params = {}) => {
      const response = await api.get('/upload/my-sessions', { params });
      return response.data;
    },

    cancelSession: async (sessionId, reason) => {
      const response = await api.patch(`/upload/cancel/${sessionId}`, { reason });
      return response.data;
    },

    deleteFile: async (sessionId, filename) => {
      const response = await api.delete(`/upload/delete-file/${sessionId}`, { 
        data: { filename } 
      });
      return response.data;
    },

    retryUpload: async (sessionId, retryType = 'processing', filenames = []) => {
      const response = await api.post(`/upload/retry/${sessionId}`, { 
        retryType, 
        filenames 
      });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/upload/statistics', { params });
      return response.data;
    },

    cleanupSessions: async () => {
      const response = await api.post('/upload/cleanup');
      return response.data;
    }
  };

  // Diagnosis endpoints
  diagnosis = {
    getAll: async (params = {}) => {
      const response = await api.get('/diagnosis', { params });
      return response.data;
    },

    getByTestId: async (testId) => {
      const response = await api.get(`/diagnosis/${testId}`);
      return response.data;
    },

    runDiagnosis: async (testId) => {
      const response = await api.post(`/diagnosis/${testId}/run`);
      return response.data;
    },

    addManualReview: async (testId, reviewData) => {
      const response = await api.post(`/diagnosis/${testId}/review`, reviewData);
      return response.data;
    },

    getImages: async (testId, imageId = null) => {
      const params = imageId ? { imageId } : {};
      const response = await api.get(`/diagnosis/${testId}/images`, { params });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/diagnosis/statistics', { params });
      return response.data;
    },

    getRequiringReview: async (params = {}) => {
      const response = await api.get('/diagnosis/requiring-review', { params });
      return response.data;
    },

    getPositiveCases: async (params = {}) => {
      const response = await api.get('/diagnosis/positive-cases', { params });
      return response.data;
    },

    exportReport: async (testId, format = 'pdf') => {
      const response = await api.get(`/diagnosis/${testId}/export`, {
        params: { format },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    sendToHospitalEMR: async (testId, data = {}) => {
      const response = await api.post(`/diagnosis/${testId}/hospital-integration`, data);
      return response.data;
    },

    batchExport: async (testIds, format = 'pdf', includeImages = false) => {
      const response = await api.post('/diagnosis/batch-export', {
        testIds,
        format,
        includeImages
      }, {
        responseType: 'blob'
      });
      return response.data;
    },

    addQualityFeedback: async (testId, feedback) => {
      const response = await api.post(`/diagnosis/${testId}/quality-feedback`, feedback);
      return response.data;
    }
  };

  // Report endpoints
  reports = {
    generateTestReport: async (testId, format = 'pdf', includeImages = false) => {
      const response = await api.get(`/reports/test/${testId}`, {
        params: { format, includeImages },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    generateBulkReports: async (params) => {
      const response = await api.post('/reports/bulk', params, {
        responseType: 'blob'
      });
      return response.data;
    },

    exportCSV: async (params = {}) => {
      const response = await api.get('/reports/export/csv', {
        params,
        responseType: 'blob'
      });
      return response.data;
    },

    getAvailable: async (params = {}) => {
      const response = await api.get('/reports/available', { params });
      return response.data;
    },

    getStatistics: async (period = 'month') => {
      const response = await api.get('/reports/statistics', { params: { period } });
      return response.data;
    },

    scheduleReport: async (scheduleData) => {
      const response = await api.post('/reports/schedule', scheduleData);
      return response.data;
    }
  };

  // Analytics endpoints
  analytics = {
    getDashboard: async () => {
      const response = await api.get('/analytics/dashboard');
      return response.data;
    },

    getComprehensive: async (params = {}) => {
      const response = await api.get('/analytics/comprehensive', { params });
      return response.data;
    },

    getTestTrends: async (params = {}) => {
      const response = await api.get('/analytics/test-trends', { params });
      return response.data;
    },

    getDiagnosisDistribution: async (params = {}) => {
      const response = await api.get('/analytics/diagnosis-distribution', { params });
      return response.data;
    },

    getParasiteTypes: async (params = {}) => {
      const response = await api.get('/analytics/parasite-types', { params });
      return response.data;
    },

    getTechnicianPerformance: async (params = {}) => {
      const response = await api.get('/analytics/technician-performance', { params });
      return response.data;
    },

    getQualityMetrics: async (params = {}) => {
      const response = await api.get('/analytics/quality-metrics', { params });
      return response.data;
    },

    exportAnalytics: async (type = 'trends', params = {}) => {
      const response = await api.get('/analytics/export', {
        params: { type, ...params },
        responseType: 'blob'
      });
      return response.data;
    }
  };

  // Integration endpoints
  integration = {
    syncTest: async (testId, system = 'api', priority = 'normal') => {
      const response = await api.post(`/integration/sync/${testId}`, { system, priority });
      return response.data;
    },

    bulkSync: async (params) => {
      const response = await api.post('/integration/bulk-sync', params);
      return response.data;
    },

    getStatus: async (params = {}) => {
      const response = await api.get('/integration/status', { params });
      return response.data;
    },

    configure: async (config) => {
      const response = await api.post('/integration/configure', config);
      return response.data;
    },

    getHealth: async () => {
      const response = await api.get('/integration/health');
      return response.data;
    },

    retryFailed: async (testIds = [], maxRetries = 3) => {
      const response = await api.post('/integration/retry-failed', { testIds, maxRetries });
      return response.data;
    },

    testConnection: async (endpoint = null, authMethod = null, credentials = null) => {
      const response = await api.post('/integration/test-connection', {
        endpoint,
        authMethod,
        credentials
      });
      return response.data;
    },

    getLogs: async (params = {}) => {
      const response = await api.get('/integration/logs', { params });
      return response.data;
    }
  };

  // Utility methods
  isAuthenticated() {
    return !!tokenManager.getToken();
  }

  getCurrentUser() {
    return tokenManager.getUser();
  }

  hasRole(role) {
    const user = this.getCurrentUser();
    return user && user.role === role;
  }

  hasPermission(permission) {
    const user = this.getCurrentUser();
    return user && user.permissions && user.permissions[permission];
  }

  clearAuth() {
    tokenManager.clearAll();
  }

  // Helper method to handle file downloads
  downloadFile(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }

  // Helper method to format errors
  formatError(error) {
    if (error.response?.data?.message) {
      return error.response.data.message;
    }
    if (error.response?.data?.errors) {
      // Handle validation errors
      const errors = error.response.data.errors;
      if (typeof errors === 'object') {
        return Object.entries(errors)
          .map(([field, messages]) => `${field}: ${messages.join(', ')}`)
          .join('; ');
      }
    }
    if (error.message) {
      return error.message;
    }
    return 'An unexpected error occurred';
  }
}

// Create and export singleton instance
const apiService = new ApiService();

// Export both the instance and the axios instance for advanced usage
export { api, tokenManager };
export default apiService;
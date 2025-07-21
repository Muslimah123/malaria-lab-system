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

// Error handling utility
const handleApiError = (error) => {
  // Handle Axios errors
  if (error.response) {
    // Server responded with error status (4xx, 5xx)
    const status = error.response.status;
    const message = error.response.data?.message || error.response.data?.error;
    
    switch (status) {
      case 400:
        return message || 'Bad request - please check your input';
      case 401:
        return 'Authentication required - please log in again';
      case 403:
        return 'Access denied - insufficient permissions';
      case 404:
        return message || 'Resource not found';
      case 422:
        return message || 'Validation error - please check your input';
      case 429:
        return 'Too many requests - please try again later';
      case 500:
        return 'Server error - please try again later';
      case 502:
        return 'Service temporarily unavailable';
      case 503:
        return 'Service unavailable - please try again later';
      default:
        return message || `Error: ${status}`;
    }
  } else if (error.request) {
    // Request was made but no response received
    return 'Network error - please check your connection';
  } else {
    // Something else happened in making the request
    return error.message || 'An unexpected error occurred';
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
  // Allow setting token from outside (for compatibility)
  setToken(token) {
    tokenManager.setToken(token);
  }
  // Auth endpoints
  auth = {
    login: async (credentials) => {
      const response = await api.post('/api/auth/login', credentials);
      
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
      const response = await api.post('/api/auth/register', userData);
      return response.data;
    },

    logout: async () => {
      try {
        await api.post('/api/auth/logout');
      } finally {
        tokenManager.clearAll();
      }
    },

    getCurrentUser: async () => {
      const response = await api.get('/api/auth/me');
      return response.data;
    },

    refreshToken: async () => {
      const refreshToken = tokenManager.getRefreshToken();
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await api.post('/api/auth/refresh', { refreshToken });
      
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
      const response = await api.put('/api/auth/change-password', passwordData);
      return response.data;
    },

    forgotPassword: async (email) => {
      const response = await api.post('/api/auth/forgot-password', { email });
      return response.data;
    },

    resetPassword: async (token, newPassword) => {
      const response = await api.post('/api/auth/reset-password', { token, newPassword });
      return response.data;
    },

    verifySession: async () => {
      const response = await api.get('/api/auth/verify-session');
      return response.data;
    }
  };

  // User management endpoints (admin only)
  users = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/users', { params });
      return response.data;
    },

    search: async (query, params = {}) => {
      const response = await api.get('/api/users/search', { 
        params: { query, ...params } 
      });
      return response.data;
    },

    updateRole: async (userId, role) => {
      const response = await api.put(`/api/users/${userId}/role`, { role });
      return response.data;
    },

    resetPassword: async (userId, newPassword) => {
      const response = await api.post(`/api/users/${userId}/reset-password`, { newPassword });
      return response.data;
    },

    delete: async (userId) => {
      const response = await api.delete(`/api/users/${userId}`);
      return response.data;
    }
  };

  // Patient endpoints
  patients = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/patients', { params });
      return response.data;
    },

    getById: async (patientId) => {
      const response = await api.get(`/api/patients/${patientId}`);
      return response.data;
    },

    // create: async (patientData) => {
    //   const response = await api.post('/api/patients', patientData);
    //   return response.data;
    // },
    create: async (patientData) => {
  try {
    const response = await api.post('/api/patients', patientData);
    
    // Handle different response structures  
    const patient = response.data?.data?.patient || 
                   response.data?.data || 
                   response.data?.patient || 
                   response.data;
    
    // Your exact normalization logic
    if (patient && !patient.patientId && patient._id) {
      patient.patientId = patient._id;
    }
    
    return response; // Return original response structure
  } catch (error) {
    throw error; // Let SampleUpload handle the error
  }
},

    update: async (patientId, patientData) => {
      const response = await api.put(`/api/patients/${patientId}`, patientData);
      return response.data;
    },

    delete: async (patientId) => {
      const response = await api.delete(`/api/patients/${patientId}`);
      return response.data;
    },


    search: async (q, limit = 10) => {
  try {
    const response = await api.get('/api/patients/search', { 
      params: { q, limit } 
    });
    
    // Handle different backend response structures
    const data = response.data?.data || response.data;
    const patients = Array.isArray(data) ? data : 
                    data?.patients ? data.patients :
                    data?.results ? data.results : [];
    
    return {
      success: true,
      data: patients
    };
  } catch (error) {
    console.error('Patient search failed:', error);
    return {
      success: false, 
      data: [],
      error: this.formatError(error)
    };
  }
},

    getTests: async (patientId, params = {}) => {
      const response = await api.get(`/api/patients/${patientId}/tests`, { params });
      return response.data;
    },

    getHistory: async (patientId, params = {}) => {
      const response = await api.get(`/api/patients/${patientId}/history`, { params });
      return response.data;
    },

    exportData: async (patientId, format = 'pdf', includeTestImages = false) => {
      const response = await api.get(`/api/patients/${patientId}/export`, {
        params: { format, includeTestImages },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/api/patients/statistics', { params });
      return response.data;
    },

    bulkImport: async (file, validateOnly = false) => {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('validateOnly', validateOnly);
      
      const response = await api.post('/api/patients/bulk-import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return response.data;
    }
  };

  // Test endpoints
  tests = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/tests', { params });
      return response.data;
    },

    getById: async (testId) => {
      const response = await api.get(`/api/tests/${testId}`);
      return response.data;
    },

    create: async (testData) => {
      const response = await api.post('/api/tests', testData);
      return response.data;
    },

    update: async (testId, testData) => {
      const response = await api.put(`/api/tests/${testId}`, testData);
      return response.data;
    },

    delete: async (testId) => {
      const response = await api.delete(`/api/tests/${testId}`);
      return response.data;
    },

    updateStatus: async (testId, status, notes = null) => {
      const response = await api.patch(`/api/tests/${testId}/status`, { status, notes });
      return response.data;
    },

    assignTest: async (testId, technicianId) => {
      const response = await api.patch(`/api/tests/${testId}/assign`, { technicianId });
      return response.data;
    },

    getMyTests: async (params = {}) => {
      const response = await api.get('/api/tests/technician/my-tests', { params });
      return response.data;
    },

    getByPatient: async (patientId, params = {}) => {
      const response = await api.get(`/api/tests/patient/${patientId}`, { params });
      return response.data;
    },

    getPending: async (params = {}) => {
      const response = await api.get('/api/tests/pending', { params });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/api/tests/statistics', { params });
      return response.data;
    }
  };

  // Upload endpoints
  upload = {
    createSession: async (sessionData) => {
  const response = await api.post('/api/upload/session', sessionData);
  return response.data;
},

    getSession: async (sessionId) => {
      const response = await api.get(`/api/upload/session/${sessionId}`);
      return response.data;
    },
   
  uploadFiles: async (sessionId, files, onProgress) => {
  console.log('🌐 API uploadFiles called with:', { sessionId, files, filesCount: files?.length });
  
  const formData = new FormData();
  
  if (Array.isArray(files)) {
    files.forEach((file, index) => {
      console.log(` Adding file ${index}:`, file.name, file.size);
      formData.append('files', file);
    });
  } else if (files instanceof FileList) {
    Array.from(files).forEach((file, index) => {
      console.log(` Adding file ${index}:`, file.name, file.size);
      formData.append('files', file);
    });
  } else {
    console.log('Adding single file:', files.name, files.size);
    formData.append('files', files);
  }

  console.log('Making API call to:', `/api/upload/files/${sessionId}`);
  
  try {
    const response = await api.post(`/api/upload/files/${sessionId}`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        console.log('Upload progress:', percentCompleted + '%');
        if (onProgress) {
          onProgress(percentCompleted);
        }
      }
    });
    
    console.log('✅ API response:', response.data);
    return response.data;
  } catch (error) {
    console.error(' API upload error:', error);
    console.error(' Error response:', error.response?.data);
    throw error;
  }
},

    processFiles: async (sessionId) => {
      const response = await api.post(`/api/upload/process/${sessionId}`);
      return response.data;
    },

    validateFiles: async (files) => {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await api.post('/api/upload/validate-files', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return response.data;
    },

    getMySessions: async (params = {}) => {
      const response = await api.get('/api/upload/my-sessions', { params });
      return response.data;
    },

    cancelSession: async (sessionId, reason) => {
      const response = await api.patch(`/api/upload/cancel/${sessionId}`, { reason });
      return response.data;
    },

    deleteFile: async (sessionId, filename) => {
      const response = await api.delete(`/api/upload/delete-file/${sessionId}`, { 
        data: { filename } 
      });
      return response.data;
    },

    retryUpload: async (sessionId, retryType = 'processing', filenames = []) => {
      const response = await api.post(`/api/upload/retry/${sessionId}`, { 
        retryType, 
        filenames 
      });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/api/upload/statistics', { params });
      return response.data;
    },

    cleanupSessions: async () => {
      const response = await api.post('/api/upload/cleanup');
      return response.data;
    }
  };

  // Diagnosis endpoints
  diagnosis = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/diagnosis', { params });
      return response.data;
    },

    getByTestId: async (testId) => {
      const response = await api.get(`/api/diagnosis/${testId}`);
      return response.data;
    },

    runDiagnosis: async (testId) => {
      const response = await api.post(`/api/diagnosis/${testId}/run`);
      return response.data;
    },

    addManualReview: async (testId, reviewData) => {
      const response = await api.post(`/api/diagnosis/${testId}/review`, reviewData);
      return response.data;
    },

    getImages: async (testId, imageId = null) => {
      const params = imageId ? { imageId } : {};
      const response = await api.get(`/api/diagnosis/${testId}/images`, { params });
      return response.data;
    },

    getStatistics: async (params = {}) => {
      const response = await api.get('/api/diagnosis/statistics', { params });
      return response.data;
    },

    getRequiringReview: async (params = {}) => {
      const response = await api.get('/api/diagnosis/requiring-review', { params });
      return response.data;
    },

    getPositiveCases: async (params = {}) => {
      const response = await api.get('/api/diagnosis/positive-cases', { params });
      return response.data;
    },

    exportReport: async (testId, format = 'pdf') => {
      const response = await api.get(`/api/diagnosis/${testId}/export`, {
        params: { format },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    sendToHospitalEMR: async (testId, data = {}) => {
      const response = await api.post(`/api/diagnosis/${testId}/hospital-integration`, data);
      return response.data;
    },

    batchExport: async (testIds, format = 'pdf', includeImages = false) => {
      const response = await api.post('/api/diagnosis/batch-export', {
        testIds,
        format,
        includeImages
      }, {
        responseType: 'blob'
      });
      return response.data;
    },

    addQualityFeedback: async (testId, feedback) => {
      const response = await api.post(`/api/diagnosis/${testId}/quality-feedback`, feedback);
      return response.data;
    }
  };

  // Report endpoints
  reports = {
    generateTestReport: async (testId, format = 'pdf', includeImages = false) => {
      const response = await api.get(`/api/reports/test/${testId}`, {
        params: { format, includeImages },
        responseType: format === 'pdf' ? 'blob' : 'json'
      });
      return response.data;
    },

    generateBulkReports: async (params) => {
      const response = await api.post('/api/reports/bulk', params, {
        responseType: 'blob'
      });
      return response.data;
    },

    exportCSV: async (params = {}) => {
      const response = await api.get('/api/reports/export/csv', {
        params,
        responseType: 'blob'
      });
      return response.data;
    },

    getAvailable: async (params = {}) => {
      const response = await api.get('/api/reports/available', { params });
      return response.data;
    },

    getStatistics: async (period = 'month') => {
      const response = await api.get('/api/reports/statistics', { params: { period } });
      return response.data;
    },

    scheduleReport: async (scheduleData) => {
      const response = await api.post('/api/reports/schedule', scheduleData);
      return response.data;
    }
  };

  // Analytics endpoints
  analytics = {
    getDashboard: async () => {
      const response = await api.get('/api/analytics/dashboard');
      return response.data;
    },

    getComprehensive: async (params = {}) => {
      const response = await api.get('/api/analytics/comprehensive', { params });
      return response.data;
    },

    getTestTrends: async (params = {}) => {
      const response = await api.get('/api/analytics/test-trends', { params });
      return response.data;
    },

    getDiagnosisDistribution: async (params = {}) => {
      const response = await api.get('/api/analytics/diagnosis-distribution', { params });
      return response.data;
    },

    getParasiteTypes: async (params = {}) => {
      const response = await api.get('/api/analytics/parasite-types', { params });
      return response.data;
    },

    getTechnicianPerformance: async (params = {}) => {
      const response = await api.get('/api/analytics/technician-performance', { params });
      return response.data;
    },

    getQualityMetrics: async (params = {}) => {
      const response = await api.get('/api/analytics/quality-metrics', { params });
      return response.data;
    },

    exportAnalytics: async (type = 'trends', params = {}) => {
      const response = await api.get('/api/analytics/export', {
        params: { type, ...params },
        responseType: 'blob'
      });
      return response.data;
    }
  };

  // Integration endpoints
  integration = {
    syncTest: async (testId, system = 'api', priority = 'normal') => {
      const response = await api.post(`/api/integration/sync/${testId}`, { system, priority });
      return response.data;
    },

    bulkSync: async (params) => {
      const response = await api.post('/api/integration/bulk-sync', params);
      return response.data;
    },

    getStatus: async (params = {}) => {
      const response = await api.get('/api/integration/status', { params });
      return response.data;
    },

    configure: async (config) => {
      const response = await api.post('/api/integration/configure', config);
      return response.data;
    },

    getHealth: async () => {
      const response = await api.get('/api/integration/health');
      return response.data;
    },

    retryFailed: async (testIds = [], maxRetries = 3) => {
      const response = await api.post('/api/integration/retry-failed', { testIds, maxRetries });
      return response.data;
    },

    testConnection: async (endpoint = null, authMethod = null, credentials = null) => {
      const response = await api.post('/api/integration/test-connection', {
        endpoint,
        authMethod,
        credentials
      });
      return response.data;
    },

    getLogs: async (params = {}) => {
      const response = await api.get('/api/integration/logs', { params });
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
apiService.handleApiError = handleApiError;


// Export both the instance and the axios instance for advanced usage
export { api, tokenManager };
export default apiService;
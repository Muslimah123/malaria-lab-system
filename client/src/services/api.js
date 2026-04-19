
// client/src/services/api.js - SIMPLIFIED VERSION
/**
 * API Module for Malaria Diagnosis Lab System
 * Simplified for basic detection features only
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
  timeout: 300000, // 5 minutes for basic detection
});

// Token management utilities
const tokenManager = {
  getToken: () => {
    const token = localStorage.getItem(TOKEN_KEY);
    return token;
  },
  setToken: (token) => {
    localStorage.setItem(TOKEN_KEY, token);
  },
  removeToken: () => {
    localStorage.removeItem(TOKEN_KEY);
  },
  
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

// Request interceptor with performance monitoring and token validation
api.interceptors.request.use(
  (config) => {
    // Start performance monitoring for this API call
    // const apiCall = performanceMonitor.startApiCall(config.url, config.method?.toUpperCase());
    // config.metadata = { apiCall };
    
    // ✅ ENHANCED: Add auth token with validation
    const token = tokenManager.getToken();
    if (token) {
      // Check if token is expired or about to expire
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        const now = Date.now() / 1000;
        const timeUntilExpiry = payload.exp - now;
        
        if (timeUntilExpiry < 300) { // Less than 5 minutes
          console.warn('🔄 Token expiring soon in request interceptor');
          // Don't block the request, let it proceed and handle 401 response
        }
        
        config.headers.Authorization = `Bearer ${token}`;
      } catch (error) {
        console.error('Error parsing token in request interceptor:', error);
        // Remove invalid token
        tokenManager.removeToken();
      }
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// ✅ ENHANCED: Response interceptor with automatic token refresh and retry
api.interceptors.response.use(
  (response) => {
    // End performance monitoring for successful calls
    // if (response.config.metadata?.apiCall) {
    //   response.config.metadata.apiCall.end(true);
    // }
    
    return response;
  },
  async (error) => {
    // End performance monitoring for failed calls
    // if (error.config?.metadata?.apiCall) {
    //   error.config.metadata.apiCall.end(false, error);
    // }
    
    const originalRequest = error.config;
    
    // Handle authentication errors with automatic token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        console.log('🔄 401 error detected, attempting token refresh...');
        
        // Try to refresh the token
        const refreshToken = tokenManager.getRefreshToken();
        if (refreshToken) {
          const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:5000'}/api/auth/refresh`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refreshToken }),
          });

          if (response.ok) {
            const data = await response.json();
            if (data.success && data.data.token) {
              // Update tokens
              tokenManager.setToken(data.data.token);
              if (data.data.refreshToken) {
                tokenManager.setRefreshToken(data.data.refreshToken);
              }
              
              // Update API headers
              api.defaults.headers.common['Authorization'] = `Bearer ${data.data.token}`;
              
              // Retry the original request with new token
              originalRequest.headers.Authorization = `Bearer ${data.data.token}`;
              console.log('✅ Token refreshed, retrying original request...');
              
              return api(originalRequest);
            }
          }
        }
        
        // If refresh failed or no refresh token, logout
        console.error('❌ Token refresh failed, logging out user');
        tokenManager.clearAll();
        window.location.href = '/login';
        
      } catch (refreshError) {
        console.error('❌ Error during token refresh:', refreshError);
        tokenManager.clearAll();
        window.location.href = '/login';
      }
    }
    
    // Handle other errors
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
        
        // Immediately set the token in API headers for subsequent requests
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
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

  // ✅ ENHANCED User management endpoints (admin only)
  users = {
    /**
     * Get all users with enhanced statistics and filtering
     * @param {Object} params - Query parameters
     * @param {number} params.page - Page number (default: 1)
     * @param {number} params.limit - Items per page (default: 20)
     * @param {string} params.role - Filter by role: 'all', 'admin', 'supervisor', 'technician'
     * @param {string} params.status - Filter by status: 'all', 'active', 'inactive'
     * @returns {Promise} Response with users, pagination, and statistics
     */
    getAll: async (params = {}) => {
      try {
        const response = await api.get('/api/users', { params });
        console.log('👥 Users API response:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Get users error:', error);
        throw error;
      }
    },

    /**
     * Search users with enhanced filters and statistics
     * @param {string} query - Search query (username, email, firstName, lastName)
     * @param {Object} params - Additional parameters
     * @param {string} params.role - Filter by role
     * @param {string} params.status - Filter by status
     * @param {number} params.page - Page number
     * @param {number} params.limit - Items per page
     * @returns {Promise} Search results with user statistics
     */
    search: async (query, params = {}) => {
      try {
        const response = await api.get('/api/users/search', { 
          params: { query, ...params } 
        });
        console.log('🔍 User search response:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Search users error:', error);
        throw error;
      }
    },

    /**
     * Get comprehensive user and system statistics
     * @returns {Promise} User statistics including roles, activity, test metrics
     */
    getStatistics: async () => {
      try {
        const response = await api.get('/api/users/statistics');
        console.log('📊 User statistics:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Get statistics error:', error);
        throw error;
      }
    },

    /**
     * Get top performing users by test metrics
     * @param {number} limit - Number of top performers to return (max 50)
     * @returns {Promise} Top performers with performance scores
     */
    getTopPerformers: async (limit = 10) => {
      try {
        const response = await api.get('/api/users/top-performers', { 
          params: { limit } 
        });
        console.log('🏆 Top performers:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Get top performers error:', error);
        throw error;
      }
    },

    /**
     * Update user role
     * @param {string} userId - User ID
     * @param {string} role - New role ('admin', 'supervisor', 'technician')
     * @returns {Promise} Updated user data
     */
    updateRole: async (userId, role) => {
      try {
        const response = await api.put(`/api/users/${userId}/role`, { role });
        console.log('✅ Role updated:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Update role error:', error);
        throw error;
      }
    },

    /**
     * Toggle user active/inactive status
     * @param {string} userId - User ID
     * @returns {Promise} Updated user with new status
     */
    toggleStatus: async (userId) => {
      try {
        const response = await api.patch(`/api/users/${userId}/toggle-status`);
        console.log('🔄 Status toggled:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Toggle status error:', error);
        throw error;
      }
    },

    /**
     * Reset user password
     * @param {string} userId - User ID
     * @param {string} newPassword - New password (min 6 chars, must contain letter and number)
     * @returns {Promise} Success message
     */
    resetPassword: async (userId, newPassword) => {
      try {
        const response = await api.post(`/api/users/${userId}/reset-password`, { newPassword });
        console.log('🔑 Password reset:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Reset password error:', error);
        throw error;
      }
    },

    /**
     * Delete user (with safety checks)
     * @param {string} userId - User ID
     * @returns {Promise} Success message
     */
    delete: async (userId) => {
      try {
        const response = await api.delete(`/api/users/${userId}`);
        console.log('🗑️ User deleted:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Delete user error:', error);
        // Re-throw with enhanced error message for users with tests
        if (error.response?.status === 400) {
          throw new Error(error.response.data.message || 'Cannot delete user with associated tests');
        }
        throw error;
      }
    },

    /**
     * Get a single user by ID with statistics
     * @param {string} userId - User ID
     * @returns {Promise} User data with test statistics
     */
    getById: async (userId) => {
      try {
        // Use the getAll endpoint with filtering to get user with stats
        const response = await api.get('/api/users', { 
          params: { limit: 1 } // We'll need to modify this if backend adds getById endpoint
        });
        return response.data;
      } catch (error) {
        console.error('❌ Get user by ID error:', error);
        throw error;
      }
    }
  };

  // Patient endpoints (keeping existing implementation)
  patients = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/patients', { params });
      return response.data;
    },

    getById: async (patientId) => {
      const response = await api.get(`/api/patients/${patientId}`);
      return response.data;
    },

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

  // Test endpoints (keeping existing implementation)
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

  // Upload endpoints (keeping existing implementation)
  upload = {
    createSession: async (sessionData) => {
      const response = await api.post('/api/upload/session', sessionData);
      return response.data;
    },

    getSession: async (sessionId) => {
      // ✅ PROGRESSIVE TIMEOUT: Start with short timeout, increase for longer operations
      const timestamp = Date.now();
      
      // Progressive timeout strategy based on operation type
      let timeout = 10000; // ✅ INCREASED: 10s for quick status checks (was 5s)
      
      // If this is a completion check (likely longer operation), use longer timeout
      if (sessionId.includes('upload_')) {
        timeout = 60000; // ✅ INCREASED: 60s timeout for upload session completion checks (matches YOLO ~30s + buffer)
      }
      
      const response = await api.get(`/api/upload/session/${sessionId}?_t=${timestamp}`, { 
        timeout: timeout,
        // ✅ ADDITIONAL: Add retry logic for completion checks
        retry: timeout > 10000 ? 1 : 0, // Retry once for longer operations
        retryDelay: 2000
      });
      return response;
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
        
        console.log('API response:', response.data);
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
    },

    // Check for existing results and attempt recovery
    checkForExistingResults: async (sessionId) => {
      const response = await api.get(`/api/upload/${sessionId}/check-results`);
      return response.data;
    }
  };

  // Diagnosis endpoints (keeping existing implementation)
  diagnosis = {
    getAll: async (params = {}) => {
      const response = await api.get('/api/diagnosis', { params });
      return response.data;
    },

    getByTestId: async (testId) => {
      const response = await api.get(`/api/diagnosis/${testId}`);
      return response.data;
    },

    runDiagnosis: async (testId, options = {}) => {
      const response = await api.post(`/api/diagnosis/${testId}/run`, options);
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
    },

    // Basic image detection details (no enhanced features)
    getImageDetectionDetails: async (resultId, imageId) => {
      const response = await api.get(`/api/diagnosis/${resultId}/detection/${imageId}`);
      return response.data;
    },

    // Basic performance analytics (no enhanced features)
    getPerformanceAnalytics: async (params = {}) => {
      const response = await api.get('/api/diagnosis/performance/analytics', { params });
      return response.data;
    }
  };

  // Report endpoints (keeping existing implementation)
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

  // Analytics endpoints (keeping existing implementation)
  analytics = {
    getDashboard: async () => {
      try {
        const response = await api.get('/api/analytics/dashboard'); // Fixed endpoint
        console.log('📊 Dashboard analytics response:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Dashboard analytics error:', error);
        throw error;
      }
    },

    getComprehensive: async (params = {}) => {
      try {
        const backendParams = {
          ...params,
          period: params.period || (params.timeRange === '30days' ? 'month' : params.timeRange || 'month')
        };
        
        const response = await api.get('/api/analytics/comprehensive', { params: backendParams }); // Fixed endpoint
        console.log('📈 Comprehensive analytics response:', response.data);
        return response.data;
      } catch (error) {
        console.error('❌ Comprehensive analytics error:', error);
        throw error;
      }
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
    },

    getTAT: async (params = {}) => {
      const response = await api.get('/api/analytics/tat', { params });
      return response.data;
    }
  };

  settings = {
  // Profile endpoints
  getProfile: async () => {
    try {
      const response = await api.get('/api/settings/profile');
      console.log('👤 Profile response:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Get profile error:', error);
      throw error;
    }
  },

  updateProfile: async (profileData) => {
    try {
      const response = await api.put('/api/settings/profile', profileData);
      console.log('✅ Profile updated:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Update profile error:', error);
      throw error;
    }
  },

  changePassword: async (passwordData) => {
    try {
      const response = await api.put('/api/settings/profile/password', passwordData);
      console.log('🔑 Password changed:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Change password error:', error);
      throw error;
    }
  },

  // User settings endpoints
  getUserSettings: async () => {
    try {
      const response = await api.get('/api/settings/user');
      console.log('⚙️ User settings response:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Get user settings error:', error);
      throw error;
    }
  },

  updateUserSettings: async (section, data) => {
    try {
      const response = await api.put('/api/settings/user', { section, data });
      console.log('✅ User settings updated:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Update user settings error:', error);
      throw error;
    }
  },

  resetUserSettings: async (section = null) => {
    try {
      const payload = section ? { section } : {};
      const response = await api.post('/api/settings/user/reset', payload);
      console.log('🔄 User settings reset:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Reset user settings error:', error);
      throw error;
    }
  },

  // Lab settings endpoints (admin/supervisor only)
  getLabSettings: async () => {
    try {
      const response = await api.get('/api/settings/lab');
      console.log('🏥 Lab settings response:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Get lab settings error:', error);
      throw error;
    }
  },

  updateLabSettings: async (section, data, reason = '') => {
    try {
      const response = await api.put('/api/settings/lab', { section, data, reason });
      console.log('✅ Lab settings updated:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Update lab settings error:', error);
      throw error;
    }
  },

  getLabSettingsHistory: async (params = {}) => {
    try {
      const response = await api.get('/api/settings/lab/history', { params });
      console.log('📜 Lab settings history:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Get lab settings history error:', error);
      throw error;
    }
  },

  // System endpoints
  getSystemStatus: async () => {
    try {
      const response = await api.get('/api/settings/system/status');
      console.log('🔍 System status:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Get system status error:', error);
      throw error;
    }
  },

  exportSettings: async (type, format = 'json', userId = null) => {
    try {
      const params = { type, format };
      if (userId) params.userId = userId;
      const response = await api.get('/api/settings/export', { params });
      console.log('📤 Settings exported:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Export settings error:', error);
      throw error;
    }
  }
};
  // Integration endpoints (keeping existing implementation)
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
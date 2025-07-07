// 📁 client/src/services/api.js
// Updated to match your backend API structure exactly

class ApiService {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';
    this.token = localStorage.getItem('authToken');
  }

  // Set authentication token
  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('authToken', token);
    } else {
      localStorage.removeItem('authToken');
    }
  }

  // Get authentication headers
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };
    
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    
    return headers;
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.getAuthHeaders(),
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();
      
      if (!response.ok) {
        // Handle different HTTP status codes
        if (response.status === 401) {
          // Token expired or invalid
          this.setToken(null);
          window.location.href = '/login';
          throw new Error('Authentication required');
        }
        
        throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
      }
      
      return data;
    } catch (error) {
      throw this.handleApiError(error);
    }
  }

  // Handle API errors consistently
  handleApiError(error) {
    if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
      return new Error('Network error - please check your connection');
    }
    
    if (error.message) {
      return new Error(error.message);
    }
    
    return new Error('An unexpected error occurred');
  }

  // Auth endpoints
  auth = {
    login: async (credentials) => {
      const response = await this.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials)
      });
      
      if (response.success && response.data.token) {
        this.setToken(response.data.token);
        // Also store refresh token
        if (response.data.refreshToken) {
          localStorage.setItem('refreshToken', response.data.refreshToken);
        }
      }
      
      return response;
    },

    register: async (userData) => {
      return this.request('/auth/register', {
        method: 'POST',
        body: JSON.stringify(userData)
      });
    },

    logout: async () => {
      try {
        await this.request('/auth/logout', { method: 'POST' });
      } finally {
        // Clear local storage regardless of API response
        this.setToken(null);
        localStorage.removeItem('refreshToken');
      }
    },

    getCurrentUser: async () => {
      return this.request('/auth/me');
    },

    refreshToken: async () => {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await this.request('/auth/refresh-token', {
        method: 'POST',
        body: JSON.stringify({ refreshToken })
      });

      if (response.success && response.data.token) {
        this.setToken(response.data.token);
        if (response.data.refreshToken) {
          localStorage.setItem('refreshToken', response.data.refreshToken);
        }
      }

      return response;
    },

    changePassword: async (passwordData) => {
      return this.request('/auth/change-password', {
        method: 'PUT',
        body: JSON.stringify(passwordData)
      });
    },

    forgotPassword: async (email) => {
      return this.request('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ email })
      });
    },

    resetPassword: async (resetData) => {
      return this.request('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify(resetData)
      });
    },

    verifySession: async () => {
      return this.request('/auth/verify-session');
    }
  };

  // User management endpoints (admin only)
  users = {
    getAll: async (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.request(`/users${queryString ? `?${queryString}` : ''}`);
    },

    search: async (query, params = {}) => {
      const searchParams = new URLSearchParams({ query, ...params }).toString();
      return this.request(`/users/search?${searchParams}`);
    },

    updateRole: async (userId, role) => {
      return this.request(`/users/${userId}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role })
      });
    },

    resetPassword: async (userId, newPassword) => {
      return this.request(`/users/${userId}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ newPassword })
      });
    },

    delete: async (userId) => {
      return this.request(`/users/${userId}`, {
        method: 'DELETE'
      });
    }
  };

  // Patient endpoints (to be implemented when you send patient controller)
  patients = {
    getAll: async (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.request(`/patients${queryString ? `?${queryString}` : ''}`);
    },

    getById: async (patientId) => {
      return this.request(`/patients/${patientId}`);
    },

    getByPatientId: async (patientId) => {
      return this.request(`/patients/patient-id/${patientId}`);
    },

    create: async (patientData) => {
      return this.request('/patients', {
        method: 'POST',
        body: JSON.stringify(patientData)
      });
    },

    update: async (patientId, patientData) => {
      return this.request(`/patients/${patientId}`, {
        method: 'PUT',
        body: JSON.stringify(patientData)
      });
    },

    delete: async (patientId) => {
      return this.request(`/patients/${patientId}`, {
        method: 'DELETE'
      });
    },

    search: async (searchTerm) => {
      return this.request(`/patients/search?q=${encodeURIComponent(searchTerm)}`);
    }
  };

  // Test endpoints (placeholder - to be updated when you send test controller)
  tests = {
    getAll: async (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.request(`/tests${queryString ? `?${queryString}` : ''}`);
    },

    getById: async (testId) => {
      return this.request(`/tests/${testId}`);
    },

    create: async (testData) => {
      return this.request('/tests', {
        method: 'POST',
        body: JSON.stringify(testData)
      });
    },

    update: async (testId, testData) => {
      return this.request(`/tests/${testId}`, {
        method: 'PUT',
        body: JSON.stringify(testData)
      });
    },

    delete: async (testId) => {
      return this.request(`/tests/${testId}`, {
        method: 'DELETE'
      });
    },

    getResults: async (testId) => {
      return this.request(`/tests/${testId}/results`);
    }
  };

  // Dashboard endpoints (placeholder)
  dashboard = {
    getStats: async () => {
      return this.request('/dashboard/stats');
    },

    getAlerts: async () => {
      return this.request('/dashboard/alerts');
    },

    getRecentActivity: async () => {
      return this.request('/dashboard/activity');
    }
  };

  // Upload endpoints (placeholder - to be updated when you send upload controller)
  uploads = {
    createSession: async (sessionData) => {
      return this.request('/uploads/session', {
        method: 'POST',
        body: JSON.stringify(sessionData)
      });
    },

    uploadFiles: async (sessionId, files, onProgress) => {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      // For file uploads, we don't set Content-Type to let browser set it with boundary
      const headers = {};
      if (this.token) {
        headers.Authorization = `Bearer ${this.token}`;
      }

      const response = await fetch(`${this.baseURL}/uploads/session/${sessionId}/files`, {
        method: 'POST',
        headers,
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Upload failed');
      }

      return response.json();
    },

    processFiles: async (sessionId) => {
      return this.request(`/uploads/session/${sessionId}/process`, {
        method: 'POST'
      });
    },

    cancelSession: async (sessionId, reason) => {
      return this.request(`/uploads/session/${sessionId}/cancel`, {
        method: 'POST',
        body: JSON.stringify({ reason })
      });
    },

    getSessionStatus: async (sessionId) => {
      return this.request(`/uploads/session/${sessionId}/status`);
    }
  };

  // Diagnosis endpoints (placeholder)
  diagnosis = {
    getByTestId: async (testId) => {
      return this.request(`/diagnosis/test/${testId}`);
    },

    updateDiagnosis: async (diagnosisId, diagnosisData) => {
      return this.request(`/diagnosis/${diagnosisId}`, {
        method: 'PUT',
        body: JSON.stringify(diagnosisData)
      });
    }
  };

  // Reports endpoints (placeholder)
  reports = {
    generate: async (reportData) => {
      return this.request('/reports/generate', {
        method: 'POST',
        body: JSON.stringify(reportData)
      });
    },

    export: async (reportId, format = 'pdf') => {
      return this.request(`/reports/${reportId}/export?format=${format}`);
    }
  };

  // Audit endpoints (for admin users)
  audit = {
    getLogs: async (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.request(`/audit/logs${queryString ? `?${queryString}` : ''}`);
    },

    getStatistics: async (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.request(`/audit/statistics${queryString ? `?${queryString}` : ''}`);
    },

    searchLogs: async (query, params = {}) => {
      const searchParams = new URLSearchParams({ query, ...params }).toString();
      return this.request(`/audit/search?${searchParams}`);
    }
  };

  // Utility methods
  isAuthenticated() {
    return !!this.token;
  }

  getCurrentToken() {
    return this.token;
  }

  // Auto-retry mechanism for expired tokens
  async requestWithRetry(endpoint, options = {}, maxRetries = 1) {
    let retryCount = 0;
    
    while (retryCount <= maxRetries) {
      try {
        return await this.request(endpoint, options);
      } catch (error) {
        if (error.message.includes('Authentication required') && retryCount < maxRetries) {
          // Try to refresh token
          try {
            await this.auth.refreshToken();
            retryCount++;
            continue;
          } catch (refreshError) {
            // Refresh failed, redirect to login
            window.location.href = '/login';
            throw error;
          }
        }
        throw error;
      }
    }
  }
}

export default new ApiService();
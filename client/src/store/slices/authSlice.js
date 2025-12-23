// 📁 client/src/store/slices/authSlice.js
// Updated to match your backend authentication system

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunks for authentication
export const login = createAsyncThunk(
  'auth/login',
  async (credentials, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.login(credentials);
      return response.data; // Contains user, token, refreshToken, expiresIn
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const register = createAsyncThunk(
  'auth/register',
  async (userData, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.register(userData);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const logout = createAsyncThunk(
  'auth/logout',
  async (_, { rejectWithValue }) => {
    try {
      await apiService.auth.logout();
      return null;
    } catch (error) {
      // Even if logout fails on server, clear local state
      return null;
    }
  }
);

export const getCurrentUser = createAsyncThunk(
  'auth/getCurrentUser',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.getCurrentUser();
      return response.data.user;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const refreshToken = createAsyncThunk(
  'auth/refreshToken',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.refreshToken();
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const changePassword = createAsyncThunk(
  'auth/changePassword',
  async (passwordData, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.changePassword(passwordData);
      return response.message;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const forgotPassword = createAsyncThunk(
  'auth/forgotPassword',
  async (email, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.forgotPassword(email);
      return response.message;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const resetPassword = createAsyncThunk(
  'auth/resetPassword',
  async (resetData, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.resetPassword(resetData);
      return response.message;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);
// Add this with your other async thunks
export const verifySession = createAsyncThunk(
  'auth/verifySession',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.auth.verifySession();
      
      // If your backend returns { valid: true } or similar
      if (!response.data.valid) {
        throw new Error('Session invalid');
      }
      
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.message || error.message);
    }
  }
);

// Helper function to get login attempts with time-based reset
const getLoginAttempts = () => {
  const stored = localStorage.getItem('loginAttempts');
  const lockoutTime = localStorage.getItem('lockoutTime');
  
  if (!stored || !lockoutTime) {
    return 0;
  }
  
  const now = Date.now();
  const lockoutTimestamp = parseInt(lockoutTime);
  const fifteenMinutes = 15 * 60 * 1000; // 15 minutes in milliseconds
  
  // If 15 minutes have passed since lockout, reset attempts
  if (now - lockoutTimestamp > fifteenMinutes) {
    localStorage.removeItem('loginAttempts');
    localStorage.removeItem('lockoutTime');
    return 0;
  }
  
  return parseInt(stored);
};

// Helper function to set login attempts with timestamp
const setLoginAttempts = (attempts) => {
  if (attempts === 0) {
    localStorage.removeItem('loginAttempts');
    localStorage.removeItem('lockoutTime');
  } else {
    localStorage.setItem('loginAttempts', attempts.toString());
    if (attempts >= 5) {
      localStorage.setItem('lockoutTime', Date.now().toString());
    }
  }
};

// Initial state
const initialState = {
  user: null,
  token: localStorage.getItem('authToken'),
  refreshToken: localStorage.getItem('refreshToken'),
  isAuthenticated: !!localStorage.getItem('authToken'),
  isLoading: false,
  error: null,
  loginAttempts: getLoginAttempts(),
  lastLoginTime: null,
  sessionExpiry: null,
  passwordChangeSuccess: false,
  forgotPasswordSuccess: false,
  resetPasswordSuccess: false
};

// Auth slice
const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    
    clearMessages: (state) => {
      state.passwordChangeSuccess = false;
      state.forgotPasswordSuccess = false;
      state.resetPasswordSuccess = false;
    },
    
    resetLoginAttempts: (state) => {
      state.loginAttempts = 0;
      setLoginAttempts(0);
    },
    
    setUser: (state, action) => {
      state.user = action.payload;
    },
    
    updateUserProfile: (state, action) => {
      if (state.user) {
        state.user = { ...state.user, ...action.payload };
      }
    },
    
    setSessionExpiry: (state, action) => {
      state.sessionExpiry = action.payload;
    },
    
    // For manual logout without API call
    clearAuth: (state) => {
      state.user = null;
      state.token = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      state.sessionExpiry = null;
      localStorage.removeItem('authToken');
      localStorage.removeItem('refreshToken');
    }
  },
  
  extraReducers: (builder) => {
    builder
      // Login
      .addCase(login.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(login.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = action.payload.user;
        state.token = action.payload.token;
        state.refreshToken = action.payload.refreshToken;
        state.isAuthenticated = true;
        state.error = null;
        state.loginAttempts = 0;
        setLoginAttempts(0);
        state.lastLoginTime = new Date().toISOString();
        
        // Calculate session expiry based on expiresIn
        if (action.payload.expiresIn) {
          const expiryTime = new Date();
          // Parse expiry time (e.g., "1h", "30m", "3600s")
          const match = action.payload.expiresIn.match(/^(\d+)([hms])$/);
          if (match) {
            const [, amount, unit] = match;
            const multipliers = { h: 3600000, m: 60000, s: 1000 };
            expiryTime.setTime(expiryTime.getTime() + (parseInt(amount) * multipliers[unit]));
            state.sessionExpiry = expiryTime.toISOString();
          }
        }
      })
      .addCase(login.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        state.loginAttempts += 1;
        setLoginAttempts(state.loginAttempts);
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.isAuthenticated = false;
      })
      
      // Register
      .addCase(register.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(register.fulfilled, (state, action) => {
        state.isLoading = false;
        state.error = null;
        // Don't auto-login after registration
      })
      .addCase(register.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Logout
      .addCase(logout.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(logout.fulfilled, (state) => {
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.isAuthenticated = false;
        state.isLoading = false;
        state.error = null;
        state.sessionExpiry = null;
      })
      .addCase(logout.rejected, (state) => {
        // Clear state even if logout fails
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.isAuthenticated = false;
        state.isLoading = false;
        state.sessionExpiry = null;
      })
      
      // Get current user
      .addCase(getCurrentUser.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(getCurrentUser.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = action.payload;
        state.isAuthenticated = true;
        state.error = null;
      })
      .addCase(getCurrentUser.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        // If getting current user fails, user might not be authenticated
        if (action.payload?.includes('Authentication')) {
          state.user = null;
          state.token = null;
          state.refreshToken = null;
          state.isAuthenticated = false;
        }
      })
      
      // Refresh token
      .addCase(refreshToken.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(refreshToken.fulfilled, (state, action) => {
        state.isLoading = false;
        state.token = action.payload.token;
        state.refreshToken = action.payload.refreshToken;
        state.error = null;
        
        // Update session expiry
        if (action.payload.expiresIn) {
          const expiryTime = new Date();
          const match = action.payload.expiresIn.match(/^(\d+)([hms])$/);
          if (match) {
            const [, amount, unit] = match;
            const multipliers = { h: 3600000, m: 60000, s: 1000 };
            expiryTime.setTime(expiryTime.getTime() + (parseInt(amount) * multipliers[unit]));
            state.sessionExpiry = expiryTime.toISOString();
          }
        }
      })
      .addCase(refreshToken.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        // If refresh fails, clear authentication
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.isAuthenticated = false;
        state.sessionExpiry = null;
      })
      
      // Change password
      .addCase(changePassword.pending, (state) => {
        state.isLoading = true;
        state.error = null;
        state.passwordChangeSuccess = false;
      })
      .addCase(changePassword.fulfilled, (state) => {
        state.isLoading = false;
        state.passwordChangeSuccess = true;
        state.error = null;
      })
      .addCase(changePassword.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        state.passwordChangeSuccess = false;
      })
      
      // Forgot password
      .addCase(forgotPassword.pending, (state) => {
        state.isLoading = true;
        state.error = null;
        state.forgotPasswordSuccess = false;
      })
      .addCase(forgotPassword.fulfilled, (state) => {
        state.isLoading = false;
        state.forgotPasswordSuccess = true;
        state.error = null;
      })
      .addCase(forgotPassword.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        state.forgotPasswordSuccess = false;
      })
      
      // Reset password
      .addCase(resetPassword.pending, (state) => {
        state.isLoading = true;
        state.error = null;
        state.resetPasswordSuccess = false;
      })
      .addCase(resetPassword.fulfilled, (state) => {
        state.isLoading = false;
        state.resetPasswordSuccess = true;
        state.error = null;
      })
      .addCase(resetPassword.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        state.resetPasswordSuccess = false;
      });
  }
});

// Action creators
export const { 
  clearError, 
  clearMessages, 
  resetLoginAttempts, 
  setUser, 
  updateUserProfile, 
  setSessionExpiry,
  clearAuth
} = authSlice.actions;

// Selectors
export const selectUser = (state) => state.auth.user;
export const selectToken = (state) => state.auth.token;
export const selectIsAuthenticated = (state) => state.auth.isAuthenticated;
export const selectIsLoading = (state) => state.auth.isLoading;
export const selectAuthError = (state) => state.auth.error;
export const selectUserRole = (state) => state.auth.user?.role;
export const selectUserPermissions = (state) => state.auth.user?.permissions;
export const selectLoginAttempts = (state) => state.auth.loginAttempts;
export const selectSessionExpiry = (state) => state.auth.sessionExpiry;
export const selectPasswordChangeSuccess = (state) => state.auth.passwordChangeSuccess;
export const selectForgotPasswordSuccess = (state) => state.auth.forgotPasswordSuccess;
export const selectResetPasswordSuccess = (state) => state.auth.resetPasswordSuccess;

// Permission-based selectors matching your backend structure
export const selectHasPermission = (permission) => (state) => {
  const permissions = state.auth.user?.permissions;
  if (!permissions) return false;
  
  // Map permission names to backend structure
  const permissionMap = {
    'CAN_UPLOAD_SAMPLES': 'canUploadSamples',
    'CAN_VIEW_ALL_TESTS': 'canViewAllTests',
    'CAN_DELETE_TESTS': 'canDeleteTests',
    'CAN_MANAGE_USERS': 'canManageUsers',
    'CAN_EXPORT_REPORTS': 'canExportReports'
  };
  
  const backendPermission = permissionMap[permission] || permission;
  return permissions[backendPermission] === true;
};

// Role-based selectors
export const selectIsAdmin = (state) => state.auth.user?.role === 'admin';
export const selectIsSupervisor = (state) => {
  const role = state.auth.user?.role;
  return role === 'supervisor' || role === 'admin';
};
export const selectIsTechnician = (state) => state.auth.user?.role === 'technician';

// Combined permission and role selectors
export const selectCanUploadSamples = (state) => {
  return selectHasPermission('canUploadSamples')(state);
};

export const selectCanViewAllTests = (state) => {
  return selectHasPermission('canViewAllTests')(state) || selectIsSupervisor(state);
};

export const selectCanDeleteTests = (state) => {
  return selectHasPermission('canDeleteTests')(state) || selectIsAdmin(state);
};

export const selectCanManageUsers = (state) => {
  return selectHasPermission('canManageUsers')(state) || selectIsAdmin(state);
};

export const selectCanExportReports = (state) => {
  return selectHasPermission('canExportReports')(state);
};

// Session management selectors
export const selectIsSessionExpired = (state) => {
  const expiry = state.auth.sessionExpiry;
  if (!expiry) return false;
  return new Date() > new Date(expiry);
};

export const selectSessionTimeRemaining = (state) => {
  const expiry = state.auth.sessionExpiry;
  if (!expiry) return null;
  
  const remaining = new Date(expiry) - new Date();
  return remaining > 0 ? remaining : 0;
};

export default authSlice.reducer;
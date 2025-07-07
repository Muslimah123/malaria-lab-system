// 📁 client/src/store/slices/dashboardSlice.js
// Dashboard data management slice

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunks
export const fetchDashboardStats = createAsyncThunk(
  'dashboard/fetchStats',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.dashboard.getStats();
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchDashboardAlerts = createAsyncThunk(
  'dashboard/fetchAlerts',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.dashboard.getAlerts();
      return response.data.alerts || [];
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchRecentActivity = createAsyncThunk(
  'dashboard/fetchRecentActivity',
  async (_, { rejectWithValue }) => {
    try {
      const response = await apiService.dashboard.getRecentActivity();
      return response.data.activities || [];
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Initial state
const initialState = {
  stats: {
    totalTests: 0,
    todayTests: 0,
    positiveTests: 0,
    negativeTests: 0,
    processingTests: 0,
    totalPatients: 0,
    averageProcessingTime: 0,
    positivityRate: 0
  },
  alerts: [],
  recentActivity: [],
  isLoading: false,
  error: null,
  lastUpdated: null
};

// Dashboard slice
const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    dismissAlert: (state, action) => {
      const alertId = action.payload;
      state.alerts = state.alerts.filter(alert => alert.id !== alertId);
    },
    addAlert: (state, action) => {
      state.alerts.unshift(action.payload);
      // Keep only the most recent 10 alerts
      if (state.alerts.length > 10) {
        state.alerts = state.alerts.slice(0, 10);
      }
    },
    updateStats: (state, action) => {
      state.stats = { ...state.stats, ...action.payload };
      state.lastUpdated = new Date().toISOString();
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch dashboard stats
      .addCase(fetchDashboardStats.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchDashboardStats.fulfilled, (state, action) => {
        state.isLoading = false;
        state.stats = { ...state.stats, ...action.payload };
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchDashboardStats.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Fetch alerts
      .addCase(fetchDashboardAlerts.fulfilled, (state, action) => {
        state.alerts = action.payload;
      })
      
      // Fetch recent activity
      .addCase(fetchRecentActivity.fulfilled, (state, action) => {
        state.recentActivity = action.payload;
      });
  }
});

export const { clearError: clearDashboardError, dismissAlert, addAlert, updateStats } = dashboardSlice.actions;

// Selectors
export const selectDashboardStats = (state) => state.dashboard.stats;
export const selectDashboardAlerts = (state) => state.dashboard.alerts;
export const selectRecentActivity = (state) => state.dashboard.recentActivity;
export const selectDashboardLoading = (state) => state.dashboard.isLoading;
export const selectDashboardError = (state) => state.dashboard.error;
export const selectLastUpdated = (state) => state.dashboard.lastUpdated;

export default dashboardSlice.reducer;
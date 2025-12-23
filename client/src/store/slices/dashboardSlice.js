
// src/store/slices/dashboardSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunk for fetching dashboard data
export const fetchDashboardData = createAsyncThunk(
  'dashboard/fetchDashboardData',
  async (params = {}, { rejectWithValue }) => {
    try {
      console.log('🔄 Fetching dashboard data...');
      const response = await apiService.analytics.getDashboard();
      console.log('📊 Dashboard response:', response);
      
      if (response.success) {
        console.log('✅ Dashboard data fetched successfully:', response.data);
        return response.data;
      } else {
        console.error('❌ Dashboard fetch failed:', response.message);
        return rejectWithValue(response.message || 'Failed to fetch dashboard data');
      }
    } catch (error) {
      console.error('❌ Dashboard fetch error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Async thunk for fetching analytics data
export const fetchAnalyticsData = createAsyncThunk(
  'dashboard/fetchAnalyticsData',
  async ({ timeRange = '30days', metric = 'all' } = {}, { rejectWithValue }) => {
    try {
      const [trendsResponse, distributionResponse, performanceResponse] = await Promise.all([
        apiService.analytics.getTestTrends({ period: timeRange }),
        apiService.analytics.getParasiteTypes({ period: timeRange }),
        apiService.analytics.getTechnicianPerformance({ period: timeRange })
      ]);

      return {
        trends: trendsResponse.data || [],
        distribution: distributionResponse.data || [],
        performance: performanceResponse.data || []
      };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Async thunk for refreshing specific dashboard section
export const refreshDashboardSection = createAsyncThunk(
  'dashboard/refreshDashboardSection',
  async (section, { getState, rejectWithValue }) => {
    try {
      const state = getState();
      let response;

      switch (section) {
        case 'stats':
          response = await apiService.analytics.getDashboard();
          return { section, data: response.data };
        
        case 'tests':
          response = await apiService.tests.getAll({ 
            limit: 10, 
            sort: '-createdAt' 
          });
          return { section, data: response.data };
        
        case 'alerts':
          // In real implementation, fetch from alerts endpoint
          return { section, data: [] };
        
        default:
          return rejectWithValue('Invalid section');
      }
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

const initialState = {
  // Dashboard overview data
  data: null,
  
  // Analytics data
  analytics: {
    trends: [],
    distribution: [],
    performance: []
  },
  
  // Loading states
  loading: false,
  analyticsLoading: false,
  refreshing: false,
  
  // Error states
  error: null,
  analyticsError: null,
  
  // UI state
  lastUpdated: null,
  autoRefresh: true,
  refreshInterval: 5 * 60 * 1000, // 5 minutes
  
  // Chart preferences
  chartPreferences: {
    defaultTimeRange: '30days',
    defaultChartType: 'line',
    selectedMetrics: ['tests', 'positive']
  }
};

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    // Clear errors
    clearDashboardError: (state) => {
      state.error = null;
    },
    
    clearAnalyticsError: (state) => {
      state.analyticsError = null;
    },
    
    // Update real-time data
    updateRealtimeData: (state, action) => {
      const { type, data } = action.payload;
      
      switch (type) {
        case 'test_completed':
          // Update test counts
          if (state.data) {
            state.data.todayTests = (state.data.todayTests || 0) + 1;
            
            if (data.result === 'positive') {
              state.data.positiveToday = (state.data.positiveToday || 0) + 1;
            }
            
            // Update recent tests list
            if (state.data.recentTests) {
              state.data.recentTests.unshift({
                id: data.testId,
                patientName: data.patientName,
                patientId: data.patientId,
                status: 'completed',
                result: data.result,
                severity: data.severity,
                parasiteType: data.parasiteType,
                timeAgo: 'Just now',
                technician: data.technician
              });
              
              // Keep only last 10 tests
              state.data.recentTests = state.data.recentTests.slice(0, 10);
            }
          }
          break;
          
        case 'urgent_alert':
          // Add urgent alert
          if (state.data) {
            if (!state.data.urgentAlerts) {
              state.data.urgentAlerts = [];
            }
            
            state.data.urgentAlerts.unshift({
              id: Date.now(),
              type: data.type,
              message: data.message,
              severity: data.severity,
              patientName: data.patientName,
              timeAgo: 'Just now'
            });
            
            // Keep only last 5 alerts
            state.data.urgentAlerts = state.data.urgentAlerts.slice(0, 5);
          }
          break;
          
        default:
          break;
      }
      
      state.lastUpdated = new Date().toISOString();
    },
    
    // Dismiss alert
    dismissAlert: (state, action) => {
      const alertId = action.payload;
      if (state.data?.urgentAlerts) {
        state.data.urgentAlerts = state.data.urgentAlerts.filter(
          alert => alert.id !== alertId
        );
      }
    },
    
    // Update chart preferences
    updateChartPreferences: (state, action) => {
      state.chartPreferences = {
        ...state.chartPreferences,
        ...action.payload
      };
    },
    
    // Toggle auto refresh
    toggleAutoRefresh: (state) => {
      state.autoRefresh = !state.autoRefresh;
    },
    
    // Set refresh interval
    setRefreshInterval: (state, action) => {
      state.refreshInterval = action.payload;
    },
    
    // Reset dashboard state
    resetDashboard: (state) => {
      Object.assign(state, initialState);
    }
  },
  
  extraReducers: (builder) => {
    builder
      // Fetch Dashboard Data
      .addCase(fetchDashboardData.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchDashboardData.fulfilled, (state, action) => {
        state.loading = false;
        state.data = action.payload;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchDashboardData.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Fetch Analytics Data
      .addCase(fetchAnalyticsData.pending, (state) => {
        state.analyticsLoading = true;
        state.analyticsError = null;
      })
      .addCase(fetchAnalyticsData.fulfilled, (state, action) => {
        state.analyticsLoading = false;
        state.analytics = action.payload;
      })
      .addCase(fetchAnalyticsData.rejected, (state, action) => {
        state.analyticsLoading = false;
        state.analyticsError = action.payload;
      })
      
      // Refresh Dashboard Section
      .addCase(refreshDashboardSection.pending, (state) => {
        state.refreshing = true;
      })
      .addCase(refreshDashboardSection.fulfilled, (state, action) => {
        state.refreshing = false;
        const { section, data } = action.payload;
        
        switch (section) {
          case 'stats':
            state.data = { ...state.data, ...data };
            break;
          case 'tests':
            if (state.data) {
              state.data.recentTests = data;
            }
            break;
          case 'alerts':
            if (state.data) {
              state.data.urgentAlerts = data;
            }
            break;
        }
        
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(refreshDashboardSection.rejected, (state, action) => {
        state.refreshing = false;
        state.error = action.payload;
      });
  }
});

// Export actions
export const {
  clearDashboardError,
  clearAnalyticsError,
  updateRealtimeData,
  dismissAlert,
  updateChartPreferences,
  toggleAutoRefresh,
  setRefreshInterval,
  resetDashboard
} = dashboardSlice.actions;

// Selectors
export const selectDashboardData = (state) => state.dashboard.data;
export const selectDashboardLoading = (state) => state.dashboard.loading;
export const selectDashboardError = (state) => state.dashboard.error;
export const selectDashboardLastUpdated = (state) => state.dashboard.lastUpdated;

export const selectAnalyticsData = (state) => state.dashboard.analytics;
export const selectAnalyticsLoading = (state) => state.dashboard.analyticsLoading;
export const selectAnalyticsError = (state) => state.dashboard.analyticsError;

export const selectDashboardStats = (state) => {
  const data = state.dashboard.data;
  if (!data) return [];
  
  return [
    {
      title: "Today's Tests",
      value: data.todayTests || 0,
      change: data.todayChange || "+0%",
      trend: "up",
      color: "bg-blue-500"
    },
    {
      title: "Positive Results", 
      value: data.positiveToday || 0,
      change: data.positiveChange || "+0%",
      trend: data.positiveChange?.includes('-') ? "down" : "up",
      color: "bg-red-500"
    },
    {
      title: "Pending Review",
      value: data.pendingReview || 0,
      change: data.pendingChange || "+0%", 
      trend: "up",
      color: "bg-yellow-500"
    },
    {
      title: "Active Patients",
      value: data.activePatients || 0,
      change: data.patientsChange || "+0%",
      trend: "up", 
      color: "bg-green-500"
    }
  ];
};

export const selectRecentTests = (state) => state.dashboard.data?.recentTests || [];
export const selectUrgentAlerts = (state) => state.dashboard.data?.urgentAlerts || [];
export const selectSystemStatus = (state) => state.dashboard.data?.systemStatus || {};

export const selectChartPreferences = (state) => state.dashboard.chartPreferences;
export const selectAutoRefresh = (state) => state.dashboard.autoRefresh;
export const selectRefreshInterval = (state) => state.dashboard.refreshInterval;

// Export reducer
export default dashboardSlice.reducer;
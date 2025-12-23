import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

// Async thunks
export const fetchDiagnosisAnalytics = createAsyncThunk(
  'analytics/fetchDiagnosisAnalytics',
  async ({ startDate, endDate, filters = {} }, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/analytics/diagnosis', {
        params: { startDate, endDate, ...filters }
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data || 'Failed to fetch diagnosis analytics');
    }
  }
);

export const fetchUploadAnalytics = createAsyncThunk(
  'analytics/fetchUploadAnalytics',
  async ({ startDate, endDate }, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/upload/statistics', {
        params: { startDate, endDate }
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data || 'Failed to fetch upload analytics');
    }
  }
);

export const fetchPerformanceMetrics = createAsyncThunk(
  'analytics/fetchPerformanceMetrics',
  async ({ startDate, endDate }, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/analytics/performance', {
        params: { startDate, endDate }
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data || 'Failed to fetch performance metrics');
    }
  }
);

const initialState = {
  diagnosisAnalytics: {
    data: null,
    loading: false,
    error: null
  },
  uploadAnalytics: {
    data: null,
    loading: false,
    error: null
  },
  performanceMetrics: {
    data: null,
    loading: false,
    error: null
  },
  filters: {
    startDate: null,
    endDate: null,
    parasiteType: null,
    severity: null,
    technician: null
  },
  dateRange: {
    startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    endDate: new Date().toISOString().split('T')[0]
  }
};

const analyticsSlice = createSlice({
  name: 'analytics',
  initialState,
  reducers: {
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    setDateRange: (state, action) => {
      state.dateRange = { ...state.dateRange, ...action.payload };
    },
    clearFilters: (state) => {
      state.filters = initialState.filters;
    },
    clearAnalytics: (state) => {
      state.diagnosisAnalytics = initialState.diagnosisAnalytics;
      state.uploadAnalytics = initialState.uploadAnalytics;
      state.performanceMetrics = initialState.performanceMetrics;
    }
  },
  extraReducers: (builder) => {
    // Diagnosis Analytics
    builder
      .addCase(fetchDiagnosisAnalytics.pending, (state) => {
        state.diagnosisAnalytics.loading = true;
        state.diagnosisAnalytics.error = null;
      })
      .addCase(fetchDiagnosisAnalytics.fulfilled, (state, action) => {
        state.diagnosisAnalytics.loading = false;
        state.diagnosisAnalytics.data = action.payload;
      })
      .addCase(fetchDiagnosisAnalytics.rejected, (state, action) => {
        state.diagnosisAnalytics.loading = false;
        state.diagnosisAnalytics.error = action.payload;
      });

    // Upload Analytics
    builder
      .addCase(fetchUploadAnalytics.pending, (state) => {
        state.uploadAnalytics.loading = true;
        state.uploadAnalytics.error = null;
      })
      .addCase(fetchUploadAnalytics.fulfilled, (state, action) => {
        state.uploadAnalytics.loading = false;
        state.uploadAnalytics.data = action.payload;
      })
      .addCase(fetchUploadAnalytics.rejected, (state, action) => {
        state.uploadAnalytics.loading = false;
        state.uploadAnalytics.error = action.payload;
      });

    // Performance Metrics
    builder
      .addCase(fetchPerformanceMetrics.pending, (state) => {
        state.performanceMetrics.loading = true;
        state.performanceMetrics.error = null;
      })
      .addCase(fetchPerformanceMetrics.fulfilled, (state, action) => {
        state.performanceMetrics.loading = false;
        state.performanceMetrics.data = action.payload;
      })
      .addCase(fetchPerformanceMetrics.rejected, (state, action) => {
        state.performanceMetrics.loading = false;
        state.performanceMetrics.error = action.payload;
      });
  }
});

export const { setFilters, setDateRange, clearFilters, clearAnalytics } = analyticsSlice.actions;

// Selectors
export const selectDiagnosisAnalytics = (state) => state.analytics.diagnosisAnalytics;
export const selectUploadAnalytics = (state) => state.analytics.uploadAnalytics;
export const selectPerformanceMetrics = (state) => state.analytics.performanceMetrics;
export const selectFilters = (state) => state.analytics.filters;
export const selectDateRange = (state) => state.analytics.dateRange;
export const selectAnalyticsLoading = (state) => 
  state.analytics.diagnosisAnalytics.loading || 
  state.analytics.uploadAnalytics.loading || 
  state.analytics.performanceMetrics.loading;

export default analyticsSlice.reducer;

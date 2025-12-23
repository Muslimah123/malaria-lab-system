// 📁 client/src/store/slices/auditSlice.js
// Audit logs management slice

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunks
export const fetchAuditLogs = createAsyncThunk(
  'audit/fetchLogs',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await apiService.audit.getLogs(params);
      return response;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchAuditStatistics = createAsyncThunk(
  'audit/fetchStatistics',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await apiService.audit.getStatistics(params);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const searchAuditLogs = createAsyncThunk(
  'audit/searchLogs',
  async ({ query, params = {} }, { rejectWithValue }) => {
    try {
      const response = await apiService.audit.searchLogs(query, params);
      return response;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Initial state
const initialState = {
  logs: [],
  statistics: null,
  searchResults: [],
  isLoading: false,
  isSearching: false,
  error: null,
  searchError: null,
  pagination: {
    page: 1,
    limit: 50,
    total: 0,
    pages: 0
  }
};

// Audit slice
const auditSlice = createSlice({
  name: 'audit',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
      state.searchError = null;
    },
    clearSearchResults: (state) => {
      state.searchResults = [];
      state.searchError = null;
    },
    clearLogs: (state) => {
      state.logs = [];
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch audit logs
      .addCase(fetchAuditLogs.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchAuditLogs.fulfilled, (state, action) => {
        state.isLoading = false;
        state.logs = action.payload.logs || action.payload.data || [];
        state.pagination = action.payload.pagination || initialState.pagination;
      })
      .addCase(fetchAuditLogs.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Fetch audit statistics
      .addCase(fetchAuditStatistics.fulfilled, (state, action) => {
        state.statistics = action.payload;
      })
      
      // Search audit logs
      .addCase(searchAuditLogs.pending, (state) => {
        state.isSearching = true;
        state.searchError = null;
      })
      .addCase(searchAuditLogs.fulfilled, (state, action) => {
        state.isSearching = false;
        state.searchResults = action.payload.logs || action.payload.data || [];
      })
      .addCase(searchAuditLogs.rejected, (state, action) => {
        state.isSearching = false;
        state.searchError = action.payload;
      });
  }
});

export const { clearError, clearSearchResults, clearLogs } = auditSlice.actions;

// Selectors
export const selectAuditLogs = (state) => state.audit.logs;
export const selectAuditStatistics = (state) => state.audit.statistics;
export const selectAuditSearchResults = (state) => state.audit.searchResults;
export const selectAuditLoading = (state) => state.audit.isLoading;
export const selectAuditError = (state) => state.audit.error;
export const selectAuditPagination = (state) => state.audit.pagination;

export default auditSlice.reducer;
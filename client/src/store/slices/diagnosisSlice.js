// 📁 client/src/store/slices/diagnosisSlice.js
// Basic Diagnosis Management Slice

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import diagnosisService from '../../services/diagnosisService';

// Async thunks for basic features
export const fetchDiagnosisResult = createAsyncThunk(
  'diagnosis/fetchDiagnosisResult',
  async (testId, { rejectWithValue }) => {
    try {
      const response = await diagnosisService.getByTestId(testId);
      return response.data || response;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to fetch diagnosis result');
    }
  }
);

// Basic diagnosis without enhanced options
export const runDiagnosis = createAsyncThunk(
  'diagnosis/runDiagnosis',
  async (testId, { rejectWithValue }) => {
    try {
      const response = await diagnosisService.runDiagnosis(testId);
      return response.data || response;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to run diagnosis');
    }
  }
);

// Get all diagnosis results with basic filtering
export const getAllDiagnosisResults = createAsyncThunk(
  'diagnosis/getAllDiagnosisResults',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await diagnosisService.getAll(params);
      return response.data || response;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to fetch diagnosis results');
    }
  }
);

// Get basic diagnosis statistics
export const getDiagnosisStatistics = createAsyncThunk(
  'diagnosis/getDiagnosisStatistics',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await diagnosisService.getStatistics(params);
      return response.data || response;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to fetch diagnosis statistics');
    }
  }
);

export const addManualReview = createAsyncThunk(
  'diagnosis/addManualReview',
  async ({ testId, reviewData }, { rejectWithValue }) => {
    try {
      const response = await diagnosisService.addManualReview(testId, reviewData);
      return response.data || response;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to add manual review');
    }
  }
);

// Initial state
const initialState = {
  currentResult: null,
  isLoading: false,
  error: null,
  statistics: null,
  allResults: [],
};

// Diagnosis slice
const diagnosisSlice = createSlice({
  name: 'diagnosis',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearCurrentResult: (state) => {
      state.currentResult = null;
    },
    setCurrentResult: (state, action) => {
      state.currentResult = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch diagnosis result
      .addCase(fetchDiagnosisResult.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchDiagnosisResult.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentResult = action.payload;
        state.error = null;
      })
      .addCase(fetchDiagnosisResult.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Run diagnosis
      .addCase(runDiagnosis.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(runDiagnosis.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentResult = action.payload;
        state.error = null;
      })
      .addCase(runDiagnosis.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Add manual review
      .addCase(addManualReview.fulfilled, (state, action) => {
        if (state.currentResult?.testId === action.payload.testId) {
          state.currentResult = { ...state.currentResult, ...action.payload };
        }
      })
      
      // ✅ NEW: Get all diagnosis results
      .addCase(getAllDiagnosisResults.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(getAllDiagnosisResults.fulfilled, (state, action) => {
        state.isLoading = false;
        state.allResults = action.payload;
        state.error = null;
      })
      .addCase(getAllDiagnosisResults.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // ✅ NEW: Get diagnosis statistics
      .addCase(getDiagnosisStatistics.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(getDiagnosisStatistics.fulfilled, (state, action) => {
        state.isLoading = false;
        state.statistics = action.payload;
        state.error = null;
      })
      .addCase(getDiagnosisStatistics.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });
  }
});

export const {
  clearError,
  clearCurrentResult,
  setCurrentResult,
} = diagnosisSlice.actions;

export default diagnosisSlice.reducer;

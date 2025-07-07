// 📁 client/src/store/slices/testsSlice.js
// Test management slice

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunks
export const fetchTests = createAsyncThunk(
  'tests/fetchTests',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.getAll(params);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchTestById = createAsyncThunk(
  'tests/fetchTestById',
  async (testId, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.getById(testId);
      return response.data.test;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const createTest = createAsyncThunk(
  'tests/createTest',
  async (testData, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.create(testData);
      return response.data.test;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Initial state
const initialState = {
  tests: [],
  currentTest: null,
  isLoading: false,
  error: null,
  pagination: {
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  }
};

// Tests slice
const testsSlice = createSlice({
  name: 'tests',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearCurrentTest: (state) => {
      state.currentTest = null;
    },
    setCurrentTest: (state, action) => {
      state.currentTest = action.payload;
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch tests
      .addCase(fetchTests.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchTests.fulfilled, (state, action) => {
        state.isLoading = false;
        state.tests = action.payload.tests || action.payload;
        state.pagination = action.payload.pagination || initialState.pagination;
      })
      .addCase(fetchTests.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Fetch test by ID
      .addCase(fetchTestById.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchTestById.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentTest = action.payload;
      })
      .addCase(fetchTestById.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Create test
      .addCase(createTest.fulfilled, (state, action) => {
        state.currentTest = action.payload;
        state.tests.unshift(action.payload);
      });
  }
});

export const { clearError: clearTestsError, clearCurrentTest, setCurrentTest } = testsSlice.actions;

// Selectors
export const selectTests = (state) => state.tests.tests;
export const selectCurrentTest = (state) => state.tests.currentTest;
export const selectTestsLoading = (state) => state.tests.isLoading;
export const selectTestsError = (state) => state.tests.error;
export const selectTestsPagination = (state) => state.tests.pagination;

export default testsSlice.reducer;
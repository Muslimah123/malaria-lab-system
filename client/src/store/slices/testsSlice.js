// 📁 client/src/store/slices/testsSlice.js
// Test management slice - FIXED VERSION

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
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const fetchTestById = createAsyncThunk(
  'tests/fetchTestById',
  async (testId, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.getById(testId);
      // ✅ FIX: Handle the actual response structure
      return response.data?.data?.test || response.data?.test || response.data;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const createTest = createAsyncThunk(
  'tests/createTest',
  async (testData, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.create(testData);
      console.log('Redux createTest response:', response);
      
      // ✅ FIX: Extract test from the correct response structure
      const test = response.data?.data?.test || 
                  response.data?.test || 
                  response.data?.data || 
                  response.data;
      
      console.log('Redux extracted test:', test);
      
      if (!test) {
        throw new Error('Invalid response structure from test creation');
      }
      
      return test;
    } catch (error) {
      console.error('Redux createTest error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const updateTest = createAsyncThunk(
  'tests/updateTest',
  async ({ testId, testData }, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.update(testId, testData);
      // ✅ FIX: Handle the actual response structure
      const test = response.data?.data?.test || 
                  response.data?.test || 
                  response.data?.data || 
                  response.data;
      
      return test;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const updateTestStatus = createAsyncThunk(
  'tests/updateTestStatus',
  async ({ testId, status, notes }, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.updateStatus(testId, status, notes);
      // ✅ FIX: Handle the actual response structure
      const result = response.data?.data || response.data;
      
      return { testId, status, ...result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const getMyTests = createAsyncThunk(
  'tests/getMyTests',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.getMyTests(params);
      return response.data;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const getTestsByPatient = createAsyncThunk(
  'tests/getTestsByPatient',
  async ({ patientId, params = {} }, { rejectWithValue }) => {
    try {
      const response = await apiService.tests.getByPatient(patientId, params);
      return response.data;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Initial state
const initialState = {
  tests: [],
  myTests: [],
  currentTest: null,
  isLoading: false,
  isCreating: false,
  isUpdating: false,
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
    },
    updateTestInList: (state, action) => {
      const { testId, updates } = action.payload;
      
      // Update in tests list
      const testIndex = state.tests.findIndex(t => t.testId === testId);
      if (testIndex !== -1) {
        state.tests[testIndex] = { ...state.tests[testIndex], ...updates };
      }
      
      // Update in myTests list
      const myTestIndex = state.myTests.findIndex(t => t.testId === testId);
      if (myTestIndex !== -1) {
        state.myTests[myTestIndex] = { ...state.myTests[myTestIndex], ...updates };
      }
      
      // Update current test if it matches
      if (state.currentTest?.testId === testId) {
        state.currentTest = { ...state.currentTest, ...updates };
      }
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
        state.error = null;
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
        state.error = null;
      })
      .addCase(fetchTestById.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Create test
      .addCase(createTest.pending, (state) => {
        state.isCreating = true;
        state.error = null;
      })
      .addCase(createTest.fulfilled, (state, action) => {
        state.isCreating = false;
        state.currentTest = action.payload;
        state.tests.unshift(action.payload);
        state.error = null;
      })
      .addCase(createTest.rejected, (state, action) => {
        state.isCreating = false;
        state.error = action.payload;
      })
      
      // Update test
      .addCase(updateTest.pending, (state) => {
        state.isUpdating = true;
        state.error = null;
      })
      .addCase(updateTest.fulfilled, (state, action) => {
        state.isUpdating = false;
        state.currentTest = action.payload;
        
        const index = state.tests.findIndex(t => t._id === action.payload._id);
        if (index !== -1) {
          state.tests[index] = action.payload;
        }
        state.error = null;
      })
      .addCase(updateTest.rejected, (state, action) => {
        state.isUpdating = false;
        state.error = action.payload;
      })
      
      // Update test status
      .addCase(updateTestStatus.fulfilled, (state, action) => {
        const { testId, status } = action.payload;
        
        // Update test status in all relevant places
        if (state.currentTest?.testId === testId) {
          state.currentTest.status = status;
        }
        
        const testIndex = state.tests.findIndex(t => t.testId === testId);
        if (testIndex !== -1) {
          state.tests[testIndex].status = status;
        }
        
        const myTestIndex = state.myTests.findIndex(t => t.testId === testId);
        if (myTestIndex !== -1) {
          state.myTests[myTestIndex].status = status;
        }
      })
      
      // Get my tests
      .addCase(getMyTests.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(getMyTests.fulfilled, (state, action) => {
        state.isLoading = false;
        state.myTests = action.payload.tests || action.payload;
        state.error = null;
      })
      .addCase(getMyTests.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });
  }
});

export const { 
  clearError: clearTestsError, 
  clearCurrentTest, 
  setCurrentTest,
  updateTestInList
} = testsSlice.actions;

// Selectors
export const selectTests = (state) => state.tests.tests;
export const selectMyTests = (state) => state.tests.myTests;
export const selectCurrentTest = (state) => state.tests.currentTest;
export const selectTestsLoading = (state) => state.tests.isLoading;
export const selectTestsError = (state) => state.tests.error;
export const selectTestsPagination = (state) => state.tests.pagination;
export const selectIsCreatingTest = (state) => state.tests.isCreating;
export const selectIsUpdatingTest = (state) => state.tests.isUpdating;

export default testsSlice.reducer;
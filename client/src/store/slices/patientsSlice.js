// 📁 client/src/store/slices/patientsSlice.js
// Patient management slice matching your backend Patient model

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// Async thunks
export const fetchPatients = createAsyncThunk(
  'patients/fetchPatients',
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await apiService.patients.getAll(params);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchPatientById = createAsyncThunk(
  'patients/fetchPatientById',
  async (patientId, { rejectWithValue }) => {
    try {
      const response = await apiService.patients.getById(patientId);
      return response.data.patient;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const createPatient = createAsyncThunk(
  'patients/createPatient',
  async (patientData, { rejectWithValue }) => {
    try {
      const response = await apiService.patients.create(patientData);
      return response.data.patient;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const updatePatient = createAsyncThunk(
  'patients/updatePatient',
  async ({ patientId, patientData }, { rejectWithValue }) => {
    try {
      const response = await apiService.patients.update(patientId, patientData);
      return response.data.patient;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const searchPatients = createAsyncThunk(
  'patients/searchPatients',
  async (searchTerm, { rejectWithValue }) => {
    try {
      const response = await apiService.patients.search(searchTerm);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// Initial state
const initialState = {
  patients: [],
  currentPatient: null,
  searchResults: [],
  isLoading: false,
  isCreating: false,
  isUpdating: false,
  isSearching: false,
  error: null,
  searchError: null,
  pagination: {
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  }
};

// Patients slice
const patientsSlice = createSlice({
  name: 'patients',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
      state.searchError = null;
    },
    clearCurrentPatient: (state) => {
      state.currentPatient = null;
    },
    clearSearchResults: (state) => {
      state.searchResults = [];
      state.searchError = null;
    },
    setCurrentPatient: (state, action) => {
      state.currentPatient = action.payload;
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch patients
      .addCase(fetchPatients.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchPatients.fulfilled, (state, action) => {
        state.isLoading = false;
        state.patients = action.payload.patients || action.payload;
        state.pagination = action.payload.pagination || initialState.pagination;
      })
      .addCase(fetchPatients.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Fetch patient by ID
      .addCase(fetchPatientById.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchPatientById.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentPatient = action.payload;
      })
      .addCase(fetchPatientById.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Create patient
      .addCase(createPatient.pending, (state) => {
        state.isCreating = true;
        state.error = null;
      })
      .addCase(createPatient.fulfilled, (state, action) => {
        state.isCreating = false;
        state.currentPatient = action.payload;
        state.patients.unshift(action.payload);
      })
      .addCase(createPatient.rejected, (state, action) => {
        state.isCreating = false;
        state.error = action.payload;
      })
      
      // Update patient
      .addCase(updatePatient.pending, (state) => {
        state.isUpdating = true;
        state.error = null;
      })
      .addCase(updatePatient.fulfilled, (state, action) => {
        state.isUpdating = false;
        state.currentPatient = action.payload;
        const index = state.patients.findIndex(p => p._id === action.payload._id);
        if (index !== -1) {
          state.patients[index] = action.payload;
        }
      })
      .addCase(updatePatient.rejected, (state, action) => {
        state.isUpdating = false;
        state.error = action.payload;
      })
      
      // Search patients
      .addCase(searchPatients.pending, (state) => {
        state.isSearching = true;
        state.searchError = null;
      })
      .addCase(searchPatients.fulfilled, (state, action) => {
        state.isSearching = false;
        state.searchResults = action.payload;
      })
      .addCase(searchPatients.rejected, (state, action) => {
        state.isSearching = false;
        state.searchError = action.payload;
      });
  }
});

export const { clearError, clearCurrentPatient, clearSearchResults, setCurrentPatient } = patientsSlice.actions;

// Selectors
export const selectPatients = (state) => state.patients.patients;
export const selectCurrentPatient = (state) => state.patients.currentPatient;
export const selectSearchResults = (state) => state.patients.searchResults;
export const selectPatientsLoading = (state) => state.patients.isLoading;
export const selectPatientsError = (state) => state.patients.error;
export const selectPatientsPagination = (state) => state.patients.pagination;

export default patientsSlice.reducer;




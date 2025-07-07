import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';
import { UPLOAD_STATUSES } from '../../utils/constants';

// Async thunks
export const createUploadSession = createAsyncThunk(
  'uploads/createSession',
  async (sessionData, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.createSession(sessionData);
      return response.data.data.session;
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const getUploadSession = createAsyncThunk(
  'uploads/getSession',
  async (sessionId, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.getSession(sessionId);
      return response.data.data.session;
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const uploadFiles = createAsyncThunk(
  'uploads/uploadFiles',
  async ({ sessionId, files, onProgress }, { rejectWithValue, dispatch }) => {
    try {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      // Create progress handler
      const progressHandler = (progressEvent) => {
        const percentCompleted = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total
        );
        
        dispatch(updateUploadProgress({
          sessionId,
          progress: percentCompleted,
          stage: 'uploading'
        }));

        if (onProgress) {
          onProgress(percentCompleted);
        }
      };

      const response = await apiService.uploads.uploadFiles(
        sessionId, 
        formData, 
        progressHandler
      );

      return {
        sessionId,
        result: response.data.data
      };
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const processFiles = createAsyncThunk(
  'uploads/processFiles',
  async (sessionId, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.processFiles(sessionId);
      return {
        sessionId,
        result: response.data.data
      };
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const cancelUploadSession = createAsyncThunk(
  'uploads/cancelSession',
  async ({ sessionId, reason }, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.cancelSession(sessionId, reason);
      return { sessionId, result: response.data };
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const deleteFile = createAsyncThunk(
  'uploads/deleteFile',
  async ({ sessionId, filename }, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.deleteFile(sessionId, filename);
      return { sessionId, filename, result: response.data };
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const getMySessions = createAsyncThunk(
  'uploads/getMySessions',
  async (params, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.getMySessions(params);
      return response.data.data;
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const validateFiles = createAsyncThunk(
  'uploads/validateFiles',
  async (files, { rejectWithValue }) => {
    try {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await apiService.uploads.validateFiles(formData);
      return response.data.data;
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

export const retryUpload = createAsyncThunk(
  'uploads/retry',
  async ({ sessionId, retryData }, { rejectWithValue }) => {
    try {
      const response = await apiService.uploads.retry(sessionId, retryData);
      return { sessionId, result: response.data };
    } catch (error) {
      return rejectWithValue(apiService.handleApiError(error));
    }
  }
);

// Initial state
const initialState = {
  // Current active session
  currentSession: null,
  
  // All user sessions
  sessions: [],
  
  // Upload progress tracking
  uploadProgress: {},
  
  // File validation results
  validationResults: null,
  
  // Loading states
  isLoading: false,
  isUploading: false,
  isProcessing: false,
  
  // Error states
  error: null,
  uploadError: null,
  
  // Pagination for sessions list
  pagination: {
    page: 1,
    limit: 10,
    total: 0,
    pages: 0
  },
  
  // Filters
  filters: {
    status: null,
    startDate: null,
    endDate: null
  }
};

// Upload slice
const uploadsSlice = createSlice({
  name: 'uploads',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
      state.uploadError = null;
    },
    
    setCurrentSession: (state, action) => {
      state.currentSession = action.payload;
    },
    
    clearCurrentSession: (state) => {
      state.currentSession = null;
      state.uploadProgress = {};
    },
    
    updateUploadProgress: (state, action) => {
      const { sessionId, progress, stage, fileIndex } = action.payload;
      
      if (!state.uploadProgress[sessionId]) {
        state.uploadProgress[sessionId] = {
          overall: 0,
          files: {},
          stage: 'preparing'
        };
      }
      
      if (fileIndex !== undefined) {
        state.uploadProgress[sessionId].files[fileIndex] = progress;
        
        // Calculate overall progress from file progress
        const fileProgresses = Object.values(state.uploadProgress[sessionId].files);
        state.uploadProgress[sessionId].overall = fileProgresses.length > 0 
          ? Math.round(fileProgresses.reduce((a, b) => a + b, 0) / fileProgresses.length)
          : 0;
      } else {
        state.uploadProgress[sessionId].overall = progress;
      }
      
      if (stage) {
        state.uploadProgress[sessionId].stage = stage;
      }
    },
    
    updateSessionStatus: (state, action) => {
      const { sessionId, status } = action.payload;
      
      // Update current session if it matches
      if (state.currentSession?.sessionId === sessionId) {
        state.currentSession.status = status;
      }
      
      // Update in sessions list
      const sessionIndex = state.sessions.findIndex(s => s.sessionId === sessionId);
      if (sessionIndex !== -1) {
        state.sessions[sessionIndex].status = status;
      }
    },
    
    addFileToSession: (state, action) => {
      const { sessionId, file } = action.payload;
      
      if (state.currentSession?.sessionId === sessionId) {
        state.currentSession.files.push(file);
        state.currentSession.progress.totalFiles += 1;
      }
    },
    
    removeFileFromSession: (state, action) => {
      const { sessionId, filename } = action.payload;
      
      if (state.currentSession?.sessionId === sessionId) {
        state.currentSession.files = state.currentSession.files.filter(
          f => f.filename !== filename
        );
        state.currentSession.progress.totalFiles -= 1;
      }
    },
    
    updateFileStatus: (state, action) => {
      const { sessionId, filename, status, errorMessage } = action.payload;
      
      if (state.currentSession?.sessionId === sessionId) {
        const file = state.currentSession.files.find(f => f.filename === filename);
        if (file) {
          file.status = status;
          if (errorMessage) {
            file.errorMessage = errorMessage;
          }
          
          // Update progress counters
          const completedFiles = state.currentSession.files.filter(f => f.status === 'completed').length;
          const failedFiles = state.currentSession.files.filter(f => f.status === 'failed').length;
          
          state.currentSession.progress.uploadedFiles = completedFiles;
          state.currentSession.progress.failedFiles = failedFiles;
        }
      }
    },
    
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    
    clearFilters: (state) => {
      state.filters = {
        status: null,
        startDate: null,
        endDate: null
      };
    },
    
    clearValidationResults: (state) => {
      state.validationResults = null;
    },
    
    // Real-time updates from socket
    handleSocketUpdate: (state, action) => {
      const { type, data } = action.payload;
      
      switch (type) {
        case 'upload:progress':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.uploadProgress[data.sessionId] = {
              overall: data.progress,
              stage: data.stage,
              files: state.uploadProgress[data.sessionId]?.files || {}
            };
          }
          break;
          
        case 'upload:fileUploaded':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            const file = state.currentSession.files.find(f => f.filename === data.filename);
            if (file) {
              file.status = 'completed';
              state.currentSession.progress.uploadedFiles += 1;
            }
          }
          break;
          
        case 'upload:processingStarted':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.currentSession.status = 'active';
            state.isProcessing = true;
            state.uploadProgress[data.sessionId] = {
              ...state.uploadProgress[data.sessionId],
              stage: 'processing'
            };
          }
          break;
          
        case 'upload:processingProgress':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.uploadProgress[data.sessionId] = {
              ...state.uploadProgress[data.sessionId],
              overall: data.progress,
              stage: data.stage
            };
          }
          break;
          
        case 'upload:processingCompleted':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.currentSession.status = 'completed';
            state.isProcessing = false;
            state.uploadProgress[data.sessionId] = {
              ...state.uploadProgress[data.sessionId],
              overall: 100,
              stage: 'completed'
            };
          }
          break;
          
        case 'upload:processingFailed':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.currentSession.status = 'failed';
            state.isProcessing = false;
            state.uploadError = data.error;
            state.uploadProgress[data.sessionId] = {
              ...state.uploadProgress[data.sessionId],
              stage: 'failed'
            };
          }
          break;
          
        case 'upload:sessionUpdated':
          if (data.sessionId && state.currentSession?.sessionId === data.sessionId) {
            state.currentSession = { ...state.currentSession, ...data.session };
          }
          break;
          
        default:
          break;
      }
    }
  },
  
  extraReducers: (builder) => {
    // Create upload session
    builder
      .addCase(createUploadSession.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(createUploadSession.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentSession = action.payload;
        state.error = null;
      })
      .addCase(createUploadSession.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Get upload session
    builder
      .addCase(getUploadSession.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(getUploadSession.fulfilled, (state, action) => {
        state.isLoading = false;
        state.currentSession = action.payload;
        state.error = null;
      })
      .addCase(getUploadSession.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Upload files
    builder
      .addCase(uploadFiles.pending, (state) => {
        state.isUploading = true;
        state.uploadError = null;
      })
      .addCase(uploadFiles.fulfilled, (state, action) => {
        state.isUploading = false;
        const { sessionId, result } = action.payload;
        
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession = result.session;
        }
        
        state.uploadError = null;
      })
      .addCase(uploadFiles.rejected, (state, action) => {
        state.isUploading = false;
        state.uploadError = action.payload;
      });

    // Process files
    builder
      .addCase(processFiles.pending, (state) => {
        state.isProcessing = true;
        state.error = null;
      })
      .addCase(processFiles.fulfilled, (state, action) => {
        state.isProcessing = false;
        const { sessionId } = action.payload;
        
        if (state.currentSession?.sessionId === sessionId) {
          state.uploadProgress[sessionId] = {
            ...state.uploadProgress[sessionId],
            stage: 'processing'
          };
        }
        
        state.error = null;
      })
      .addCase(processFiles.rejected, (state, action) => {
        state.isProcessing = false;
        state.error = action.payload;
      });

    // Cancel upload session
    builder
      .addCase(cancelUploadSession.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(cancelUploadSession.fulfilled, (state, action) => {
        state.isLoading = false;
        const { sessionId } = action.payload;
        
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.status = UPLOAD_STATUSES.CANCELLED;
        }
        
        state.error = null;
      })
      .addCase(cancelUploadSession.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Delete file
    builder
      .addCase(deleteFile.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(deleteFile.fulfilled, (state, action) => {
        state.isLoading = false;
        const { sessionId, filename } = action.payload;
        
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.files = state.currentSession.files.filter(
            f => f.filename !== filename
          );
          state.currentSession.progress.totalFiles -= 1;
        }
        
        state.error = null;
      })
      .addCase(deleteFile.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Get my sessions
    builder
      .addCase(getMySessions.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(getMySessions.fulfilled, (state, action) => {
        state.isLoading = false;
        state.sessions = action.payload.sessions;
        state.pagination = action.payload.pagination;
        state.error = null;
      })
      .addCase(getMySessions.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Validate files
    builder
      .addCase(validateFiles.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(validateFiles.fulfilled, (state, action) => {
        state.isLoading = false;
        state.validationResults = action.payload;
        state.error = null;
      })
      .addCase(validateFiles.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });

    // Retry upload
    builder
      .addCase(retryUpload.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(retryUpload.fulfilled, (state, action) => {
        state.isLoading = false;
        const { sessionId } = action.payload;
        
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.status = UPLOAD_STATUSES.ACTIVE;
        }
        
        state.error = null;
      })
      .addCase(retryUpload.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });
  },
});

// Export actions
export const {
  clearError,
  setCurrentSession,
  clearCurrentSession,
  updateUploadProgress,
  updateSessionStatus,
  addFileToSession,
  removeFileFromSession,
  updateFileStatus,
  setFilters,
  clearFilters,
  clearValidationResults,
  handleSocketUpdate,
} = uploadsSlice.actions;

// Selectors
export const selectUploads = (state) => state.uploads;
export const selectCurrentSession = (state) => state.uploads.currentSession;
export const selectSessions = (state) => state.uploads.sessions;
export const selectUploadProgress = (state) => state.uploads.uploadProgress;
export const selectValidationResults = (state) => state.uploads.validationResults;
export const selectIsUploading = (state) => state.uploads.isUploading;
export const selectIsProcessing = (state) => state.uploads.isProcessing;
export const selectUploadError = (state) => state.uploads.uploadError;
export const selectUploadFilters = (state) => state.uploads.filters;
export const selectUploadPagination = (state) => state.uploads.pagination;

// Session progress selectors
export const selectSessionProgress = (sessionId) => (state) => {
  return state.uploads.uploadProgress[sessionId] || { overall: 0, stage: 'preparing' };
};

export const selectCurrentSessionProgress = (state) => {
  const sessionId = state.uploads.currentSession?.sessionId;
  return sessionId ? state.uploads.uploadProgress[sessionId] || { overall: 0, stage: 'preparing' } : null;
};

// File selectors
export const selectValidFiles = (state) => {
  return state.uploads.currentSession?.files?.filter(f => f.isValid && f.status === 'completed') || [];
};

export const selectFailedFiles = (state) => {
  return state.uploads.currentSession?.files?.filter(f => f.status === 'failed' || !f.isValid) || [];
};

export const selectTotalFiles = (state) => {
  return state.uploads.currentSession?.files?.length || 0;
};

// Export reducer
export default uploadsSlice.reducer;
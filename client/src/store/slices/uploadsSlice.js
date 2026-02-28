// client/src/store/slices/uploadsSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';
import { UPLOAD_STATUSES } from '../../utils/constants';

// Async thunks
export const createUploadSession = createAsyncThunk(
  'uploads/createSession',
  async (sessionData, { rejectWithValue }) => {
    try {
      const response = await apiService.upload.createSession(sessionData);
      return response.session; // already session object
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const getUploadSession = createAsyncThunk(
  'uploads/getSession',
  async (sessionId, { rejectWithValue }) => {
    try {
      const response = await apiService.upload.getSession(sessionId);
      return response.session;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const uploadFiles = createAsyncThunk(
  'uploads/uploadFiles',
  async ({ sessionId, files, onProgress }, { rejectWithValue, dispatch }) => {
    try {
      const progressHandler = (percentCompleted) => {
        dispatch(updateUploadProgress({
          sessionId,
          progress: percentCompleted,
          stage: 'uploading'
        }));
        if (onProgress) onProgress(percentCompleted);
      };

      const result = await apiService.upload.uploadFiles(sessionId, files, progressHandler);
      return { sessionId, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const processFiles = createAsyncThunk(
  'uploads/processFiles',
  async (sessionId, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.processFiles(sessionId);
      return { sessionId, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const cancelUploadSession = createAsyncThunk(
  'uploads/cancelSession',
  async ({ sessionId, reason }, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.cancelSession(sessionId, reason);
      return { sessionId, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const deleteFile = createAsyncThunk(
  'uploads/deleteFile',
  async ({ sessionId, filename }, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.deleteFile(sessionId, filename);
      return { sessionId, filename, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const getMySessions = createAsyncThunk(
  'uploads/getMySessions',
  async (params, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.getMySessions(params);
      return result;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const validateFiles = createAsyncThunk(
  'uploads/validateFiles',
  async (files, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.validateFiles(files);
      return result;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

export const retryUpload = createAsyncThunk(
  'uploads/retryUpload',
  async ({ sessionId, retryData }, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.retryUpload(sessionId, retryData.retryType, retryData.filenames);
      return { sessionId, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// New thunk
export const cleanupSessions = createAsyncThunk(
  'uploads/cleanupSessions',
  async (_, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.cleanupSessions();
      return result;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// ✅ BASIC: Get upload statistics
export const getStatistics = createAsyncThunk(
  'uploads/getStatistics',
  async (params = {}, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.getStatistics(params);
      return result;
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// ✅ BASIC: Check for existing results
export const checkForExistingResults = createAsyncThunk(
  'uploads/checkForExistingResults',
  async (sessionId, { rejectWithValue }) => {
    try {
      const result = await apiService.upload.checkForExistingResults(sessionId);
      return { sessionId, result };
    } catch (error) {
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Initial state
const initialState = {
  currentSession: null,
  sessions: [],
  uploadProgress: {},
  validationResults: null,
  isLoading: false,
  isUploading: false,
  isProcessing: false,
  error: null,
  uploadError: null,
  pagination: {
    page: 1,
    limit: 10,
    total: 0,
    pages: 0
  },
  // ✅ BASIC: Basic state for core features
  filters: {
    status: null,
    startDate: null,
    endDate: null
  }
};

// Slice
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
      state.isProcessing = false;
      state.isUploading = false;
      state.uploadError = null;
    },
    updateUploadProgress: (state, action) => {
      const { sessionId, progress, stage, fileIndex, currentFile, processedFiles, totalFiles, estimatedTimeRemaining } = action.payload;
      if (!state.uploadProgress[sessionId]) {
        state.uploadProgress[sessionId] = { 
          overall: 0, 
          files: {}, 
          stage: 'preparing',
          currentFile: 'Preparing...',
          processedFiles: 0,
          totalFiles: 0,
          estimatedTimeRemaining: 180
        };
      }
      if (fileIndex !== undefined) {
        state.uploadProgress[sessionId].files[fileIndex] = progress;
        const values = Object.values(state.uploadProgress[sessionId].files);
        state.uploadProgress[sessionId].overall = values.length
          ? Math.round(values.reduce((a, b) => a + b, 0) / values.length)
          : 0;
      } else {
        state.uploadProgress[sessionId].overall = progress;
      }
      if (stage) state.uploadProgress[sessionId].stage = stage;
      if (currentFile) state.uploadProgress[sessionId].currentFile = currentFile;
      if (processedFiles !== undefined) state.uploadProgress[sessionId].processedFiles = processedFiles;
      if (totalFiles !== undefined) state.uploadProgress[sessionId].totalFiles = totalFiles;
      if (estimatedTimeRemaining !== undefined) state.uploadProgress[sessionId].estimatedTimeRemaining = estimatedTimeRemaining;
    },
    updateSessionStatus: (state, action) => {
      const { sessionId, status } = action.payload;
      if (state.currentSession?.sessionId === sessionId) {
        state.currentSession.status = status;
      }
      const idx = state.sessions.findIndex(s => s.sessionId === sessionId);
      if (idx !== -1) {
        state.sessions[idx].status = status;
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
        state.currentSession.files = state.currentSession.files.filter(f => f.filename !== filename);
        if (state.currentSession.progress.totalFiles > 0) {
          state.currentSession.progress.totalFiles -= 1;
        }
      }
    },
    updateFileStatus: (state, action) => {
      const { sessionId, filename, status, errorMessage } = action.payload;
      if (state.currentSession?.sessionId === sessionId) {
        const file = state.currentSession.files.find(f => f.filename === filename);
        if (file) {
          file.status = status;
          if (errorMessage) file.errorMessage = errorMessage;
          const completed = state.currentSession.files.filter(f => f.status === 'completed').length;
          const failed = state.currentSession.files.filter(f => f.status === 'failed').length;
          state.currentSession.progress.uploadedFiles = completed;
          state.currentSession.progress.failedFiles = failed;
        }
      }
    },
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    clearFilters: (state) => {
      state.filters = { status: null, startDate: null, endDate: null };
    },
    clearValidationResults: (state) => {
      state.validationResults = null;
    },
    handleSocketUpdate: (state, action) => {
      const { type, data } = action.payload;
      console.log('🔌 Redux handleSocketUpdate called:', { type, data });
      console.log('🔌 Current state:', {
        currentSessionId: state.currentSession?.sessionId,
        dataSessionId: data.sessionId,
        uploadProgressKeys: Object.keys(state.uploadProgress)
      });
      
      switch (type) {
        case 'upload:progress':
          if (data.sessionId) {
            state.uploadProgress[data.sessionId] = {
              overall: data.progress,
              stage: data.stage,
              files: state.uploadProgress[data.sessionId]?.files || {}
            };
          }
          break;
        case 'upload:fileUploaded':
          if (data.sessionId) {
            const session = state.sessions.find(s => s.sessionId === data.sessionId);
            if (session) {
              const file = session.files.find(f => f.filename === data.filename);
              if (file) {
                file.status = 'completed';
                session.progress.uploadedFiles += 1;
              }
            }
          }
          break;
        case 'upload:processingStarted':
          if (data.sessionId) {
            // Initialize upload progress
            if (!state.uploadProgress[data.sessionId]) {
              state.uploadProgress[data.sessionId] = { 
                overall: 0, 
                files: {}, 
                stage: 'preparing',
                currentFile: 'Preparing...',
                processedFiles: 0,
                totalFiles: 0,
                estimatedTimeRemaining: 180
              };
            }
            
            // Update current session if it matches
            if (state.currentSession?.sessionId === data.sessionId) {
              state.currentSession.status = 'active';
            }
            
            state.isProcessing = true;
            state.uploadProgress[data.sessionId].stage = 'processing';
          }
          break;
        case 'upload:processingProgress':
          if (data.sessionId) {
            if (!state.uploadProgress[data.sessionId]) {
              state.uploadProgress[data.sessionId] = {
                overall: 0,
                files: {},
                stage: 'processing',
                currentFile: 'Processing...',
                processedFiles: 0,
                totalFiles: 0,
                estimatedTimeRemaining: 180,
                imageProgress: null,
                analysisMode: null
              };
            }

            state.uploadProgress[data.sessionId] = {
              ...state.uploadProgress[data.sessionId],
              overall: data.progress || data.overall,
              stage: data.stage,
              currentFile: data.currentFile,
              processedFiles: data.processedFiles,
              totalFiles: data.totalFiles,
              estimatedTimeRemaining: data.estimatedTimeRemaining,
              // ✅ NEW: Include per-image progress for parallel processing display
              imageProgress: data.imageProgress || state.uploadProgress[data.sessionId].imageProgress,
              analysisMode: data.analysisMode || state.uploadProgress[data.sessionId].analysisMode
            };

            // Log progress for debugging
            if (data.imageProgress) {
              console.log(`🔄 Image progress: ${data.imageProgress.completed}/${data.imageProgress.total}`);
            }
          }
          break;
        case 'upload:processingCompleted':
          console.log('🔌 Processing completion event received in Redux');
          console.log('🔌 Session ID check:', {
            dataSessionId: data.sessionId,
            currentSessionId: state.currentSession?.sessionId,
            match: data.sessionId === state.currentSession?.sessionId
          });
          
          if (data.sessionId) {
            // Initialize progress if it doesn't exist
            if (!state.uploadProgress[data.sessionId]) {
              state.uploadProgress[data.sessionId] = { 
                overall: 0, 
                files: {}, 
                stage: 'preparing',
                currentFile: 'Preparing...',
                processedFiles: 0,
                totalFiles: 0,
                estimatedTimeRemaining: 0
              };
            }
            
            // Update current session if it matches
            if (state.currentSession?.sessionId === data.sessionId) {
              state.currentSession.status = 'completed';
              state.currentSession.result = data.result;
            }
            
            state.isProcessing = false;
            state.uploadProgress[data.sessionId].stage = 'completed';
            state.uploadProgress[data.sessionId].overall = 100;
            state.uploadProgress[data.sessionId].currentFile = 'Analysis complete!';
            state.uploadProgress[data.sessionId].processedFiles = data.totalFiles || state.uploadProgress[data.sessionId].totalFiles;
            state.uploadProgress[data.sessionId].estimatedTimeRemaining = 0;
            console.log('🔌 State updated successfully for session:', data.sessionId);
          } else {
            console.log('🔌 No session ID in completion data');
          }
          break;
        case 'upload:processingFailed':
          if (data.sessionId) {
            if (!state.uploadProgress[data.sessionId]) {
              state.uploadProgress[data.sessionId] = { 
                overall: 0, 
                files: {}, 
                stage: 'failed',
                currentFile: 'Processing failed',
                processedFiles: 0,
                totalFiles: 0,
                estimatedTimeRemaining: 0
              };
            }
            
            // Update current session if it matches
            if (state.currentSession?.sessionId === data.sessionId) {
              state.currentSession.status = 'failed';
            }
            
            state.isProcessing = false;
            state.uploadProgress[data.sessionId].stage = 'failed';
            state.uploadProgress[data.sessionId].currentFile = data.error || 'Processing failed';
            state.uploadProgress[data.sessionId].estimatedTimeRemaining = 0;
          }
          break;
        case 'upload:sessionUpdated':
          if (data.sessionId) {
            const sessionIndex = state.sessions.findIndex(s => s.sessionId === data.sessionId);
            if (sessionIndex !== -1) {
              state.sessions[sessionIndex] = { ...state.sessions[sessionIndex], ...data };
            }
            if (state.currentSession?.sessionId === data.sessionId) {
              state.currentSession = { ...state.currentSession, ...data };
            }
          }
          break;
        default:
          console.log('🔌 Unknown socket event type:', type);
      }
    }
  },
  extraReducers: (builder) => {
    builder
      .addCase(createUploadSession.pending, (state) => { state.isLoading = true; })
      .addCase(createUploadSession.fulfilled, (state, action) => {
        state.currentSession = action.payload;
        state.isLoading = false;
      })
      .addCase(createUploadSession.rejected, (state, action) => {
        state.error = action.payload;
        state.isLoading = false;
      });

    builder
      .addCase(getUploadSession.pending, (state) => { state.isLoading = true; })
      .addCase(getUploadSession.fulfilled, (state, action) => {
        state.currentSession = action.payload;
        state.isLoading = false;
      })
      .addCase(getUploadSession.rejected, (state, action) => {
        state.error = action.payload;
        state.isLoading = false;
      });

    builder
      .addCase(uploadFiles.pending, (state) => { state.isUploading = true; })
      .addCase(uploadFiles.fulfilled, (state, action) => {
        const { sessionId, result } = action.payload;
        if (state.currentSession?.sessionId === sessionId && result?.session) {
          state.currentSession = result.session;
        }
        state.isUploading = false;
      })
      .addCase(uploadFiles.rejected, (state, action) => {
        state.uploadError = action.payload;
        state.isUploading = false;
      });

    builder
      .addCase(processFiles.pending, (state) => { state.isProcessing = true; })
      .addCase(processFiles.fulfilled, (state, action) => {
        const { sessionId } = action.payload;
        state.uploadProgress[sessionId].stage = 'processing';
        state.isProcessing = false;
      })
      .addCase(processFiles.rejected, (state, action) => {
        state.error = action.payload;
        state.isProcessing = false;
      })
      
      .addCase(cancelUploadSession.fulfilled, (state, action) => {
        const { sessionId } = action.payload;
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.status = UPLOAD_STATUSES.CANCELLED;
        }
        state.isLoading = false;
      })

      .addCase(deleteFile.fulfilled, (state, action) => {
        const { sessionId, filename } = action.payload;
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.files = state.currentSession.files.filter(f => f.filename !== filename);
          if (state.currentSession.progress.totalFiles > 0) {
            state.currentSession.progress.totalFiles -= 1;
          }
        }
        state.isLoading = false;
      })

      .addCase(getMySessions.fulfilled, (state, action) => {
        state.sessions = action.payload.sessions;
        state.pagination = action.payload.pagination;
        state.isLoading = false;
      })

      .addCase(validateFiles.fulfilled, (state, action) => {
        state.validationResults = action.payload;
        state.isLoading = false;
      })

      .addCase(retryUpload.fulfilled, (state, action) => {
        const { sessionId } = action.payload;
        if (state.currentSession?.sessionId === sessionId) {
          state.currentSession.status = UPLOAD_STATUSES.ACTIVE;
        }
        state.isLoading = false;
      })

      .addCase(cleanupSessions.fulfilled, (state) => {
        state.isLoading = false;
      })
      
      // ✅ BASIC: Get upload statistics
      .addCase(getStatistics.pending, (state) => { 
        state.isLoading = true; 
      })
      .addCase(getStatistics.fulfilled, (state, action) => {
        state.isLoading = false;
      })
      .addCase(getStatistics.rejected, (state, action) => {
        state.error = action.payload;
        state.isLoading = false;
      })
      
      // ✅ BASIC: Check for existing results
      .addCase(checkForExistingResults.pending, (state) => { 
        state.isLoading = true; 
      })
      .addCase(checkForExistingResults.fulfilled, (state, action) => {
        const { sessionId, result } = action.payload;
        state.isLoading = false;
      })
      .addCase(checkForExistingResults.rejected, (state, action) => {
        state.error = action.payload;
        state.isLoading = false;
      });
  }
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

// Export selectors and reducer
export const selectUploads = (state) => state.uploads;
export const selectCurrentSession = (state) => state.uploads.currentSession;
export const selectUploadProgress = (state) => state.uploads.uploadProgress;
export const selectValidationResults = (state) => state.uploads.validationResults;
export const selectIsUploading = (state) => state.uploads.isUploading;
export const selectIsProcessing = (state) => state.uploads.isProcessing;
export const selectUploadError = (state) => state.uploads.uploadError;
export const selectUploadFilters = (state) => state.uploads.filters;
export const selectUploadPagination = (state) => state.uploads.pagination;
export const selectSessions = (state) => state.uploads.sessions;

export const selectSessionProgress = (sessionId) => (state) =>
  state.uploads.uploadProgress[sessionId] || { overall: 0, stage: 'preparing' };

export const selectCurrentSessionProgress = (state) => {
  const sessionId = state.uploads.currentSession?.sessionId;
  return sessionId ? state.uploads.uploadProgress[sessionId] || { overall: 0, stage: 'preparing' } : null;
};

export const selectValidFiles = (state) =>
  state.uploads.currentSession?.files?.filter(f => f.isValid && f.status === 'completed') || [];

export const selectFailedFiles = (state) =>
  state.uploads.currentSession?.files?.filter(f => f.status === 'failed' || !f.isValid) || [];

export const selectTotalFiles = (state) =>
  state.uploads.currentSession?.files?.length || 0;

export default uploadsSlice.reducer;


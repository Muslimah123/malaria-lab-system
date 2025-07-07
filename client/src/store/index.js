// 📁 client/src/store/index.js
// Complete Redux store configuration matching your backend system

import { configureStore } from '@reduxjs/toolkit';
import { combineReducers } from 'redux';
import { useDispatch, useSelector } from 'react-redux';
import {
  persistStore,
  persistReducer,
  FLUSH,
  REHYDRATE,
  PAUSE,
  PERSIST,
  PURGE,
  REGISTER,
} from 'redux-persist';
import storage from 'redux-persist/lib/storage';

// Import reducers
import authReducer from './slices/authSlice';
import uploadsReducer from './slices/uploadsSlice';
import notificationsReducer from './slices/notificationsSlice';
import patientsReducer from './slices/patientsSlice';
import testsReducer from './slices/testsSlice';
import dashboardReducer from './slices/dashboardSlice';
import usersReducer from './slices/usersSlice';
import auditReducer from './slices/auditSlice';

// API Service for store integration
import apiService from '../services/api';

// Root reducer
const rootReducer = combineReducers({
  auth: authReducer,
  uploads: uploadsReducer,
  notifications: notificationsReducer,
  patients: patientsReducer,
  tests: testsReducer,
  dashboard: dashboardReducer,
  users: usersReducer,
  audit: auditReducer,
});

// Persist configuration
const persistConfig = {
  key: 'root',
  version: 1,
  storage,
  // Only persist auth state, everything else should be fresh on reload
  whitelist: ['auth'],
  // Transform functions to handle serialization
  transforms: [],
};

// Create persisted reducer
const persistedReducer = persistReducer(persistConfig, rootReducer);

// Custom middleware for API integration
const apiMiddleware = (store) => (next) => (action) => {
  // Auto-logout on authentication errors
  if (action.type?.endsWith('/rejected') && 
      action.payload?.includes?.('Authentication required')) {
    store.dispatch({ type: 'auth/clearAuth' });
  }
  
  return next(action);
};

// Token synchronization middleware
const tokenSyncMiddleware = (store) => (next) => (action) => {
  const result = next(action);
  
  // Sync token with API service when auth state changes
  if (action.type?.startsWith('auth/')) {
    const state = store.getState();
    const token = state.auth.token;
    apiService.setToken(token);
  }
  
  return result;
};

// Configure store
export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER],
        // Ignore certain paths that might contain non-serializable data
        ignoredPaths: ['socket', 'api'],
      },
      // Disable dev tools in production
      devTools: process.env.NODE_ENV !== 'production',
    })
    .concat(apiMiddleware, tokenSyncMiddleware),
  
  // Enable Redux DevTools Extension
  devTools: process.env.NODE_ENV !== 'production' && {
    name: 'Malaria Lab System',
    trace: true,
    traceLimit: 25,
    actionSanitizer: (action) => {
      // Sanitize sensitive data in dev tools
      if (action.type?.includes('password') || action.type?.includes('token')) {
        return {
          ...action,
          payload: action.payload ? '[REDACTED]' : action.payload,
        };
      }
      return action;
    },
    stateSanitizer: (state) => {
      // Hide sensitive data in dev tools
      return {
        ...state,
        auth: {
          ...state.auth,
          token: state.auth.token ? '[TOKEN_PRESENT]' : null,
          refreshToken: state.auth.refreshToken ? '[REFRESH_TOKEN_PRESENT]' : null,
        },
      };
    },
  },
});

// Create persistor
export const persistor = persistStore(store);

// Initialize API service with store
apiService.setStore?.(store);

// Export for use in components
export default store;
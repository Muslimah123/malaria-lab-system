import React from 'react';
import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';

// **ADD THIS LINE - Import your CSS file**
import './index.css';

// Redux slices
import authReducer from './store/slices/authSlice';
import uploadsReducer from './store/slices/uploadsSlice';
import testsReducer from './store/slices/testsSlice';
import notificationsReducer from './store/slices/notificationsSlice';

// Socket middleware
import socketMiddleware from './store/middleware/socketMiddleware';

// Main App component
import App from './App';

// Performance monitoring
import reportWebVitals from './reportWebVitals';

// Configure Redux store
const store = configureStore({
  reducer: {
    auth: authReducer,
    uploads: uploadsReducer,
    tests: testsReducer,
    notifications: notificationsReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types for serialization check
        ignoredActions: [
          'uploads/uploadFiles/pending',
          'uploads/uploadFiles/fulfilled',
          'uploads/handleSocketUpdate',
        ],
        // Ignore these field paths in all actions
        ignoredActionsPaths: ['payload.onProgress'],
        // Ignore these paths in the state
        ignoredPaths: ['uploads.uploadProgress.onProgress'],
      },
    }).concat(socketMiddleware),
  devTools: process.env.NODE_ENV !== 'production',
});

// Create root element
const container = document.getElementById('root');
const root = createRoot(container);

// Render app
root.render(
  <React.StrictMode>
    <Provider store={store}>
      <App />
    </Provider>
  </React.StrictMode>
);

// Performance monitoring
reportWebVitals(console.log);

// Hot module replacement for development
if (process.env.NODE_ENV === 'development' && module.hot) {
  module.hot.accept('./App', () => {
    const NextApp = require('./App').default;
    root.render(
      <React.StrictMode>
        <Provider store={store}>
          <NextApp />
        </Provider>
      </React.StrictMode>
    );
  });
}

// Service worker registration (optional)
if ('serviceWorker' in navigator && process.env.NODE_ENV === 'production') {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        console.log('SW registered: ', registration);
      })
      .catch((registrationError) => {
        console.log('SW registration failed: ', registrationError);
      });
  });
}
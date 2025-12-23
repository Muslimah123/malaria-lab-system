
// 📁 client/src/App.jsx
import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { store, persistor } from './store';
import { useAuth, usePermissions } from './hooks/useAuth';
import { ToastProvider } from './contexts/ToastContext';

import LoginForm from './components/auth/LoginForm';
import Dashboard from './pages/Dashboard';
import AppLayout from './components/layout/AppLayout';
import SampleUpload from './pages/UploadPageLayout';
import TestResultsList from './pages/TestResultsList';
import UserManagement from './components/admin/UserManagement';
import LoadingSpinner from './components/common/LoadingSpinner';
import UploadPageLayout from './pages/UploadPageLayout';
import TestResultsLayout from './pages/TestResultsLayout';
import TestRecordsPage from './pages/TestRecordsPage';
import PatientManagementPage from './pages/PatientManagementPage';
import UserManagementPage from './pages/UserManagementPage';
import SettingsPage from './pages/SettingsPage';
import AnalyticsPage from './pages/AnalyticsPage';


// Protected Route Component
const ProtectedRoute = ({ children, requiredRole = null, requiredPermission = null }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const { hasPermission, hasRole } = usePermissions();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner size="xl" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return <Navigate to="/dashboard" replace />;
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

function AppContent() {
  return (
    <Router>
      <div className="App">
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<LoginForm />} />
          
          {/* Protected Routes */}
          <Route 
            path="/dashboard" 
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } 
          />
          
          <Route 
            path="/upload" 
            element={
              <ProtectedRoute requiredPermission="canUploadSamples">
                <UploadPageLayout />
              </ProtectedRoute>
            } 
          />

          {/* Test Results Routes */}
          <Route 
            path="/results/:testId" 
            element={
              <ProtectedRoute>
                <TestResultsLayout />
              </ProtectedRoute>
            } 
          />

          

          <Route 
  path="/results" 
  element={
    <ProtectedRoute>
      <TestResultsList />
    </ProtectedRoute>
  } 
/>
<Route 
  path="/tests" 
  element={
    <ProtectedRoute>
      <TestRecordsPage />
    </ProtectedRoute>
  } 
/>
          <Route 
  path="/patients" 
  element={
    <ProtectedRoute>
      <PatientManagementPage />
    </ProtectedRoute>
  } 
/>
          <Route 
            path="/users" 
            element={
              <ProtectedRoute >
                <UserManagementPage />
              </ProtectedRoute>
            } 
          />
          
          <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <SettingsPage />
              </ProtectedRoute>

          }
          />

          <Route
          path="/analytics"
          element={
            <ProtectedRoute>
              <AnalyticsPage />
              </ProtectedRoute>

          }
          />
          
          {/* Redirect root to login instead of dashboard */}
          <Route path="/" element={<Navigate to="/login" replace />} />
          
          {/* Catch all - redirect to login */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

function App() {
  // Initialize performance monitoring when the app starts
  useEffect(() => {
    // Start performance monitoring when the app loads
    // performanceMonitor.start(); // This line is removed as per the edit hint
    
    // Cleanup on unmount
    return () => {
      // performanceMonitor.stop(); // This line is removed as per the edit hint
    };
  }, []);

  return (
    <Provider store={store}>
      <PersistGate loading={<LoadingSpinner size="xl" />} persistor={persistor}>
        <ToastProvider>
          <AppContent />
        </ToastProvider>
      </PersistGate>
    </Provider>
  );
}

export default App;
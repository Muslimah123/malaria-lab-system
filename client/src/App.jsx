// // 📁 client/src/App.jsx
// // Fixed App component with correct imports

// import React from 'react';
// import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
// import { Provider } from 'react-redux';
// import { PersistGate } from 'redux-persist/integration/react';
// import { store, persistor } from './store';
// import { useAuth, usePermissions } from './hooks/useAuth';

// import LoginForm from './components/auth/LoginForm';
// import Dashboard from './pages/Dashboard';
// import AppLayout from './components/layout/AppLayout';
// import SampleUpload from './pages/UploadPageLayout'; // Updated import to match the new layout
// import UserManagement from './components/admin/UserManagement';
// import LoadingSpinner from './components/common/LoadingSpinner';
// import UploadPageLayout from './pages/UploadPageLayout';

// // Protected Route Component
// const ProtectedRoute = ({ children, requiredRole = null, requiredPermission = null }) => {
//   const { isAuthenticated, isLoading } = useAuth();
//   const { hasPermission, hasRole } = usePermissions();

//   if (isLoading) {
//     return (
//       <div className="min-h-screen flex items-center justify-center">
//         <LoadingSpinner size="xl" />
//       </div>
//     );
//   }

//   if (!isAuthenticated) {
//     return <Navigate to="/login" replace />;
//   }

//   if (requiredRole && !hasRole(requiredRole)) {
//     return <Navigate to="/dashboard" replace />;
//   }

//   if (requiredPermission && !hasPermission(requiredPermission)) {
//     return <Navigate to="/dashboard" replace />;
//   }

//   return children;
// };

// function AppContent() {
//   return (
//     <Router>
//       <div className="App">
//         <Routes>
//           {/* Public Routes */}
//           <Route path="/login" element={<LoginForm />} />
          
//           {/* Protected Routes */}
//           <Route 
//             path="/dashboard" 
//             element={
//               <ProtectedRoute>
//                 {/* <AppLayout> */}
//                   <Dashboard />
//                 {/* </AppLayout> */}
//               </ProtectedRoute>
//             } 
//           />
          
//           <Route 
//             path="/upload" 
//             element={
//               <ProtectedRoute requiredPermission="canUploadSamples">
//                 <UploadPageLayout />
//               </ProtectedRoute>
//             } 
//           />
          
//           <Route 
//             path="/users" 
//             element={
//               <ProtectedRoute requiredRole="admin">
//                 <UserManagement />
//               </ProtectedRoute>
//             } 
//           />
          
//           {/* Redirect root to dashboard */}
//           <Route path="/" element={<Navigate to="/dashboard" replace />} />
//         </Routes>
//       </div>
//     </Router>
//   );
// }

// function App() {
//   return (
//     <Provider store={store}>
//       <PersistGate loading={<LoadingSpinner size="xl" />} persistor={persistor}>
//         <AppContent />
//       </PersistGate>
//     </Provider>
//   );
// }

// export default App;
// 📁 client/src/App.jsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { store, persistor } from './store';
import { useAuth, usePermissions } from './hooks/useAuth';

import LoginForm from './components/auth/LoginForm';
import Dashboard from './pages/Dashboard';
import AppLayout from './components/layout/AppLayout';
import SampleUpload from './pages/UploadPageLayout';
import TestResultsPage from './pages/TestResultsPage'; 
import UserManagement from './components/admin/UserManagement';
import LoadingSpinner from './components/common/LoadingSpinner';
import UploadPageLayout from './pages/UploadPageLayout';
import TestResultsLayout from './pages/TestResultsLayout'; 


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
                {/* TODO: Create TestResultsList component for viewing all results */}
                <div className="p-8 text-center">
                  <h1 className="text-2xl font-bold">Test Results Overview</h1>
                  <p className="text-gray-600 mt-2">Coming soon - list of all test results</p>
                </div>
              </ProtectedRoute>
            } 
          />
          
          <Route 
            path="/users" 
            element={
              <ProtectedRoute requiredRole="admin">
                <UserManagement />
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
  return (
    <Provider store={store}>
      <PersistGate loading={<LoadingSpinner size="xl" />} persistor={persistor}>
        <AppContent />
      </PersistGate>
    </Provider>
  );
}

export default App;
import React, { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { Navigate, useLocation } from 'react-router-dom';
import { 
  selectIsAuthenticated, 
  selectIsLoading, 
  selectUser,
  verifySession 
} from '../../store/slices/authSlice';
import { ROUTES } from '../../utils/constants';
import LoadingSpinner from '../common/LoadingSpinner';

const ProtectedRoute = ({ children, requiredRole = null, requiredPermission = null }) => {
  const dispatch = useDispatch();
  const location = useLocation();
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const isLoading = useSelector(selectIsLoading);
  const user = useSelector(selectUser);

  useEffect(() => {
    // Verify session periodically if authenticated
    if (isAuthenticated) {
      const verifySessionInterval = setInterval(() => {
        dispatch(verifySession());
      }, 5 * 60 * 1000); // Check every 5 minutes

      return () => clearInterval(verifySessionInterval);
    }
  }, [isAuthenticated, dispatch]);

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-gray-600">Verifying authentication...</p>
        </div>
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return (
      <Navigate 
        to={ROUTES.LOGIN} 
        state={{ from: location.pathname }} 
        replace 
      />
    );
  }

  // Check role-based access
  if (requiredRole && user?.role !== requiredRole) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center p-8">
          <div className="bg-red-50 border border-red-200 rounded-lg p-6">
            <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-red-100 rounded-full">
              <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-red-900 mb-2">Access Denied</h3>
            <p className="text-red-700">
              You don't have the required role ({requiredRole}) to access this page.
            </p>
            <p className="text-sm text-red-600 mt-2">
              Current role: {user?.role || 'Unknown'}
            </p>
            <button
              onClick={() => window.history.back()}
              className="mt-4 btn btn-outline"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Check permission-based access
  if (requiredPermission && !user?.permissions?.[requiredPermission]) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center p-8">
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
            <div className="flex items-center justify-center w-12 h-12 mx-auto mb-4 bg-yellow-100 rounded-full">
              <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 0h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-yellow-900 mb-2">Permission Required</h3>
            <p className="text-yellow-700">
              You don't have the required permission ({requiredPermission}) to access this page.
            </p>
            <p className="text-sm text-yellow-600 mt-2">
              Please contact your administrator if you believe this is an error.
            </p>
            <button
              onClick={() => window.history.back()}
              className="mt-4 btn btn-outline"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Render protected content
  return children;
};

// Higher-order component for role-based protection
export const withRoleProtection = (Component, requiredRole) => {
  return (props) => (
    <ProtectedRoute requiredRole={requiredRole}>
      <Component {...props} />
    </ProtectedRoute>
  );
};

// Higher-order component for permission-based protection
export const withPermissionProtection = (Component, requiredPermission) => {
  return (props) => (
    <ProtectedRoute requiredPermission={requiredPermission}>
      <Component {...props} />
    </ProtectedRoute>
  );
};

// Role-specific route components
export const AdminRoute = ({ children }) => (
  <ProtectedRoute requiredRole="admin">
    {children}
  </ProtectedRoute>
);

export const SupervisorRoute = ({ children }) => (
  <ProtectedRoute requiredRole="supervisor">
    {children}
  </ProtectedRoute>
);

export const TechnicianRoute = ({ children }) => (
  <ProtectedRoute requiredRole="technician">
    {children}
  </ProtectedRoute>
);

// Permission-specific route components
export const UploadRoute = ({ children }) => (
  <ProtectedRoute requiredPermission="canUploadSamples">
    {children}
  </ProtectedRoute>
);

export const ReportsRoute = ({ children }) => (
  <ProtectedRoute requiredPermission="canViewReports">
    {children}
  </ProtectedRoute>
);

export const ExportRoute = ({ children }) => (
  <ProtectedRoute requiredPermission="canExportReports">
    {children}
  </ProtectedRoute>
);

export default ProtectedRoute;
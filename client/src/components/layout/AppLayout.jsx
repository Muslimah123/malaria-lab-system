// src/components/layout/AppLayout.jsx
import React, { useState, useEffect } from 'react';
import { X, AlertTriangle } from 'lucide-react';
import { useSelector, useDispatch } from 'react-redux';
import { selectUser, selectIsAuthenticated } from '../../store/slices/authSlice';
import { selectNotifications } from '../../store/slices/notificationsSlice';

// Components
import Header from '../common/Header';
import Sidebar from '../common/Sidebar';
import Toast from '../common/Toast';
import LoadingSpinner from '../common/LoadingSpinner';

// Services
import socketService from '../../services/socketService';

const AppLayout = ({ 
  children, 
  title, 
  subtitle,
  showHeader = true,
  showSidebar = true,
  showSearch = true,
  showNotifications = true,
  onRefresh = null,
  headerActions = null,
  className = ""
}) => {
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const notifications = useSelector(selectNotifications);

  // Local state
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [socketConnected, setSocketConnected] = useState(false);
  const [pageLoading, setPageLoading] = useState(false);

  // Initialize socket connection on mount
  useEffect(() => {
    if (isAuthenticated) {
      initializeSocket();
    }

    return () => {
      if (socketService.isConnected()) {
        socketService.disconnect();
      }
    };
  }, [isAuthenticated]);

  const initializeSocket = () => {
    const token = localStorage.getItem('authToken');
    
    if (token) {
      socketService.safeConnect(token);
      
      socketService.socket?.on('connect', () => {
        setSocketConnected(true);
      });

      socketService.socket?.on('disconnect', () => {
        setSocketConnected(false);
      });

      // Subscribe to notifications for current user
      if (user?.id) {
        socketService.subscribeToNotifications(user.id, (notification) => {
          // Notifications are handled by the notifications slice
          console.log('Layout received notification:', notification);
        });
      }
    }
  };

  // Don't render layout for unauthenticated users
  if (!isAuthenticated) {
    return children;
  }

  return (
    <div className={`min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex ${className}`}>
      {/* Sidebar */}
      {showSidebar && (
        <Sidebar 
          isOpen={sidebarOpen} 
          onClose={() => setSidebarOpen(false)} 
        />
      )}

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-64">
        {/* Header */}
        {showHeader && (
          <Header
            title={title}
            subtitle={subtitle}
            onMenuClick={() => setSidebarOpen(true)}
            onRefresh={onRefresh}
            socketConnected={socketConnected}
            showSearch={showSearch}
            showNotifications={showNotifications}
          />
        )}

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto pt-20">
          {/* Loading Overlay */}
          {pageLoading && (
            <div className="absolute inset-0 bg-black/50 flex items-center justify-center z-50">
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-8 flex items-center space-x-4">
                <LoadingSpinner size="lg" color="white" />
                <span className="text-white text-lg">Loading...</span>
              </div>
            </div>
          )}

          {/* Page Content */}
          <div className="h-full">
            {children}
          </div>
        </main>

        {/* Header Actions (if provided) */}
        {headerActions && (
          <div className="absolute top-4 right-4 z-10">
            {headerActions}
          </div>
        )}
      </div>

      {/* Toast Notifications */}
      <Toast />
    </div>
  );
};

// Higher-order component for wrapping pages with layout
export const withAppLayout = (WrappedComponent, layoutProps = {}) => {
  return (props) => (
    <AppLayout {...layoutProps}>
      <WrappedComponent {...props} />
    </AppLayout>
  );
};

// Specialized layout components for different page types

// Dashboard Layout
export const DashboardLayout = ({ children, ...props }) => (
  <AppLayout
    title="Dashboard"
    subtitle={`Welcome back, ${props.user?.firstName || 'User'}`}
    showSearch={true}
    showNotifications={true}
    {...props}
  >
    {children}
  </AppLayout>
);

// Admin Layout
export const AdminLayout = ({ children, ...props }) => (
  <AppLayout
    showSearch={true}
    showNotifications={true}
    {...props}
  >
    {children}
  </AppLayout>
);

// Simple Page Layout (minimal header)
export const SimpleLayout = ({ children, ...props }) => (
  <AppLayout
    showSearch={false}
    showNotifications={false}
    {...props}
  >
    {children}
  </AppLayout>
);

// Full Screen Layout (no sidebar)
export const FullScreenLayout = ({ children, ...props }) => (
  <AppLayout
    showSidebar={false}
    showSearch={false}
    showNotifications={true}
    {...props}
  >
    {children}
  </AppLayout>
);

// Modal Layout (for overlay content)
export const ModalLayout = ({ children, isOpen, onClose, title, ...props }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg max-w-4xl w-full mx-4 max-h-[90vh] overflow-hidden">
        {title && (
          <div className="flex items-center justify-between p-6 border-b border-white/20">
            <h2 className="text-xl font-semibold text-white">{title}</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        )}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
          {children}
        </div>
      </div>
    </div>
  );
};

// Loading Layout (for initial app loading)
export const LoadingLayout = ({ message = "Loading application..." }) => (
  <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
    <div className="text-center">
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-8 inline-block">
        <LoadingSpinner size="xl" color="white" />
        <p className="mt-4 text-white text-lg">{message}</p>
      </div>
    </div>
  </div>
);

// Error Layout (for error boundaries)
export const ErrorLayout = ({ 
  error = "Something went wrong", 
  onRetry = null,
  onGoHome = () => window.location.href = '/dashboard'
}) => (
  <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
    <div className="text-center max-w-md mx-4">
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-8">
        <div className="text-red-400 mb-4">
          <AlertTriangle className="h-16 w-16 mx-auto" />
        </div>
        <h2 className="text-xl font-semibold text-white mb-2">Application Error</h2>
        <p className="text-red-200 mb-6">{error}</p>
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          {onRetry && (
            <button
              onClick={onRetry}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              Try Again
            </button>
          )}
          <button
            onClick={onGoHome}
            className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 text-white rounded-lg transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    </div>
  </div>
);

export default AppLayout;
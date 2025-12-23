// 📁 client/src/hooks/useAuth.js
// Custom hooks for authentication and authorization matching your backend

import { useSelector, useDispatch } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { useEffect, useState, useCallback } from 'react';
import {
  selectUser,
  selectIsAuthenticated,
  selectIsLoading,
  selectAuthError,
  selectUserRole,
  selectUserPermissions,
  selectIsSessionExpired,
  selectSessionTimeRemaining,
  logout,
  getCurrentUser,
  refreshToken
} from '../store/slices/authSlice';
import { USER_ROLES, ROUTES } from '../utils/constants';
import apiService from '../services/api';

/**
 * Main authentication hook
 * Provides all authentication-related state and functions
 */
export const useAuth = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();

  const user = useSelector(selectUser);
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const isLoading = useSelector(selectIsLoading);
  const error = useSelector(selectAuthError);
  const userRole = useSelector(selectUserRole);
  const permissions = useSelector(selectUserPermissions);
  const isSessionExpired = useSelector(selectIsSessionExpired);
  const sessionTimeRemaining = useSelector(selectSessionTimeRemaining);

  // Auto-refresh token when nearing expiry
  useEffect(() => {
    if (sessionTimeRemaining && sessionTimeRemaining < 300000) { // 5 minutes
      dispatch(refreshToken());
    }
  }, [sessionTimeRemaining, dispatch]);

  // Redirect to login if session expired
  useEffect(() => {
    if (isSessionExpired && isAuthenticated) {
      handleLogout();
    }
  }, [isSessionExpired, isAuthenticated]);

  const handleLogout = useCallback(async () => {
    try {
      await dispatch(logout()).unwrap();
      navigate(ROUTES.LOGIN, { 
        state: { 
          from: location.pathname !== ROUTES.LOGIN ? location : null,
          message: 'You have been logged out successfully'
        } 
      });
    } catch (error) {
      // Even if logout fails, redirect to login
      navigate(ROUTES.LOGIN);
    }
  }, [dispatch, navigate, location]);

  const refreshUserData = useCallback(async () => {
    if (isAuthenticated) {
      try {
        await dispatch(getCurrentUser()).unwrap();
      } catch (error) {
        console.error('Failed to refresh user data:', error);
      }
    }
  }, [dispatch, isAuthenticated]);

  return {
    // State
    user,
    isAuthenticated,
    isLoading,
    error,
    userRole,
    permissions,
    isSessionExpired,
    sessionTimeRemaining,
    
    // Actions
    logout: handleLogout,
    refreshUserData,
    
    // Computed values
    isAdmin: userRole === USER_ROLES.ADMIN,
    isSupervisor: userRole === USER_ROLES.SUPERVISOR || userRole === USER_ROLES.ADMIN,
    isTechnician: userRole === USER_ROLES.TECHNICIAN,
    fullName: user ? `${user.firstName} ${user.lastName}` : null,
    initials: user ? `${user.firstName?.[0] || ''}${user.lastName?.[0] || ''}` : null
  };
};

/**
 * Permission-based authorization hook
 * Checks if user has specific permissions
 */
export const usePermissions = () => {
  const permissions = useSelector(selectUserPermissions);
  const userRole = useSelector(selectUserRole);

  const hasPermission = useCallback((permission) => {
    if (!permissions) return false;
    
    // Admin has all permissions
    if (userRole === USER_ROLES.ADMIN) return true;
    
    return permissions[permission] === true;
  }, [permissions, userRole]);

  const hasAnyPermission = useCallback((permissionList) => {
    return permissionList.some(permission => hasPermission(permission));
  }, [hasPermission]);

  const hasAllPermissions = useCallback((permissionList) => {
    return permissionList.every(permission => hasPermission(permission));
  }, [hasPermission]);

  const hasRole = useCallback((role) => {
    if (Array.isArray(role)) {
      return role.includes(userRole);
    }
    return userRole === role;
  }, [userRole]);

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole,
    permissions,
    // Specific permissions for easy access
    canUploadSamples: hasPermission('canUploadSamples'),
    canViewAllTests: hasPermission('canViewAllTests') || userRole === USER_ROLES.SUPERVISOR || userRole === USER_ROLES.ADMIN,
    canDeleteTests: hasPermission('canDeleteTests') || userRole === USER_ROLES.ADMIN,
    canManageUsers: hasPermission('canManageUsers') || userRole === USER_ROLES.ADMIN,
    canExportReports: hasPermission('canExportReports')
  };
};

/**
 * Route protection hook
 * Handles authentication requirements for protected routes
 */
export const useRouteProtection = (requiredRole = null, requiredPermission = null) => {
  const { isAuthenticated, isLoading } = useAuth();
  const { hasPermission, hasRole } = usePermissions();
  const navigate = useNavigate();
  const location = useLocation();
  const [isAuthorized, setIsAuthorized] = useState(false);

  useEffect(() => {
    if (isLoading) return;

    if (!isAuthenticated) {
      // Not logged in - redirect to login
      navigate(ROUTES.LOGIN, { 
        state: { from: location },
        replace: true 
      });
      return;
    }

    // Check role requirements
    if (requiredRole && !hasRole(requiredRole)) {
      setIsAuthorized(false);
      return;
    }

    // Check permission requirements
    if (requiredPermission && !hasPermission(requiredPermission)) {
      setIsAuthorized(false);
      return;
    }

    setIsAuthorized(true);
  }, [
    isAuthenticated, 
    isLoading, 
    requiredRole, 
    requiredPermission, 
    hasRole, 
    hasPermission, 
    navigate, 
    location
  ]);

  return {
    isAuthorized,
    isLoading,
    isAuthenticated
  };
};

/**
 * Session management hook
 * Handles session timeout and warnings
 */
export const useSessionManagement = () => {
  const { sessionTimeRemaining, isAuthenticated, logout } = useAuth();
  const [showWarning, setShowWarning] = useState(false);
  const [timeoutId, setTimeoutId] = useState(null);

  useEffect(() => {
    if (!isAuthenticated || !sessionTimeRemaining) {
      setShowWarning(false);
      if (timeoutId) {
        if (Array.isArray(timeoutId)) {
          timeoutId.forEach(id => clearTimeout(id));
        } else {
          clearTimeout(timeoutId);
        }
        setTimeoutId(null);
      }
      return;
    }

    // Show warning 5 minutes before expiry
    const warningTime = sessionTimeRemaining - 300000; // 5 minutes
    
    if (warningTime > 0) {
      const warningTimeoutId = setTimeout(() => {
        setShowWarning(true);
      }, warningTime);

      // Auto-logout at expiry
      const logoutTimeoutId = setTimeout(() => {
        logout();
      }, sessionTimeRemaining);

      setTimeoutId([warningTimeoutId, logoutTimeoutId]);

      return () => {
        clearTimeout(warningTimeoutId);
        clearTimeout(logoutTimeoutId);
      };
    } else if (sessionTimeRemaining <= 300000) {
      // Less than 5 minutes remaining
      setShowWarning(true);
    }
  }, [sessionTimeRemaining, isAuthenticated, logout, timeoutId]);

  const extendSession = useCallback(async () => {
    try {
      // Make a simple API call to extend session
      await apiService.auth.getCurrentUser();
      setShowWarning(false);
    } catch (error) {
      console.error('Failed to extend session:', error);
    }
  }, []);

  const formatTimeRemaining = useCallback((ms) => {
    if (!ms) return '';
    
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }, []);

  return {
    showWarning,
    timeRemaining: sessionTimeRemaining,
    timeRemainingFormatted: formatTimeRemaining(sessionTimeRemaining),
    extendSession,
    dismissWarning: () => setShowWarning(false)
  };
};

/**
 * API error handling hook
 * Handles common API errors and authentication issues
 */
export const useApiErrorHandler = () => {
  const { logout } = useAuth();

  const handleApiError = useCallback((error) => {
    if (!error) return null;

    // Handle authentication errors
    if (error.message?.includes('Authentication required') || 
        error.message?.includes('Invalid token') ||
        error.message?.includes('Token has expired')) {
      logout();
      return 'Your session has expired. Please log in again.';
    }

    // Handle authorization errors
    if (error.message?.includes('Access denied') || 
        error.message?.includes('Forbidden')) {
      return 'You do not have permission to perform this action.';
    }

    // Handle network errors
    if (error.message?.includes('Network error') || 
        error.message?.includes('Failed to fetch')) {
      return 'Network error. Please check your connection and try again.';
    }

    // Handle validation errors
    if (error.message?.includes('validation')) {
      return 'Please check your input and try again.';
    }

    // Return the original error message or a generic message
    return error.message || 'An unexpected error occurred. Please try again.';
  }, [logout]);

  return { handleApiError };
};

/**
 * User preferences hook
 * Manages user-specific settings and preferences
 */
export const useUserPreferences = () => {
  const { user } = useAuth();
  const [preferences, setPreferences] = useState({
    theme: 'light',
    language: 'en',
    notifications: true,
    autoRefresh: true,
    pageSize: 20
  });

  // Load preferences from localStorage
  useEffect(() => {
    if (user) {
      const stored = localStorage.getItem(`userPrefs_${user._id}`);
      if (stored) {
        try {
          setPreferences(prev => ({ ...prev, ...JSON.parse(stored) }));
        } catch (error) {
          console.error('Failed to parse user preferences:', error);
        }
      }
    }
  }, [user]);

  const updatePreference = useCallback((key, value) => {
    setPreferences(prev => {
      const updated = { ...prev, [key]: value };
      
      // Save to localStorage
      if (user) {
        localStorage.setItem(`userPrefs_${user._id}`, JSON.stringify(updated));
      }
      
      return updated;
    });
  }, [user]);

  const resetPreferences = useCallback(() => {
    const defaults = {
      theme: 'light',
      language: 'en',
      notifications: true,
      autoRefresh: true,
      pageSize: 20
    };
    
    setPreferences(defaults);
    
    if (user) {
      localStorage.setItem(`userPrefs_${user._id}`, JSON.stringify(defaults));
    }
  }, [user]);

  return {
    preferences,
    updatePreference,
    resetPreferences
  };
};

/**
 * Real-time notifications hook
 * Handles WebSocket notifications and updates
 */
export const useRealTimeNotifications = () => {
  const { user, isAuthenticated } = useAuth();
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);

  // Mock implementation - replace with actual WebSocket integration
  useEffect(() => {
    if (!isAuthenticated || !user) return;

    // Mock notifications
    const mockNotifications = [
      {
        id: 1,
        type: 'test_completed',
        title: 'Test Analysis Complete',
        message: 'Test MT-2024-001 analysis has been completed',
        timestamp: new Date(),
        read: false
      }
    ];

    setNotifications(mockNotifications);
    setUnreadCount(mockNotifications.filter(n => !n.read).length);
  }, [user, isAuthenticated]);

  const markAsRead = useCallback((notificationId) => {
    setNotifications(prev => 
      prev.map(n => 
        n.id === notificationId ? { ...n, read: true } : n
      )
    );
    setUnreadCount(prev => Math.max(0, prev - 1));
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    setUnreadCount(0);
  }, []);

  const clearNotification = useCallback((notificationId) => {
    setNotifications(prev => prev.filter(n => n.id !== notificationId));
    setUnreadCount(prev => {
      const notification = notifications.find(n => n.id === notificationId);
      return notification && !notification.read ? prev - 1 : prev;
    });
  }, [notifications]);

  return {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    clearNotification
  };
};
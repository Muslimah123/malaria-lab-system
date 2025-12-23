// src/hooks/useDashboard.js
import { useState, useEffect, useCallback } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import apiService from '../services/api';
import socketService from '../services/socketService';
import { selectUser, selectIsAuthenticated } from '../store/slices/authSlice';
import { showErrorToast, showSuccessToast } from '../store/slices/notificationsSlice';

const useDashboard = () => {
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  const isAuthenticated = useSelector(selectIsAuthenticated);

  // Local state
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [socketConnected, setSocketConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async (showLoading = false) => {
    try {
      if (showLoading) setLoading(true);
      setError(null);

      const response = await apiService.analytics.getDashboard();
      
      if (response.success) {
        setDashboardData(response.data);
        setLastUpdated(new Date());
      } else {
        throw new Error(response.message || 'Failed to fetch dashboard data');
      }
    } catch (err) {
      console.error('Dashboard fetch error:', err);
      const errorMessage = apiService.formatError(err);
      setError(errorMessage);
      dispatch(showErrorToast(errorMessage));
    } finally {
      setLoading(false);
    }
  }, [dispatch]);

  // Initialize socket connection
  const initializeSocket = useCallback(() => {
    const token = localStorage.getItem('authToken');
    
    if (!token || !isAuthenticated) return;

    try {
      socketService.safeConnect(token);
      
      socketService.socket?.on('connect', () => {
        setSocketConnected(true);
        console.log('Dashboard socket connected');
      });

      socketService.socket?.on('disconnect', () => {
        setSocketConnected(false);
        console.log('Dashboard socket disconnected');
      });

      // Subscribe to test updates
      socketService.subscribeToTestUpdates((testUpdate) => {
        handleTestUpdate(testUpdate);
      });

      // Subscribe to system notifications
      socketService.subscribeToNotifications(user?.id, (notification) => {
        handleNotification(notification);
      });

      // Listen for dashboard-specific events
      socketService.on('dashboard_update', (data) => {
        setDashboardData(prevData => ({
          ...prevData,
          ...data
        }));
        setLastUpdated(new Date());
      });

    } catch (err) {
      console.error('Socket initialization error:', err);
    }
  }, [isAuthenticated, user?.id]);

  // Handle real-time test updates
  const handleTestUpdate = useCallback((testUpdate) => {
    // Update dashboard stats when tests are completed
    if (testUpdate.status === 'completed') {
      fetchDashboardData(false); // Refresh without showing loading
      
      // Show notifications for critical results
      if (testUpdate.result === 'positive' && testUpdate.severity === 'severe') {
        dispatch(showErrorToast(
          `🚨 Critical: Severe malaria detected in ${testUpdate.patientName}`,
          { 
            actionUrl: `/results/${testUpdate.testId}`,
            duration: 10000 
          }
        ));
      } else if (testUpdate.result === 'positive') {
        dispatch(showSuccessToast(
          `⚠️ Positive malaria result for ${testUpdate.patientName}`,
          { 
            actionUrl: `/results/${testUpdate.testId}`,
            duration: 7000 
          }
        ));
      }
    }

    // Update recent tests list
    setDashboardData(prevData => {
      if (!prevData) return prevData;

      const updatedRecentTests = prevData.recentTests?.map(test => 
        test.id === testUpdate.testId ? { ...test, ...testUpdate } : test
      ) || [];

      return {
        ...prevData,
        recentTests: updatedRecentTests
      };
    });
  }, [dispatch, fetchDashboardData]);

  // Handle notifications
  const handleNotification = useCallback((notification) => {
    // Add to urgent alerts if critical
    if (notification.severity === 'urgent' || notification.severity === 'critical') {
      setDashboardData(prevData => {
        if (!prevData) return prevData;

        const newAlert = {
          id: Date.now(),
          title: notification.title,
          message: notification.message,
          severity: notification.severity,
          timeAgo: 'Just now',
          patientName: notification.patientName,
          actionUrl: notification.actionUrl
        };

        return {
          ...prevData,
          urgentAlerts: [newAlert, ...(prevData.urgentAlerts || [])].slice(0, 5)
        };
      });
    }

    // Show toast notification
    if (notification.severity === 'critical') {
      dispatch(showErrorToast(notification.message));
    } else {
      dispatch(showSuccessToast(notification.message));
    }
  }, [dispatch]);

  // Refresh data
  const refresh = useCallback(() => {
    fetchDashboardData(true);
  }, [fetchDashboardData]);

  // Clear error
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Cleanup
  const cleanup = useCallback(() => {
    if (socketService.isConnected()) {
      socketService.disconnect();
    }
  }, []);

  // Initialize on mount
  useEffect(() => {
    if (isAuthenticated) {
      fetchDashboardData(true);
      initializeSocket();
    }

    return cleanup;
  }, [isAuthenticated, fetchDashboardData, initializeSocket, cleanup]);

  // Auto-refresh every 5 minutes
  useEffect(() => {
    if (!isAuthenticated) return;

    const interval = setInterval(() => {
      fetchDashboardData(false);
    }, 5 * 60 * 1000); // 5 minutes

    return () => clearInterval(interval);
  }, [isAuthenticated, fetchDashboardData]);

  // Computed values
  const stats = dashboardData ? [
    { 
      title: "Today's Tests", 
      value: dashboardData.todayTests || 0, 
      change: dashboardData.todayChange || "+0%", 
      trend: "up",
      icon: 'Microscope',
      color: "bg-blue-500"
    },
    { 
      title: "Positive Results", 
      value: dashboardData.positiveToday || 0, 
      change: dashboardData.positiveChange || "+0%", 
      trend: dashboardData.positiveChange?.includes('-') ? "down" : "up",
      icon: 'AlertTriangle',
      color: "bg-red-500"
    },
    { 
      title: "Pending Review", 
      value: dashboardData.pendingReview || 0, 
      change: dashboardData.pendingChange || "+0%", 
      trend: "up",
      icon: 'Clock',
      color: "bg-yellow-500"
    },
    { 
      title: "Active Patients", 
      value: dashboardData.activePatients || 0, 
      change: dashboardData.patientsChange || "+0%", 
      trend: "up",
      icon: 'Users',
      color: "bg-green-500"
    }
  ] : [];

  const recentTests = dashboardData?.recentTests || [];
  const urgentAlerts = dashboardData?.urgentAlerts || [];
  const systemStatus = {
    api: dashboardData?.systemStatus?.api !== false,
    diagnosis: dashboardData?.systemStatus?.diagnosis !== false,
    database: dashboardData?.systemStatus?.database !== false,
    realtime: socketConnected
  };

  return {
    // Data
    dashboardData,
    stats,
    recentTests,
    urgentAlerts,
    systemStatus,
    
    // State
    loading,
    error,
    socketConnected,
    lastUpdated,
    
    // Actions
    refresh,
    clearError,
    fetchDashboardData,
    
    // Computed
    hasUrgentAlerts: urgentAlerts.length > 0,
    allSystemsOperational: Object.values(systemStatus).every(status => status),
    isRealTimeEnabled: socketConnected
  };
};

export default useDashboard;
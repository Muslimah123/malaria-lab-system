import { createSlice } from '@reduxjs/toolkit';
import { NOTIFICATION_TYPES } from '../../utils/constants';

// Initial state
const initialState = {
  notifications: [],
  toasts: [],
  unreadCount: 0,
  systemAlerts: [],
  preferences: {
    showToasts: true,
    soundEnabled: true,
    emailNotifications: true,
    pushNotifications: true,
    positiveResultAlerts: true,
    systemMaintenanceAlerts: true,
  },
};

// Notifications slice
const notificationsSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    // Add a new notification
    addNotification: (state, action) => {
      const notification = {
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString(),
        read: false,
        ...action.payload,
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
      
      // Keep only the last 100 notifications
      if (state.notifications.length > 100) {
        state.notifications = state.notifications.slice(0, 100);
      }
    },

    // Add a toast notification
    addToast: (state, action) => {
      const toast = {
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString(),
        autoHide: true,
        duration: 5000,
        ...action.payload,
      };
      
      state.toasts.push(toast);
      
      // Keep only the last 5 toasts
      if (state.toasts.length > 5) {
        state.toasts = state.toasts.slice(-5);
      }
    },

    // Remove a toast
    removeToast: (state, action) => {
      const toastId = action.payload;
      state.toasts = state.toasts.filter(toast => toast.id !== toastId);
    },

    // Clear all toasts
    clearToasts: (state) => {
      state.toasts = [];
    },

    // Mark notification as read
    markAsRead: (state, action) => {
      const notificationId = action.payload;
      const notification = state.notifications.find(n => n.id === notificationId);
      
      if (notification && !notification.read) {
        notification.read = true;
        state.unreadCount = Math.max(0, state.unreadCount - 1);
      }
    },

    // Mark all notifications as read
    markAllAsRead: (state) => {
      state.notifications.forEach(notification => {
        notification.read = true;
      });
      state.unreadCount = 0;
    },

    // Remove a notification
    removeNotification: (state, action) => {
      const notificationId = action.payload;
      const notificationIndex = state.notifications.findIndex(n => n.id === notificationId);
      
      if (notificationIndex !== -1) {
        const notification = state.notifications[notificationIndex];
        if (!notification.read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
        state.notifications.splice(notificationIndex, 1);
      }
    },

    // Clear all notifications
    clearAllNotifications: (state) => {
      state.notifications = [];
      state.unreadCount = 0;
    },

    // Add system alert
    addSystemAlert: (state, action) => {
      const alert = {
        id: Date.now() + Math.random(),
        timestamp: new Date().toISOString(),
        dismissed: false,
        ...action.payload,
      };
      
      state.systemAlerts.unshift(alert);
      
      // Keep only the last 10 system alerts
      if (state.systemAlerts.length > 10) {
        state.systemAlerts = state.systemAlerts.slice(0, 10);
      }
    },

    // Dismiss system alert
    dismissSystemAlert: (state, action) => {
      const alertId = action.payload;
      const alert = state.systemAlerts.find(a => a.id === alertId);
      
      if (alert) {
        alert.dismissed = true;
      }
    },

    // Update notification preferences
    updatePreferences: (state, action) => {
      state.preferences = { ...state.preferences, ...action.payload };
    },

    // Handle socket notifications
    handleSocketNotification: (state, action) => {
      const { type, data } = action.payload;
      
      switch (type) {
        case 'diagnosis:positiveResult':
          if (state.preferences.positiveResultAlerts) {
            const notification = {
              type: NOTIFICATION_TYPES.WARNING,
              title: 'Positive Malaria Result',
              message: `Test ${data.testId} shows positive malaria diagnosis`,
              data: data,
              actionUrl: `/results/${data.testId}`,
              priority: 'high',
              category: 'medical',
            };
            
            notificationsSlice.caseReducers.addNotification(state, { payload: notification });
            
            if (state.preferences.showToasts) {
              notificationsSlice.caseReducers.addToast(state, { 
                payload: {
                  ...notification,
                  duration: 10000, // Show longer for critical alerts
                }
              });
            }
          }
          break;
          
        case 'upload:processingCompleted':
          const completedNotification = {
            type: NOTIFICATION_TYPES.SUCCESS,
            title: 'Processing Complete',
            message: `Analysis completed for test ${data.testId}`,
            data: data,
            actionUrl: `/results/${data.testId}`,
            category: 'upload',
          };
          
          notificationsSlice.caseReducers.addNotification(state, { payload: completedNotification });
          
          if (state.preferences.showToasts) {
            notificationsSlice.caseReducers.addToast(state, { payload: completedNotification });
          }
          break;
          
        case 'upload:processingFailed':
          const failedNotification = {
            type: NOTIFICATION_TYPES.ERROR,
            title: 'Processing Failed',
            message: `Analysis failed for test ${data.testId}: ${data.error}`,
            data: data,
            actionUrl: `/upload`,
            category: 'upload',
          };
          
          notificationsSlice.caseReducers.addNotification(state, { payload: failedNotification });
          
          if (state.preferences.showToasts) {
            notificationsSlice.caseReducers.addToast(state, { payload: failedNotification });
          }
          break;
          
        case 'test:assigned':
          const assignedNotification = {
            type: NOTIFICATION_TYPES.INFO,
            title: 'Test Assigned',
            message: `Test ${data.testId} has been assigned to you`,
            data: data,
            actionUrl: `/history`,
            category: 'assignment',
          };
          
          notificationsSlice.caseReducers.addNotification(state, { payload: assignedNotification });
          
          if (state.preferences.showToasts) {
            notificationsSlice.caseReducers.addToast(state, { payload: assignedNotification });
          }
          break;
          
        case 'system:alert':
          if (state.preferences.systemMaintenanceAlerts) {
            notificationsSlice.caseReducers.addSystemAlert(state, { payload: data });
          }
          break;
          
        default:
          break;
      }
    },
  },
});

// Export actions
export const {
  addNotification,
  addToast,
  removeToast,
  clearToasts,
  markAsRead,
  markAllAsRead,
  removeNotification,
  clearAllNotifications,
  addSystemAlert,
  dismissSystemAlert,
  updatePreferences,
  handleSocketNotification,
} = notificationsSlice.actions;

// Selectors
export const selectNotifications = (state) => state.notifications.notifications;
export const selectToasts = (state) => state.notifications.toasts;
export const selectUnreadCount = (state) => state.notifications.unreadCount;
export const selectSystemAlerts = (state) => state.notifications.systemAlerts;
export const selectNotificationPreferences = (state) => state.notifications.preferences;

// Get unread notifications
export const selectUnreadNotifications = (state) => {
  return state.notifications.notifications.filter(notification => !notification.read);
};

// Get notifications by category
export const selectNotificationsByCategory = (category) => (state) => {
  return state.notifications.notifications.filter(notification => notification.category === category);
};

// Get recent notifications (last 24 hours)
export const selectRecentNotifications = (state) => {
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  return state.notifications.notifications.filter(notification => 
    new Date(notification.timestamp) > twentyFourHoursAgo
  );
};

// Get active system alerts (not dismissed)
export const selectActiveSystemAlerts = (state) => {
  return state.notifications.systemAlerts.filter(alert => !alert.dismissed);
};

// Utility action creators
export const showSuccessToast = (message, options = {}) => 
  addToast({
    type: NOTIFICATION_TYPES.SUCCESS,
    title: 'Success',
    message,
    ...options,
  });

export const showErrorToast = (message, options = {}) => 
  addToast({
    type: NOTIFICATION_TYPES.ERROR,
    title: 'Error',
    message,
    duration: 8000, // Show errors longer
    ...options,
  });

export const showWarningToast = (message, options = {}) => 
  addToast({
    type: NOTIFICATION_TYPES.WARNING,
    title: 'Warning',
    message,
    ...options,
  });

export const showInfoToast = (message, options = {}) => 
  addToast({
    type: NOTIFICATION_TYPES.INFO,
    title: 'Info',
    message,
    ...options,
  });

// Export reducer
export default notificationsSlice.reducer;
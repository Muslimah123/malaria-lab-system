// Middleware to handle WebSocket connections and events
// This middleware listens for authentication actions to connect/disconnect the socket
// and sets up event listeners for various real-time updates

import socketService from '../../services/socketService';
import { handleSocketUpdate } from '../slices/uploadsSlice';
import { handleSocketNotification } from '../slices/notificationsSlice';
import { login, logout } from '../slices/authSlice';

const socketMiddleware = (store) => (next) => (action) => {
  const result = next(action);
  
  // Handle authentication events
  if (action.type === login.fulfilled.type) {
    // Connect socket when user logs in
    socketService.connect();
    
    // Set up socket event listeners
    setupSocketListeners(store);
  }
  
  if (action.type === logout.fulfilled.type || action.type === logout.rejected.type) {
    // Disconnect socket when user logs out
    socketService.disconnect();
  }
  
  return result;
};

const setupSocketListeners = (store) => {
  const { dispatch } = store;
  
  // Connection events
  socketService.on('connected', () => {
    console.log('Socket connected successfully');
    // You could dispatch a connection status action here
  });
  
  socketService.on('disconnected', (reason) => {
    console.log('Socket disconnected:', reason);
    // You could dispatch a disconnection status action here
  });
  
  socketService.on('connectionFailed', (error) => {
    console.error('Socket connection failed:', error);
    // You could show an error notification here
  });
  
  socketService.on('reconnected', (attemptNumber) => {
    console.log('Socket reconnected after', attemptNumber, 'attempts');
    // You could show a success notification here
  });

  // ✅ NEW: Handle heartbeat and reconnection events
  socketService.on('heartbeat_response', (data) => {
    console.log('Heartbeat response received:', data);
  });

  socketService.on('reconnect', (attemptNumber) => {
    console.log('Socket reconnected after', attemptNumber, 'attempts');
    // Dispatch reconnection success action
    dispatch({ type: 'socket/reconnected', payload: { attemptNumber } });
  });

  socketService.on('reconnect_failed', () => {
    console.error('Socket reconnection failed after all attempts');
    // Dispatch reconnection failure action
    dispatch({ type: 'socket/reconnect_failed' });
  });
  
  // Upload events
  socketService.on('uploadProgress', (data) => {
    dispatch(handleSocketUpdate({
      type: 'upload:progress',
      data
    }));
  });
  
  socketService.on('fileUploaded', (data) => {
    dispatch(handleSocketUpdate({
      type: 'upload:fileUploaded',
      data
    }));
  });
  
  socketService.on('processingStarted', (data) => {
    // ✅ NEW: Track processing session for fallback completion checking
    if (data.sessionId) {
      socketService.trackProcessingSession(data.sessionId);
    }
    
    dispatch(handleSocketUpdate({
      type: 'upload:processingStarted',
      data
    }));
  });
  
  socketService.on('processingProgress', (data) => {
    dispatch(handleSocketUpdate({
      type: 'upload:processingProgress',
      data
    }));
  });
  
  socketService.on('processingCompleted', (data) => {
    // ✅ NEW: Stop tracking processing session
    if (data.sessionId) {
      socketService.stopTrackingProcessingSession(data.sessionId);
    }
    
    dispatch(handleSocketUpdate({
      type: 'upload:processingCompleted',
      data
    }));
    
    // Also send notification
    dispatch(handleSocketNotification({
      type: 'upload:processingCompleted',
      data
    }));
  });
  
  socketService.on('processingFailed', (data) => {
    // ✅ NEW: Stop tracking processing session
    if (data.sessionId) {
      socketService.stopTrackingProcessingSession(data.sessionId);
    }
    
    dispatch(handleSocketUpdate({
      type: 'upload:processingFailed',
      data
    }));
    
    // Also send notification
    dispatch(handleSocketNotification({
      type: 'upload:processingFailed',
      data
    }));
  });

  // ✅ NEW: Handle fallback completion events
  socketService.on('processingCompleted', (data) => {
    if (data.viaFallback) {
      console.log('Processing completed via fallback mechanism:', data);
      // Update UI to show completion was detected via fallback
      dispatch(handleSocketUpdate({
        type: 'upload:processingCompleted',
        data: { ...data, source: 'fallback' }
      }));
    }
  });
  
  // Test events
  socketService.on('test_update', (data) => {
    dispatch(handleSocketUpdate({
      type: 'test:update',
      data
    }));
  });
  
  // Notification events
  socketService.on('notification', (data) => {
    dispatch(handleSocketNotification({
      type: 'notification:received',
      data
    }));
  });
  
  // ✅ NEW: Handle socket health monitoring
  socketService.on('connect', () => {
    console.log('Socket health: Connected');
    dispatch({ type: 'socket/connected' });
  });
  
  socketService.on('disconnect', (reason) => {
    console.log('Socket health: Disconnected -', reason);
    dispatch({ type: 'socket/disconnected', payload: { reason } });
  });
  
  socketService.on('connect_error', (error) => {
    console.error('Socket health: Connection error -', error);
    dispatch({ type: 'socket/connection_error', payload: { error: error.message } });
  });
};

export default socketMiddleware;
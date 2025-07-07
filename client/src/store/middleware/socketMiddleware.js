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
  
  socketService.on('sessionUpdated', (data) => {
    dispatch(handleSocketUpdate({
      type: 'upload:sessionUpdated',
      data
    }));
  });
  
  // Test events
  socketService.on('testCreated', (data) => {
    // You could update tests slice here when it's created
    dispatch(handleSocketNotification({
      type: 'test:created',
      data
    }));
  });
  
  socketService.on('testUpdated', (data) => {
    // You could update tests slice here when it's created
    dispatch(handleSocketNotification({
      type: 'test:updated',
      data
    }));
  });
  
  socketService.on('testStatusChanged', (data) => {
    // You could update tests slice here when it's created
    dispatch(handleSocketNotification({
      type: 'test:statusChanged',
      data
    }));
  });
  
  // Diagnosis events
  socketService.on('diagnosisCompleted', (data) => {
    dispatch(handleSocketNotification({
      type: 'diagnosis:completed',
      data
    }));
  });
  
  socketService.on('diagnosisReviewed', (data) => {
    dispatch(handleSocketNotification({
      type: 'diagnosis:reviewed',
      data
    }));
  });
  
  socketService.on('positiveResult', (data) => {
    dispatch(handleSocketNotification({
      type: 'diagnosis:positiveResult',
      data
    }));
  });
  
  // General notifications
  socketService.on('notification', (data) => {
    dispatch(handleSocketNotification({
      type: 'notification',
      data
    }));
  });
  
  socketService.on('systemAlert', (data) => {
    dispatch(handleSocketNotification({
      type: 'system:alert',
      data
    }));
  });
};

export default socketMiddleware;
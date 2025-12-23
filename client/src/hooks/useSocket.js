// 📁 client/src/hooks/useSocket.js
// High-level real-time socket hook for your architecture with enhanced stability

import { useEffect, useRef, useCallback, useState } from 'react';
import socketService from '../services/socketService';

/**
 * useSocket - subscribe to a socket event and handle cleanup with enhanced stability
 * @param {string} event - event name to listen for
 * @param {Function} handler - callback to handle event data
 * @param {Array} deps - dependencies for the effect
 * @param {Object} options - additional options for enhanced functionality
 */
export function useSocket(event, handler, deps = [], options = {}) {
  const savedHandler = useRef();
  const eventRef = useRef(event);
  const optionsRef = useRef(options);
  
  savedHandler.current = handler;
  eventRef.current = event;
  optionsRef.current = options;

  // ✅ NEW: Enhanced event listener with error handling and reconnection
  const eventListener = useCallback((data) => {
    try {
      if (savedHandler.current) {
        savedHandler.current(data);
      }
    } catch (error) {
      console.error(`🔌 Error in socket event listener for ${event}:`, error);
    }
  }, [event]);

  useEffect(() => {
    // ✅ NEW: Ensure socket is connected before listening
    const ensureConnection = async () => {
      try {
        if (!socketService.isConnected()) {
          console.log(`🔌 Socket not connected, attempting connection for event: ${event}`);
          await socketService.connect();
        }
      } catch (error) {
        console.error(`🔌 Failed to connect socket for event ${event}:`, error);
      }
    };

    ensureConnection();

    // ✅ ENHANCED: Register event listener with reconnection handling
    socketService.on(event, eventListener);
    
    // ✅ NEW: Handle socket reconnection for this event
    const handleReconnect = () => {
      console.log(`🔌 Re-registering listener for event ${event} after reconnection`);
      socketService.on(event, eventListener);
    };

    // Listen for reconnection events
    socketService.on('reconnect', handleReconnect);
    
    return () => {
      socketService.off(event, eventListener);
      socketService.off('reconnect', handleReconnect);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [event, ...deps]);

  // ✅ NEW: Return connection status and utility functions
  return {
    isConnected: socketService.isConnected(),
    isConnecting: socketService.isConnecting(),
    connectionStatus: socketService.getConnectionStatus(),
    // Utility functions
    connect: socketService.connect.bind(socketService),
    disconnect: socketService.disconnect.bind(socketService),
    emit: socketService.emit.bind(socketService),
    testConnection: socketService.testConnection.bind(socketService)
  };
}

/**
 * ✅ NEW: useSocketConnection - Hook for managing socket connection lifecycle
 */
export function useSocketConnection() {
  const [connectionStatus, setConnectionStatus] = useState({
    connected: false,
    connecting: false,
    error: null
  });

  useEffect(() => {
    const updateStatus = () => {
      setConnectionStatus({
        connected: socketService.isConnected(),
        connecting: socketService.isConnecting(),
        error: null
      });
    };

    // Initial status
    updateStatus();

    // Listen for connection changes
    const events = ['connect', 'disconnect', 'connect_error', 'reconnect', 'reconnect_failed'];
    
    events.forEach(event => {
      socketService.on(event, updateStatus);
    });

    return () => {
      events.forEach(event => {
        socketService.off(event, updateStatus);
      });
    };
  }, []);

  const connect = useCallback(async (token) => {
    try {
      setConnectionStatus(prev => ({ ...prev, connecting: true, error: null }));
      await socketService.connect(token);
      setConnectionStatus(prev => ({ ...prev, connecting: false, connected: true }));
    } catch (error) {
      setConnectionStatus(prev => ({ 
        ...prev, 
        connecting: false, 
        error: error.message 
      }));
      throw error;
    }
  }, []);

  const disconnect = useCallback(() => {
    socketService.disconnect();
    setConnectionStatus({ connected: false, connecting: false, error: null });
  }, []);

  return {
    ...connectionStatus,
    connect,
    disconnect,
    socketService
  };
}

/**
 * ✅ NEW: useProcessingSession - Hook for tracking long-running processing operations
 */
export function useProcessingSession(sessionId) {
  const [sessionStatus, setSessionStatus] = useState({
    isProcessing: false,
    progress: 0,
    status: 'idle',
    result: null,
    error: null,
    viaFallback: false
  });

  useEffect(() => {
    if (!sessionId) return;

    // Start tracking the processing session
    socketService.trackProcessingSession(sessionId);

    // Listen for processing events
    const events = {
      'processingStarted': (data) => {
        if (data.sessionId === sessionId) {
          setSessionStatus(prev => ({
            ...prev,
            isProcessing: true,
            status: 'processing',
            progress: 0,
            error: null
          }));
        }
      },
      'processingProgress': (data) => {
        if (data.sessionId === sessionId) {
          setSessionStatus(prev => ({
            ...prev,
            progress: data.progress || prev.progress
          }));
        }
      },
      'processingCompleted': (data) => {
        if (data.sessionId === sessionId) {
          setSessionStatus(prev => ({
            ...prev,
            isProcessing: false,
            status: 'completed',
            progress: 100,
            result: data.result,
            viaFallback: data.viaFallback || false
          }));
          // Stop tracking this session
          socketService.stopTrackingProcessingSession(sessionId);
        }
      },
      'processingFailed': (data) => {
        if (data.sessionId === sessionId) {
          setSessionStatus(prev => ({
            ...prev,
            isProcessing: false,
            status: 'failed',
            error: data.error || 'Processing failed',
            viaFallback: data.viaFallback || false
          }));
          // Stop tracking this session
          socketService.stopTrackingProcessingSession(sessionId);
        }
      }
    };

    // Register all event listeners
    Object.entries(events).forEach(([event, handler]) => {
      socketService.on(event, handler);
    });

    return () => {
      // Cleanup event listeners
      Object.entries(events).forEach(([event, handler]) => {
        socketService.off(event, handler);
      });
      // Stop tracking session
      socketService.stopTrackingProcessingSession(sessionId);
    };
  }, [sessionId]);

  return sessionStatus;
}

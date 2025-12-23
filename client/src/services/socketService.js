
// 📁 client/src/services/socketService.js - ENHANCED VERSION
import { io } from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

class SocketService {
  constructor() {
    this.socket = null;
    this.connected = false;
    this.onConnect = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 2000;
    this.connectionPromise = null; // Track ongoing connection attempts
    this.eventListeners = new Map(); // Track event listeners
    this.tokenRefreshTimer = null; // Track token refresh timer
    this.heartbeatInterval = null; // Track heartbeat interval
    this.lastActivity = Date.now(); // Track last activity
    this.processingSessions = new Set(); // Track active processing sessions
    this.fallbackCheckInterval = null; // Track fallback completion checks
  }

  setOnConnect(callback) {
    this.onConnect = callback;
  }

  /**
   * ✅ ENHANCED: Connect with proper authentication, token refresh, and retry logic
   * Now prevents multiple simultaneous connection attempts and handles token expiration
   */
  async connect(token = null) {
    try {
      // Get token if not provided
      if (!token) {
        token = this.getValidToken();
      }

      if (!token) {
        console.warn('🔌 No valid auth token available for socket connection');
        throw new Error('No valid authentication token available');
      }

      // If already connected, return existing connection
      if (this.socket && this.connected) {
        console.log('🔌 Socket already connected, reusing existing connection');
        return this.socket;
      }

      // If connection attempt is in progress, wait for it
      if (this.connectionPromise) {
        console.log('🔌 Connection attempt already in progress, waiting...');
        return this.connectionPromise;
      }

      console.log('🔌 Connecting socket with authentication...');

      // Create connection promise
      this.connectionPromise = this._createConnection(token);
      
      try {
        const result = await this.connectionPromise;
        // Start token refresh monitoring and heartbeat
        this.startTokenRefreshMonitoring();
        this.startHeartbeat();
        return result;
      } finally {
        this.connectionPromise = null; // Clear the promise
      }

    } catch (error) {
      console.error('🔌 Socket connection failed:', error);
      this.connectionPromise = null; // Clear the promise on error
      throw error;
    }
  }

  /**
   * ✅ NEW: Get valid token with automatic refresh if needed
   */
  getValidToken() {
    const token = localStorage.getItem('authToken');
    if (!token) return null;

    try {
      // Check if token is expired or about to expire (within 5 minutes)
      const payload = JSON.parse(atob(token.split('.')[1]));
      const now = Date.now() / 1000;
      const timeUntilExpiry = payload.exp - now;
      
      if (timeUntilExpiry < 300) { // Less than 5 minutes
        console.log('🔌 Token expiring soon, attempting refresh...');
        this.refreshTokenAndReconnect();
        return null;
      }
      
      return token;
    } catch (error) {
      console.error('🔌 Error parsing token:', error);
      return null;
    }
  }

  /**
   * ✅ NEW: Refresh token and reconnect socket
   */
  async refreshTokenAndReconnect() {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      // Call refresh endpoint
      const response = await fetch(`${SOCKET_URL}/api/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken }),
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      if (data.success && data.data.token) {
        localStorage.setItem('authToken', data.data.token);
        if (data.data.refreshToken) {
          localStorage.setItem('refreshToken', data.data.refreshToken);
        }
        
        // Reconnect socket with new token
        if (this.socket) {
          this.disconnect();
        }
        await this.connect(data.data.token);
        
        console.log('🔌 Token refreshed and socket reconnected successfully');
      }
    } catch (error) {
      console.error('🔌 Token refresh failed:', error);
      // Redirect to login if refresh fails
      localStorage.clear();
      window.location.href = '/login';
    }
  }

  /**
   * ✅ NEW: Start token refresh monitoring
   */
  startTokenRefreshMonitoring() {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
    }

    // Check token every 2 minutes
    this.tokenRefreshTimer = setInterval(() => {
      const token = this.getValidToken();
      if (!token && this.connected) {
        console.log('🔌 Token expired during monitoring, attempting refresh...');
        this.refreshTokenAndReconnect();
      }
    }, 120000); // 2 minutes
  }

  /**
   * ✅ NEW: Start heartbeat monitoring
   */
  startHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    // Send heartbeat every 15 seconds
    this.heartbeatInterval = setInterval(() => {
      if (this.socket && this.connected) {
        this.socket.emit('heartbeat', { timestamp: Date.now() });
        this.lastActivity = Date.now();
      }
    }, 15000); // 15 seconds
  }

  /**
   * ✅ NEW: Track processing session for fallback completion checking
   */
  trackProcessingSession(sessionId) {
    this.processingSessions.add(sessionId);
    console.log(`🔌 Tracking processing session: ${sessionId}`);
    
    // Start fallback completion checking
    this.startFallbackCompletionCheck(sessionId);
  }

  /**
   * ✅ NEW: Stop tracking processing session
   */
  stopTrackingProcessingSession(sessionId) {
    this.processingSessions.delete(sessionId);
    console.log(`🔌 Stopped tracking processing session: ${sessionId}`);
  }

  /**
   * ✅ NEW: Start fallback completion checking for long operations
   */
  startFallbackCompletionCheck(sessionId) {
    // Check completion status every 30 seconds as fallback
    const checkInterval = setInterval(async () => {
      if (!this.processingSessions.has(sessionId)) {
        clearInterval(checkInterval);
        return;
      }

      try {
        // Check completion status via HTTP API as fallback
        const response = await fetch(`${SOCKET_URL}/api/diagnosis/status/${sessionId}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          if (data.status === 'completed' || data.status === 'failed') {
            console.log(`🔌 Fallback completion check: Session ${sessionId} ${data.status}`);
            
            // Emit completion event locally
            this.emitLocalEvent('processingCompleted', {
              sessionId,
              status: data.status,
              result: data.result,
              viaFallback: true
            });
            
            // Stop tracking this session
            this.stopTrackingProcessingSession(sessionId);
            clearInterval(checkInterval);
          }
        }
      } catch (error) {
        console.warn(`🔌 Fallback completion check failed for session ${sessionId}:`, error);
      }
    }, 30000); // 30 seconds

    // Store interval reference for cleanup
    this.fallbackCheckInterval = checkInterval;
  }

  /**
   * ✅ NEW: Emit event locally when socket is disconnected
   */
  emitLocalEvent(event, data) {
    const listeners = this.eventListeners.get(event) || [];
    listeners.forEach(listener => {
      try {
        listener(data);
      } catch (error) {
        console.error(`🔌 Error in local event listener for ${event}:`, error);
      }
    });
  }

  /**
   * Internal method to create the actual connection
   */
  _createConnection(token) {
    // Disconnect existing connection if any
    if (this.socket) {
      console.log('🔌 Disconnecting existing socket connection');
      this.disconnect();
    }

    this.socket = io(SOCKET_URL, {
      auth: { token },
      transports: ['websocket', 'polling'],
      autoConnect: true,
      timeout: 60000, // ✅ INCREASED: 60 seconds to match Axios timeout
      forceNew: false, // Changed to false to prevent new connections
      pingTimeout: 60000, // ✅ INCREASED: 60s ping timeout to match YOLO processing time
      pingInterval: 30000, // ✅ INCREASED: 30s ping interval for better stability
      upgrade: true, // ✅ NEW: Allow transport upgrade
      rememberUpgrade: true, // ✅ NEW: Remember transport preference
      reconnection: true, // ✅ NEW: Enable automatic reconnection
      reconnectionAttempts: 5, // ✅ NEW: Limit reconnection attempts
      reconnectionDelay: 1000, // ✅ NEW: Start with 1 second delay
      reconnectionDelayMax: 5000, // ✅ NEW: Max 5 second delay
      maxReconnectionAttempts: 5 // ✅ NEW: Max attempts
    });

    // Return promise that resolves when connected
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, 10000);

      this.socket.on('connect', () => {
        clearTimeout(timeout);
        this.connected = true;
        this.reconnectAttempts = 0;
        this.lastConnectionAttempt = new Date();
        console.log('🔌 Socket connected successfully');
        
        if (typeof this.onConnect === 'function') {
          this.onConnect();
        }
        
        resolve(this.socket);
      });

      this.socket.on('connect_error', (error) => {
        clearTimeout(timeout);
        console.error('🔌 Socket connection error:', error);
        this.connected = false;
        reject(error);
      });

      this.socket.on('disconnect', (reason) => {
        this.connected = false;
        console.log('🔌 Socket disconnected:', reason);
        
        // Auto-reconnect on unexpected disconnection
        if (reason !== 'io client disconnect') {
          this.handleReconnect(token);
        }
      });

      this.socket.on('connected', (data) => {
        console.log('🔌 Socket authentication confirmed:', data);
      });

      this.socket.on('error', (error) => {
        console.error('🔌 Socket error:', error);
      });

      // ✅ NEW: Handle heartbeat response
      this.socket.on('heartbeat_response', (data) => {
        this.lastActivity = Date.now();
        console.log('🔌 Heartbeat response received:', data);
      });

      // ✅ NEW: Handle reconnection events
      this.socket.on('reconnect', (attemptNumber) => {
        console.log(`🔌 Socket reconnected after ${attemptNumber} attempts`);
        this.connected = true;
        this.reconnectAttempts = 0;
        
        // Re-authenticate after reconnection
        this.reauthenticateAfterReconnect();
      });

      this.socket.on('reconnect_attempt', (attemptNumber) => {
        console.log(`🔌 Socket reconnection attempt ${attemptNumber}`);
      });

      this.socket.on('reconnect_error', (error) => {
        console.error('🔌 Socket reconnection error:', error);
      });

      this.socket.on('reconnect_failed', () => {
        console.error('🔌 Socket reconnection failed after all attempts');
        this.connected = false;
      });
    });
  }

  /**
   * ✅ NEW: Re-authenticate after reconnection
   */
  async reauthenticateAfterReconnect() {
    try {
      const token = this.getValidToken();
      if (token) {
        this.socket.emit('reauthenticate', { token });
        console.log('🔌 Re-authenticating after reconnection...');
      }
    } catch (error) {
      console.error('🔌 Re-authentication failed:', error);
    }
  }

  /**
   * ✅ ENHANCED: Handle automatic reconnection with exponential backoff
   */
  async handleReconnect(token) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('🔌 Max reconnection attempts reached, waiting before allowing new attempts');
      // Wait 30 seconds before allowing new connection attempts
      setTimeout(() => {
        this.reconnectAttempts = 0;
        console.log('🔌 Reconnection attempts reset, can try again');
      }, 30000);
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), 30000);
    
    console.log(`🔌 Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms`);
    
    setTimeout(async () => {
      try {
        await this.connect(token);
      } catch (error) {
        console.error('🔌 Reconnection failed:', error);
      }
    }, delay);
  }

  /**
   * ✅ ENHANCED: Connect with retry logic and token refresh
   */
  async connectWithRetry(token = null, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`🔌 Socket connection attempt ${attempt}/${maxRetries}`);
        await this.connect(token);
        return; // Success
      } catch (error) {
        console.error(`🔌 Connection attempt ${attempt} failed:`, error);
        
        // Try token refresh on authentication errors
        if (error.message.includes('Authentication') || error.message.includes('token')) {
          try {
            await this.refreshTokenAndReconnect();
            return; // Success after token refresh
          } catch (refreshError) {
            console.error('🔌 Token refresh failed during retry:', refreshError);
          }
        }
        
        if (attempt === maxRetries) {
          throw new Error(`Failed to connect after ${maxRetries} attempts: ${error.message}`);
        }
        
        // Wait before retry with exponential backoff
        await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt - 1)));
      }
    }
  }

  disconnect() {
    if (this.socket) {
      console.log('🔌 Disconnecting socket...');
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
      this.reconnectAttempts = 0;
      this.connectionPromise = null;
      
      // Clear all timers and intervals
      if (this.tokenRefreshTimer) {
        clearInterval(this.tokenRefreshTimer);
        this.tokenRefreshTimer = null;
      }
      
      if (this.heartbeatInterval) {
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = null;
      }
      
      if (this.fallbackCheckInterval) {
        clearInterval(this.fallbackCheckInterval);
        this.fallbackCheckInterval = null;
      }
      
      // Clear all event listeners
      this.eventListeners.clear();
      console.log('🔌 Socket disconnected and cleaned up');
    }
  }

  on(event, callback) {
    if (this.socket) {
      console.log(`🔌 Registering listener for event: ${event}`);
      this.socket.on(event, callback);
      console.log(`🔌 Successfully registered listener for event: ${event}`);
    } else {
      console.warn(`🔌 Cannot listen for event ${event} - socket not connected`);
    }
  }

  off(event, callback) {
    if (this.socket) {
      if (callback) {
        this.socket.off(event, callback);
      } else {
        this.socket.off(event);
      }
    }
  }

  /**
   * Check if socket is ready for operations (connected and authenticated)
   */
  isReady() {
    return this.isConnected() && this.socket && this.socket.connected;
  }

  emit(event, data) {
    if (this.isReady()) {
      this.socket.emit(event, data);
    } else {
      console.warn(`🔌 Cannot emit event ${event} - socket not ready. State:`, {
        isConnected: this.isConnected(),
        hasSocket: !!this.socket,
        socketConnected: this.socket?.connected
      });
    }
  }

  isConnected() {
    return this.connected && this.socket && this.socket.connected;
  }

  /**
   * Check if a connection attempt is in progress
   */
  isConnecting() {
    return this.connectionPromise !== null;
  }

  /**
   * Wait for socket to be fully ready (connected and authenticated)
   */
  async waitForReady(timeout = 10000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      
      const checkReady = () => {
        if (this.isConnected()) {
          resolve(true);
          return;
        }
        
        if (Date.now() - startTime > timeout) {
          reject(new Error('Socket ready timeout'));
          return;
        }
        
        setTimeout(checkReady, 100);
      };
      
      checkReady();
    });
  }

  /**
   * Safe connect method that prevents duplicate connections
   * Use this instead of connect() in components
   */
  async safeConnect(token = null) {
    // If already connected and healthy, do nothing
    if (this.isConnectionHealthy()) {
      console.log('🔌 Socket already connected and healthy, reusing existing connection');
      return this.socket;
    }

    // If connecting, wait for existing attempt
    if (this.isConnecting()) {
      console.log('🔌 Connection already in progress, waiting...');
      return this.connectionPromise;
    }

    // Check if we have a recent failed connection attempt
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('🔌 Max reconnection attempts reached, waiting before retry...');
      // Wait a bit before allowing new connection attempts
      await new Promise(resolve => setTimeout(resolve, 30000)); // 30 seconds
      this.reconnectAttempts = 0;
    }

    // Connect if not connected
    const result = await this.connect(token);
    
    // Wait for socket to be fully ready
    try {
      await this.waitForReady(5000);
      console.log('🔌 Socket is fully ready');
    } catch (error) {
      console.warn('🔌 Socket connection timeout, but continuing:', error);
    }
    
    return result;
  }

  /**
   * ✅ IMPROVED: Subscribe to upload session updates
   */
  subscribeToUploadSession(sessionId, callback) {
    if (!this.isConnected()) {
      console.warn('🔌 Cannot subscribe to upload session - socket not connected');
      return;
    }

    console.log('🔌 Subscribing to upload session:', sessionId);
    
    // Join the session room
    this.socket.emit('joinUploadSession', sessionId);
    
    // Listen for upload events - these will be handled by Redux in the component
    // but we can still log them here for debugging
    const events = [
      'upload:processingProgress',
      'upload:processingCompleted',
      'upload:processingFailed',
      'upload:fileUploaded',
      'upload:sessionUpdated',
      'upload-session-joined',
      'upload-session-left'
    ];

    events.forEach(eventName => {
      this.on(eventName, (data) => {
        console.log(`🔌 Received ${eventName}:`, data);
        if (callback) callback({ type: eventName, data });
      });
    });

    // Confirm session joined
    this.on('upload-session-joined', (data) => {
      console.log('🔌 Successfully joined upload session:', data);
    });
  }

  /**
   * ✅ IMPROVED: Unsubscribe from upload session
   */
  unsubscribeFromUploadSession(sessionId, callback) {
    if (!this.isConnected()) {
      console.warn('🔌 Cannot unsubscribe from upload session - socket not connected');
      return;
    }

    console.log('🔌 Unsubscribing from upload session:', sessionId);
    
    // Leave the session room
    this.socket.emit('leaveUploadSession', sessionId);
    
    // Remove upload event listeners
    const events = [
      'upload:processingProgress',
      'upload:processingCompleted', 
      'upload:processingFailed',
      'upload:fileUploaded',
      'upload:sessionUpdated',
      'upload-session-joined',
      'upload-session-left'
    ];

    events.forEach(eventName => {
      this.off(eventName, callback);
    });
  }

  /**
   * Subscribe to test updates
   */
  subscribeToTestUpdates(callback) {
    if (this.socket) {
      this.on('test_update', callback);
    }
  }

  unsubscribeFromTestUpdates(callback) {
    if (this.socket) {
      this.off('test_update', callback);
    }
  }

  /**
   * Subscribe to notifications
   */
  subscribeToNotifications(userId, callback) {
    if (this.socket) {
      this.socket.emit('joinNotifications', userId);
      this.on('notification', callback);
    }
  }

  unsubscribeFromNotifications(userId, callback) {
    if (this.socket) {
      this.socket.emit('leaveNotifications', userId);
      this.off('notification', callback);
    }
  }

  /**
   * ✅ NEW: Get connection status with debug info
   */
  getConnectionStatus() {
    return {
      connected: this.connected,
      socketConnected: this.socket?.connected || false,
      reconnectAttempts: this.reconnectAttempts,
      socketId: this.socket?.id || null
    };
  }

  /**
   * ✅ NEW: Test connection with ping
   */
  testConnection() {
    return new Promise((resolve) => {
      if (!this.isConnected()) {
        resolve(false);
        return;
      }

      const timeout = setTimeout(() => {
        resolve(false);
      }, 5000);

      this.socket.once('pong', () => {
        clearTimeout(timeout);
        resolve(true);
      });

      this.socket.emit('ping');
    });
  }

  /**
   * Check if connection is healthy and should be maintained
   */
  isConnectionHealthy() {
    // Check if we have a socket object and it's connected
    if (!this.socket || !this.socket.connected) {
      return false;
    }

    // Check if our internal state is consistent
    if (!this.connected) {
      return false;
    }

    return true;
  }

  /**
   * Get connection statistics for debugging
   */
  getConnectionStats() {
    return {
      connected: this.connected,
      socketConnected: this.socket?.connected || false,
      reconnectAttempts: this.reconnectAttempts,
      maxReconnectAttempts: this.maxReconnectAttempts,
      isConnecting: this.isConnecting(),
      connectionPromise: this.connectionPromise !== null,
      socketId: this.socket?.id || null,
      lastConnectionAttempt: this.lastConnectionAttempt || null
    };
  }

  /**
   * Log connection status for debugging
   */
  logConnectionStatus() {
    const stats = this.getConnectionStats();
    console.log('🔌 Socket Connection Status:', stats);
    
    if (this.socket) {
      console.log('🔌 Socket Details:', {
        id: this.socket.id,
        connected: this.socket.connected,
        disconnected: this.socket.disconnected,
        transport: this.socket.io?.engine?.transport?.name || 'unknown'
      });
    }
  }
}

export default new SocketService();


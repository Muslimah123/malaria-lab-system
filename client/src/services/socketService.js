
// 📁 client/src/services/socketService.js - COMPLETE REPLACEMENT
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
  }

  setOnConnect(callback) {
    this.onConnect = callback;
  }

  /**
   * ✅ IMPROVED: Connect with proper authentication and retry logic
   */
  async connect(token = null) {
    try {
      // Get token if not provided
      if (!token) {
        token = localStorage.getItem('authToken');
      }

      if (!token) {
        console.warn('🔌 No auth token available for socket connection');
        throw new Error('No authentication token available');
      }

      // Disconnect existing connection
      if (this.socket && this.connected) {
        console.log('🔌 Disconnecting existing socket connection');
        this.disconnect();
      }

      console.log('🔌 Connecting socket with authentication...');

      this.socket = io(SOCKET_URL, {
        auth: { token }, // ✅ Pass token for backend authentication
        transports: ['websocket', 'polling'],
        autoConnect: true,
        timeout: 10000,
        forceNew: true
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
      });

    } catch (error) {
      console.error('🔌 Socket connection failed:', error);
      throw error;
    }
  }

  /**
   * ✅ NEW: Handle automatic reconnection
   */
  async handleReconnect(token) {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('🔌 Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * this.reconnectAttempts;
    
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
   * ✅ IMPROVED: Connect with retry logic
   */
  async connectWithRetry(token = null, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`🔌 Socket connection attempt ${attempt}/${maxRetries}`);
        await this.connect(token);
        return; // Success
      } catch (error) {
        console.error(`🔌 Connection attempt ${attempt} failed:`, error);
        
        if (attempt === maxRetries) {
          throw new Error(`Failed to connect after ${maxRetries} attempts: ${error.message}`);
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
      this.reconnectAttempts = 0;
      console.log('🔌 Socket disconnected');
    }
  }

  on(event, callback) {
    if (this.socket) {
      this.socket.on(event, callback);
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

  emit(event, data) {
    if (this.socket && this.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn(`🔌 Cannot emit event ${event} - socket not connected`);
    }
  }

  isConnected() {
    return this.connected && this.socket && this.socket.connected;
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
}

export default new SocketService();
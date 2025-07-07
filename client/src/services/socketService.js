// 📁 client/src/services/socketService.js
// Simplified socket service without missing constants

class SocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.connected = false;
  }

  connect(token = null) {
    try {
      // In a real implementation, you'd connect to your WebSocket server
      // For now, we'll just simulate the connection
      console.log('Socket service connected (simulated)');
      this.connected = true;
      
      // Simulate connection success
      setTimeout(() => {
        this.emit('connect', { status: 'connected' });
      }, 100);
      
    } catch (error) {
      console.error('Socket connection failed:', error);
      this.connected = false;
    }
  }

  disconnect() {
    try {
      if (this.socket) {
        this.socket.close();
      }
      this.connected = false;
      this.listeners.clear();
      console.log('Socket disconnected');
    } catch (error) {
      console.error('Socket disconnect error:', error);
    }
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
  }

  off(event, callback) {
    if (this.listeners.has(event)) {
      const callbacks = this.listeners.get(event);
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      const callbacks = this.listeners.get(event);
      callbacks.forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in socket event handler for ${event}:`, error);
        }
      });
    }
  }

  // Upload-specific methods
  subscribeToUploadSession(sessionId) {
    console.log(`Subscribed to upload session: ${sessionId}`);
    // Simulate upload progress updates
    this.simulateUploadProgress(sessionId);
  }

  unsubscribeFromUploadSession(sessionId) {
    console.log(`Unsubscribed from upload session: ${sessionId}`);
  }

  // Simulate upload progress for demo purposes
  simulateUploadProgress(sessionId) {
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 20;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        this.emit('upload_completed', { sessionId, progress });
      } else {
        this.emit('upload_progress', { sessionId, progress: Math.round(progress) });
      }
    }, 500);
  }

  // Test-specific methods
  subscribeToTestUpdates() {
    console.log('Subscribed to test updates');
  }

  unsubscribeFromTestUpdates() {
    console.log('Unsubscribed from test updates');
  }

  // Notification methods
  subscribeToNotifications(userId) {
    console.log(`Subscribed to notifications for user: ${userId}`);
  }

  unsubscribeFromNotifications(userId) {
    console.log(`Unsubscribed from notifications for user: ${userId}`);
  }

  // Check connection status
  isConnected() {
    return this.connected;
  }

  // Send data to server (mock implementation)
  send(event, data) {
    if (!this.connected) {
      console.warn('Socket not connected, cannot send data');
      return false;
    }
    
    console.log(`Sending socket event: ${event}`, data);
    return true;
  }
}

// Export singleton instance
export default new SocketService();
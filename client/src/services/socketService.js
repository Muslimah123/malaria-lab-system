// 📁 client/src/services/socketService.js
import { io } from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

class SocketService {
  constructor() {
    this.socket = null;
    this.connected = false;
    this.onConnect = null; // Optional callback for connect event
  }

  setOnConnect(callback) {
    this.onConnect = callback;
  }

  connect(token = null) {
    if (this.socket && this.connected) return;
    this.socket = io(SOCKET_URL, {
      auth: token ? { token } : undefined,
      transports: ['websocket', 'polling'],
      autoConnect: true,
    });

    this.socket.on('connect', () => {
      this.connected = true;
      if (typeof this.onConnect === 'function') {
        this.onConnect();
      }
    });

    this.socket.on('disconnect', () => {
      this.connected = false;
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
    }
  }

  on(event, callback) {
    if (this.socket) {
      this.socket.on(event, callback);
    }
  }

  off(event, callback) {
    if (this.socket) {
      this.socket.off(event, callback);
    }
  }

  emit(event, data) {
    if (this.socket) {
      this.socket.emit(event, data);
    }
  }

  isConnected() {
    return this.connected;
  }

  // Example: subscribe to upload session updates
  subscribeToUploadSession(sessionId, callback) {
    if (this.socket) {
      this.socket.emit('joinUploadSession', sessionId);
      this.on('upload_progress', callback);
    }
  }

  unsubscribeFromUploadSession(sessionId, callback) {
    if (this.socket) {
      this.socket.emit('leaveUploadSession', sessionId);
      this.off('upload_progress', callback);
    }
  }

  // Example: subscribe to test updates
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

  // Example: subscribe to notifications
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
}

export default new SocketService();
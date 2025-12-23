// server/src/socket/index.js
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { SOCKET_EVENTS, USER_ROLES } = require('../utils/constants');

class SocketService {
  constructor() {
    this.io = null;
    this.connectedUsers = new Map(); // userId -> Set of socketIds
    this.userSockets = new Map(); // socketId -> user info mapping
    this.rooms = new Map(); // room management
    this.uploadSessions = new Map(); // sessionId -> Set of socketIds
  }

  /**
   * Initialize Socket.io server
   */
  initialize(server) {
    // Initialize Socket.IO with authentication
    const io = new Server(server, {
      cors: {
        origin: process.env.CLIENT_URL || "http://localhost:3000",
        methods: ["GET", "POST"],
        credentials: true
      },
      pingTimeout: 60000, // ✅ INCREASED: 60 seconds to match YOLO processing time
      pingInterval: 30000, // ✅ INCREASED: 30 seconds for better stability
      transports: ['websocket', 'polling'],
      allowEIO3: true
    });

    this.io = io; // Assign the initialized io to this.io
    this.setupMiddleware();
    this.setupEventHandlers();
    this.setupHeartbeat();

    logger.info('Socket.io server initialized');
    return this.io;
  }

  /**
   * Setup authentication middleware
   */
  setupMiddleware() {
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token;
        
        if (!token) {
          logger.warn('Socket connection attempted without token');
          return next(new Error('Authentication token missing'));
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from database
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
          return next(new Error('User not found or inactive'));
        }

        // Attach user to socket
        socket.user = user;
        socket.userId = user._id.toString();
        
        logger.debug(`Socket authenticated for user: ${user.username}`);
        next();

      } catch (error) {
        logger.warn('Socket authentication failed:', error.message);
        next(new Error('Authentication failed'));
      }
    });

    // Rate limiting middleware
    this.io.use((socket, next) => {
      const userId = socket.userId;
      const now = Date.now();
      
      // Check connection rate limit
      if (!this.checkConnectionRateLimit(userId, now)) {
        return next(new Error('Connection rate limit exceeded'));
      }
      
      next();
    });
  }

  /**
   * Setup main event handlers
   */
  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      this.handleConnection(socket);
      
      // Setup event listeners
      socket.on('disconnect', (reason) => {
        this.handleDisconnection(socket, reason);
      });

      socket.on('join-room', (roomName) => {
        this.handleJoinRoom(socket, roomName);
      });

      socket.on('leave-room', (roomName) => {
        this.handleLeaveRoom(socket, roomName);
      });

      // ✅ NEW: Upload session handlers
      socket.on('joinUploadSession', (sessionId) => {
        this.handleUploadSessionJoin(socket, sessionId);
      });

      socket.on('leaveUploadSession', (sessionId) => {
        this.handleUploadSessionLeave(socket, sessionId);
      });

      socket.on('test-subscribe', (testId) => {
        this.handleTestSubscription(socket, testId);
      });

      socket.on('ping', () => {
        socket.emit('pong', { timestamp: Date.now() });
      });

      // Handle errors
      socket.on('error', (error) => {
        logger.error('Socket error:', error);
      });
    });
  }

  /**
   * Handle new connection
   */
  handleConnection(socket) {
    const user = socket.user;
    const userId = user._id.toString();

    // Store connection mapping
    if (!this.connectedUsers.has(userId)) {
      this.connectedUsers.set(userId, new Set());
    }
    this.connectedUsers.get(userId).add(socket.id);
    this.userSockets.set(socket.id, {
      userId,
      username: user.username,
      role: user.role,
      connectedAt: new Date()
    });

    // Join user to role-based room
    socket.join(`role:${user.role}`);
    
    // Join user to personal room
    socket.join(`user:${userId}`);

    // Emit connection confirmation
    socket.emit('connected', {
      userId,
      username: user.username,
      role: user.role,
      timestamp: new Date().toISOString()
    });

    // Notify supervisors about technician connections
    if (user.role === USER_ROLES.TECHNICIAN) {
      this.emitToRole(USER_ROLES.SUPERVISOR, 'technician-online', {
        userId,
        username: user.username,
        timestamp: new Date().toISOString()
      });
    }

    // Log connection
    auditService.log({
      action: 'socket_connected',
      userId,
      userInfo: { username: user.username, email: user.email, role: user.role },
      resourceType: 'system',
      resourceId: 'socket_connection',
      details: {
        socketId: socket.id,
        userAgent: socket.handshake.headers['user-agent']
      },
      status: 'success',
      riskLevel: 'low'
    });

    logger.info(`User connected via socket: ${user.username} (${socket.id})`);
  }

  /**
   * Handle disconnection
   */
  handleDisconnection(socket, reason) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (userInfo) {
      const { userId, username, role } = userInfo;

      // Remove from mappings
      const userSockets = this.connectedUsers.get(userId);
      if (userSockets) {
        userSockets.delete(socket.id);
        if (userSockets.size === 0) {
          this.connectedUsers.delete(userId);
        }
      }
      this.userSockets.delete(socket.id);

      // Remove from upload sessions
      this.uploadSessions.forEach((sockets, sessionId) => {
        if (sockets.has(socket.id)) {
          sockets.delete(socket.id);
          if (sockets.size === 0) {
            this.uploadSessions.delete(sessionId);
          }
        }
      });

      // Notify supervisors about technician disconnections
      if (role === USER_ROLES.TECHNICIAN) {
        this.emitToRole(USER_ROLES.SUPERVISOR, 'technician-offline', {
          userId,
          username,
          timestamp: new Date().toISOString(),
          reason
        });
      }

      // Log disconnection
      auditService.log({
        action: 'socket_disconnected',
        userId,
        userInfo: { username, role },
        resourceType: 'system',
        resourceId: 'socket_connection',
        details: {
          socketId: socket.id,
          reason
        },
        status: 'success',
        riskLevel: 'low'
      });

      logger.info(`User disconnected: ${username} (${socket.id}) - Reason: ${reason}`);
    }
  }

  /**
   * ✅ NEW: Handle joining upload session
   */
  handleUploadSessionJoin(socket, sessionId) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (!userInfo) {
      logger.warn('Upload session join attempted without authenticated socket');
      return;
    }

    const roomName = `upload:${sessionId}`;
    socket.join(roomName);
    
    // Track upload session membership
    if (!this.uploadSessions.has(sessionId)) {
      this.uploadSessions.set(sessionId, new Set());
    }
    this.uploadSessions.get(sessionId).add(socket.id);

    // Track room membership
    if (!this.rooms.has(roomName)) {
      this.rooms.set(roomName, new Set());
    }
    this.rooms.get(roomName).add(socket.id);

    socket.emit('upload-session-joined', { sessionId });
    logger.info(`User ${userInfo.username} joined upload session: ${sessionId}`);
  }

  /**
   * ✅ NEW: Handle leaving upload session
   */
  handleUploadSessionLeave(socket, sessionId) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (!userInfo) return;

    const roomName = `upload:${sessionId}`;
    socket.leave(roomName);
    
    // Remove from upload session tracking
    if (this.uploadSessions.has(sessionId)) {
      this.uploadSessions.get(sessionId).delete(socket.id);
      
      // Clean up empty sessions
      if (this.uploadSessions.get(sessionId).size === 0) {
        this.uploadSessions.delete(sessionId);
      }
    }
    
    // Remove from room tracking
    if (this.rooms.has(roomName)) {
      this.rooms.get(roomName).delete(socket.id);
      
      // Clean up empty rooms
      if (this.rooms.get(roomName).size === 0) {
        this.rooms.delete(roomName);
      }
    }

    socket.emit('upload-session-left', { sessionId });
    logger.info(`User ${userInfo.username} left upload session: ${sessionId}`);
  }

  /**
   * Handle joining rooms
   */
  handleJoinRoom(socket, roomName) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (!userInfo) return;

    // Validate room access
    if (!this.canAccessRoom(userInfo, roomName)) {
      socket.emit('error', { message: 'Access denied to room' });
      return;
    }

    socket.join(roomName);
    
    // Track room membership
    if (!this.rooms.has(roomName)) {
      this.rooms.set(roomName, new Set());
    }
    this.rooms.get(roomName).add(socket.id);

    socket.emit('room-joined', { room: roomName });
    logger.debug(`User ${userInfo.username} joined room: ${roomName}`);
  }

  /**
   * Handle leaving rooms
   */
  handleLeaveRoom(socket, roomName) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (!userInfo) return;

    socket.leave(roomName);
    
    // Remove from room tracking
    if (this.rooms.has(roomName)) {
      this.rooms.get(roomName).delete(socket.id);
      
      // Clean up empty rooms
      if (this.rooms.get(roomName).size === 0) {
        this.rooms.delete(roomName);
      }
    }

    socket.emit('room-left', { room: roomName });
    logger.debug(`User ${userInfo.username} left room: ${roomName}`);
  }

  /**
   * Handle test subscription
   */
  handleTestSubscription(socket, testId) {
    const userInfo = this.userSockets.get(socket.id);
    
    if (!userInfo) return;

    const roomName = `test:${testId}`;
    socket.join(roomName);

    socket.emit('test-subscribed', { testId });
    logger.debug(`User ${userInfo.username} subscribed to test: ${testId}`);
  }

  /**
   * Check if user can access a room
   */
  canAccessRoom(userInfo, roomName) {
    const { role } = userInfo;

    // Admin can access all rooms
    if (role === USER_ROLES.ADMIN) {
      return true;
    }

    // Supervisor can access most rooms
    if (role === USER_ROLES.SUPERVISOR) {
      return !roomName.startsWith('admin:');
    }

    // Technician has limited access
    if (role === USER_ROLES.TECHNICIAN) {
      return roomName.startsWith('technician:') || 
             roomName.startsWith('test:') ||
             roomName.startsWith('upload:') ||
             roomName.startsWith('general:');
    }

    return false;
  }

  /**
   * Setup heartbeat to check connection health
   */
  setupHeartbeat() {
    setInterval(() => {
      this.io.emit('heartbeat', { timestamp: Date.now() });
    }, 30000); // Every 30 seconds
  }

  /**
   * Check connection rate limit
   */
  checkConnectionRateLimit(userId, timestamp) {
    // Simple rate limiting - max 5 connections per minute per user
    if (!this.connectionAttempts) {
      this.connectionAttempts = new Map();
    }

    const attempts = this.connectionAttempts.get(userId) || [];
    const recentAttempts = attempts.filter(time => timestamp - time < 60000);

    if (recentAttempts.length >= 5) {
      return false;
    }

    recentAttempts.push(timestamp);
    this.connectionAttempts.set(userId, recentAttempts);
    return true;
  }

  /**
   * Emit to all connected clients
   */
  emitToAll(event, data) {
    this.io.emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
    
    logger.debug(`Emitted ${event} to all clients`);
  }

  /**
   * Emit to specific user
   */
  emitToUser(userId, event, data) {
    const socketIds = this.connectedUsers.get(userId.toString());
    
    if (socketIds && socketIds.size > 0) {
      socketIds.forEach(socketId => {
        this.io.to(socketId).emit(event, {
          ...data,
          timestamp: new Date().toISOString()
        });
      });
      
      logger.debug(`Emitted ${event} to user ${userId} on ${socketIds.size} sockets`);
      return true;
    }
    
    logger.warn(`No active sockets found for user ${userId}`);
    return false;
  }

  /**
   * Emit to users with specific role
   */
  emitToRole(role, event, data) {
    this.io.to(`role:${role}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
    
    logger.debug(`Emitted ${event} to role ${role}`);
  }

  /**
   * Emit to specific room
   */
  emitToRoom(roomName, event, data) {
    this.io.to(roomName).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
    
    logger.debug(`Emitted ${event} to room ${roomName}`);
  }

  /**
   * ✅ NEW: Emit to upload session (both session room and user)
   */
  emitToUploadSession(sessionId, userId, event, data) {
    const roomName = `upload:${sessionId}`;
    let success = false;
    
    // Emit to session room (primary method)
    const sessionSockets = this.uploadSessions.get(sessionId);
    if (sessionSockets && sessionSockets.size > 0) {
      this.emitToRoom(roomName, event, data);
      success = true;
      logger.debug(`Emitted ${event} to upload session room ${sessionId} with ${sessionSockets.size} sockets`);
    }
    
    // Also emit to user directly (backup method)
    const userEmitSuccess = this.emitToUser(userId, event, data);
    if (userEmitSuccess) {
      success = true;
    }
    
    if (!success) {
      logger.warn(`Failed to emit ${event} to session ${sessionId} and user ${userId} - no active connections`);
    }
    
    return success;
  }

  /**
   * Broadcast test updates
   */
  broadcastTestUpdate(testId, updateType, data) {
    const event = `test:${updateType}`;
    const roomName = `test:${testId}`;
    
    this.emitToRoom(roomName, event, {
      testId,
      updateType,
      ...data
    });

    // Also emit to supervisors
    this.emitToRole(USER_ROLES.SUPERVISOR, event, {
      testId,
      updateType,
      ...data
    });
  }

  /**
   * Broadcast diagnosis updates
   */
  broadcastDiagnosisUpdate(testId, status, data) {
    const event = SOCKET_EVENTS.DIAGNOSIS_COMPLETED;
    
    // Emit to test subscribers
    this.emitToRoom(`test:${testId}`, event, {
      testId,
      status,
      ...data
    });

    // Emit to all supervisors for positive results
    if (status === 'POS') {
      this.emitToRole(USER_ROLES.SUPERVISOR, 'positive-result-alert', {
        testId,
        ...data
      });
    }
  }

  /**
   * Send notification to user
   */
  sendNotification(userId, notification) {
    this.emitToUser(userId, SOCKET_EVENTS.NOTIFICATION, {
      type: notification.type || 'info',
      title: notification.title,
      message: notification.message,
      data: notification.data,
      priority: notification.priority || 'normal'
    });
  }

  /**
   * Send alert to role
   */
  sendAlertToRole(role, alert) {
    this.emitToRole(role, SOCKET_EVENTS.ALERT, {
      type: alert.type || 'warning',
      title: alert.title,
      message: alert.message,
      data: alert.data,
      priority: alert.priority || 'high'
    });
  }

  /**
   * Get connection statistics
   */
  getConnectionStats() {
    const stats = {
      totalConnections: this.connectedUsers.size,
      usersByRole: {},
      rooms: {},
      uploadSessions: {},
      connectionsByTime: {}
    };

    // Count users by role
    this.userSockets.forEach(userInfo => {
      const role = userInfo.role;
      stats.usersByRole[role] = (stats.usersByRole[role] || 0) + 1;
    });

    // Count rooms
    this.rooms.forEach((users, roomName) => {
      stats.rooms[roomName] = users.size;
    });

    // Count upload sessions
    this.uploadSessions.forEach((sockets, sessionId) => {
      stats.uploadSessions[sessionId] = sockets.size;
    });

    return stats;
  }

  /**
   * Disconnect user
   */
  disconnectUser(userId, reason = 'Administrative disconnect') {
    const socketIds = this.connectedUsers.get(userId.toString());
    
    if (socketIds && socketIds.size > 0) {
      socketIds.forEach(socketId => {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit('force-disconnect', { reason });
          socket.disconnect(true);
        }
      });
      logger.info(`Forcibly disconnected user ${userId}: ${reason}`);
      return true;
    }
    
    return false;
  }

  /**
   * Broadcast system maintenance alert
   */
  broadcastMaintenanceAlert(maintenanceInfo) {
    this.emitToAll(SOCKET_EVENTS.ALERT, {
      type: 'maintenance',
      title: 'System Maintenance',
      message: maintenanceInfo.message,
      scheduledTime: maintenanceInfo.scheduledTime,
      duration: maintenanceInfo.duration,
      priority: 'high'
    });
  }

  /**
   * Check if user is online
   */
  isUserOnline(userId) {
    return this.connectedUsers.has(userId.toString());
  }

  /**
   * Get online users
   */
  getOnlineUsers() {
    const onlineUsers = [];
    
    this.userSockets.forEach((userInfo, socketId) => {
      onlineUsers.push({
        userId: userInfo.userId,
        username: userInfo.username,
        role: userInfo.role,
        connectedAt: userInfo.connectedAt,
        socketId
      });
    });

    return onlineUsers;
  }

  /**
   * Cleanup expired connections
   */
  cleanup() {
    const now = Date.now();
    const timeout = 5 * 60 * 1000; // 5 minutes

    this.userSockets.forEach((userInfo, socketId) => {
      const connectionAge = now - userInfo.connectedAt.getTime();
      
      if (connectionAge > timeout) {
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket && !socket.connected) {
          this.handleDisconnection(socket, 'cleanup');
        }
      }
    });
  }
}

// Create singleton instance
const socketService = new SocketService();

module.exports = { socketService, SocketService };
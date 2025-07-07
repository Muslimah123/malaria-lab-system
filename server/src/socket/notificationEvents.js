// 📁 server/src/socket/notificationEvents.js

module.exports = function notificationEvents(io, socket, user) {
  /**
   * Send a general notification to the user
   * @param {Object} notification - The notification data
   * @param {string} notification.title - Notification title
   * @param {string} notification.message - Notification message
   * @param {string} [notification.type='info'] - Type: info, success, warning, error
   */
  socket.on('sendNotification', (notification) => {
    const data = {
      title: notification.title || 'Notification',
      message: notification.message || '',
      type: notification.type || 'info',
      timestamp: new Date().toISOString(),
      from: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    };

    // Send to the specific user
    io.to(socket.id).emit('notification', data);
  });

  /**
   * Broadcast notification to all connected users (admin only)
   */
  socket.on('broadcastNotification', (notification) => {
    if (user.role === 'admin') {
      const data = {
        title: notification.title || 'Broadcast',
        message: notification.message || '',
        type: notification.type || 'info',
        timestamp: new Date().toISOString(),
        from: {
          id: user._id,
          username: user.username,
          role: user.role
        }
      };

      io.emit('notification', data);
    } else {
      io.to(socket.id).emit('notification', {
        title: 'Permission Denied',
        message: 'Only admin can broadcast notifications',
        type: 'error'
      });
    }
  });
};
// 📁 server/src/socket/testEvents.js

module.exports = function testEvents(io, socket, user) {
  /**
   * Listen for test progress updates from the client (e.g., lab device)
   */
  socket.on('testProgress', (data) => {
    const progressUpdate = {
      testId: data.testId,
      status: data.status,
      progress: data.progress || 0,
      updatedAt: new Date().toISOString()
    };

    // Broadcast to everyone who might be tracking this test
    io.emit('testProgressUpdate', progressUpdate);
  });

  /**
   * Notify when a test result is ready (broadcast to all users)
   */
  socket.on('testResultReady', (data) => {
    const resultNotification = {
      testId: data.testId,
      status: data.status,
      result: data.result,
      completedAt: new Date().toISOString()
    };

    io.emit('testResultNotification', resultNotification);
  });
};

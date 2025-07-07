// // server/src/config/socket.js
// const { Server } = require('socket.io');

// let io;

// /**
//  * Initializes Socket.io with the provided HTTP server.
//  */
// const initSocket = (server) => {
//   io = new Server(server, {
//     cors: {
//       origin: '*',
//       methods: ['GET', 'POST'],
//     },
//   });

//   io.on('connection', (socket) => {
//     console.log('Client connected:', socket.id);

//     // Example room join
//     socket.on('joinTestRoom', (testId) => {
//       socket.join(testId);
//       console.log(`Client ${socket.id} joined room for test: ${testId}`);
//     });

//     // Example notification
//     socket.on('sendNotification', (data) => {
//       console.log('Notification event:', data);
//       io.to(data.testId).emit('newNotification', data.message);
//     });

//     socket.on('disconnect', () => {
//       console.log('Client disconnected:', socket.id);
//     });
//   });
// };

// /**
//  * Returns the Socket.io instance.
//  */
// const getIO = () => {
//   if (!io) {
//     throw new Error('Socket.io not initialized. Call initSocket(server) first.');
//   }
//   return io;
// };

// module.exports = { initSocket, getIO };

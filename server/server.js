// 📁 server/server.js
const http = require('http');
const App = require('./src/app');
const { socketService } = require('./src/socket');
const logger = require('./src/utils/logger');

// Handle unhandled promise rejections and uncaught exceptions early
process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT EXCEPTION! 💥 Shutting down...', err);
  process.exit(1);
});

process.on('unhandledRejection', (err, promise) => {
  logger.error('UNHANDLED REJECTION! 💥 Shutting down...', err);
  process.exit(1);
});

class Server {
  constructor() {
    this.port = process.env.PORT || 5000;
    this.host = process.env.HOST || '0.0.0.0';
    this.app = null;
    this.server = null;
  }

  /**
   * Initialize and start the server
   */
  async start() {
    try {
      logger.startup({
        port: this.port,
        host: this.host,
        nodeEnv: process.env.NODE_ENV || 'development'
      });

      // Create Express application
      const appInstance = new App();
      
      // Initialize the application (database, etc.)
      await appInstance.initialize();
      
      this.app = appInstance.getInstance();

      // Create HTTP server
      this.server = http.createServer(this.app);

      // Initialize Socket.io
      socketService.initialize(this.server);
      logger.info('Socket.io initialized');

      // Setup global error handlers
      appInstance.setupGlobalErrorHandlers(this.server);

      // Setup graceful shutdown handlers
      this.setupShutdownHandlers(appInstance);

      // Start server
      await this.listen();

      // Setup periodic maintenance tasks
      this.setupMaintenanceTasks();

      logger.info(`🚀 Server successfully started`);
      logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`🌐 Server running on http://${this.host}:${this.port}`);
      logger.info(`📚 API Documentation: http://${this.host}:${this.port}/api-docs`);
      logger.info(`❤️ Health Check: http://${this.host}:${this.port}/health`);

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  /**
   * Start listening on the specified port
   */
  async listen() {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, this.host, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });

      // Handle server errors
      this.server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          logger.error(`Port ${this.port} is already in use`);
        } else if (error.code === 'EACCES') {
          logger.error(`Permission denied to bind to port ${this.port}`);
        } else {
          logger.error('Server error:', error);
        }
        reject(error);
      });
    });
  }

  /**
   * Setup graceful shutdown handlers
   */
  setupShutdownHandlers(appInstance) {
    const gracefulShutdown = async (signal) => {
      logger.info(`📴 Received ${signal}. Starting graceful shutdown...`);

      try {
        // Stop accepting new connections
        this.server.close(async (err) => {
          if (err) {
            logger.error('Error closing HTTP server:', err);
          } else {
            logger.info('HTTP server closed');
          }

          try {
            // Perform application cleanup
            await appInstance.gracefulShutdown();
            
            logger.shutdown(signal);
            process.exit(0);
          } catch (shutdownError) {
            logger.error('Error during graceful shutdown:', shutdownError);
            process.exit(1);
          }
        });

        // Force shutdown after timeout
        setTimeout(() => {
          logger.error('Forced shutdown due to timeout');
          process.exit(1);
        }, 30000); // 30 seconds timeout

      } catch (error) {
        logger.error('Error in shutdown handler:', error);
        process.exit(1);
      }
    };

    // Handle various shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // Nodemon restart

    // Handle Docker stop signals
    process.on('SIGQUIT', () => gracefulShutdown('SIGQUIT'));
  }

  /**
   * Setup periodic maintenance tasks
   */
  setupMaintenanceTasks() {
    // Memory monitoring
    this.setupMemoryMonitoring();

    // Socket cleanup
    this.setupSocketCleanup();

    // Log cleanup
    this.setupLogCleanup();

    // Health metrics
    this.setupHealthMetrics();

    logger.info('Periodic maintenance tasks initialized');
  }

  /**
   * Setup memory monitoring
   */
  setupMemoryMonitoring() {
    setInterval(() => {
      const memUsage = process.memoryUsage();
      const memUsageMB = {
        rss: Math.round(memUsage.rss / 1024 / 1024),
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
        external: Math.round(memUsage.external / 1024 / 1024)
      };

      // Log memory usage every hour
      const now = new Date();
      if (now.getMinutes() === 0 && now.getSeconds() < 30) {
        logger.system('memory_usage', memUsageMB);
      }

      // Warn about high memory usage
      if (memUsageMB.heapUsed > 800) { // 800MB threshold
        logger.warn('High memory usage detected', memUsageMB);
      }

      // Critical memory usage
      if (memUsageMB.heapUsed > 1500) { // 1.5GB threshold
        logger.error('Critical memory usage detected', memUsageMB);
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
          logger.info('Forced garbage collection');
        }
      }

    }, 60000); // Every minute
  }

  /**
   * Setup socket cleanup
   */
  setupSocketCleanup() {
    setInterval(() => {
      socketService.cleanup();
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Setup log cleanup
   */
  setupLogCleanup() {
    // Clean up old logs daily
    setInterval(() => {
      try {
        logger.cleanup();
      } catch (error) {
        logger.error('Log cleanup failed:', error);
      }
    }, 24 * 60 * 60 * 1000); // Every 24 hours
  }

  /**
   * Setup health metrics collection
   */
  setupHealthMetrics() {
    setInterval(async () => {
      try {
        // Collect basic metrics
        const metrics = {
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          connections: socketService.getConnectionStats(),
          environment: process.env.NODE_ENV || 'development'
        };

        // Log metrics (these could be sent to monitoring service)
        logger.system('health_metrics', metrics);

      } catch (error) {
        logger.error('Health metrics collection failed:', error);
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Get server information
   */
  getServerInfo() {
    return {
      port: this.port,
      host: this.host,
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      platform: process.platform,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      pid: process.pid
    };
  }

  /**
   * Stop the server
   */
  async stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

// Create and start server instance
const server = new Server();

// Handle process events
process.on('warning', (warning) => {
  logger.warn('Process warning:', {
    name: warning.name,
    message: warning.message,
    stack: warning.stack
  });
});

// Start the server
if (require.main === module) {
  server.start().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = server;
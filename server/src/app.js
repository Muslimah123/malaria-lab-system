// 📁 server/src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./config/swagger');

// Import middleware
const { errorHandler, notFoundHandler, requestDurationLogger } = require('./middleware/errorHandler');
const { validateEnvironment } = require('./middleware/validation');
const { generalLimiter, addRateLimitHeaders } = require('./middleware/rateLimit');
const logger = require('./utils/logger');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const patientRoutes = require('./routes/patients');
const testRoutes = require('./routes/tests');
const uploadRoutes = require('./routes/upload');
const diagnosisRoutes = require('./routes/diagnosis');
const reportRoutes = require('./routes/reports');
const integrationRoutes = require('./routes/integration');

class App {
  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  /**
   * Setup application middleware
   */
  setupMiddleware() {
    // Trust proxy for accurate IP addresses
    this.app.set('trust proxy', 1);

    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"]
        }
      },
      crossOriginEmbedderPolicy: false // Allow file uploads
    }));

    // CORS configuration
    this.app.use(cors({
      origin: this.getAllowedOrigins(),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']
    }));

    // Compression
    this.app.use(compression());

    // Request logging
    if (process.env.NODE_ENV === 'development') {
      this.app.use(morgan('dev'));
    } else {
      this.app.use(morgan('combined', {
        stream: {
          write: (message) => {
            logger.info(message.trim());
          }
        }
      }));
    }

    // Request duration logging
    this.app.use(requestDurationLogger);

    // Rate limiting
    this.app.use(generalLimiter);
    this.app.use(addRateLimitHeaders);

    // Body parsing
    this.app.use(express.json({ 
      limit: '10mb',
      verify: this.verifyJsonPayload
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: '10mb' 
    }));

    // Static file serving
    this.app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
    this.app.use('/public', express.static(path.join(__dirname, '../public')));

    // Add request ID for tracking
    this.app.use(logger.addRequestId);

    // Health check endpoint (before authentication)
    this.app.get('/health', this.healthCheck);
    this.app.get('/api/health', this.healthCheck);

    // API documentation
    this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }'
    }));

    // API status endpoint
    this.app.get('/api/status', this.getApiStatus);
  }

  /**
   * Setup application routes
   */
  setupRoutes() {
    const apiPrefix = '/api';

    // Authentication routes (no prefix for some)
    this.app.use('/api/auth', authRoutes);

    // API routes
    this.app.use(`${apiPrefix}/users`, userRoutes);
    this.app.use(`${apiPrefix}/patients`, patientRoutes);
    this.app.use(`${apiPrefix}/tests`, testRoutes);
    this.app.use(`${apiPrefix}/upload`, uploadRoutes);
    this.app.use(`${apiPrefix}/diagnosis`, diagnosisRoutes);
    this.app.use(`${apiPrefix}/reports`, reportRoutes);
    this.app.use(`${apiPrefix}/integration`, integrationRoutes);

    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        message: 'Malaria Lab System API',
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        documentation: '/api-docs',
        health: '/health',
        timestamp: new Date().toISOString()
      });
    });

    // API root
    this.app.get('/api', (req, res) => {
      res.json({
        message: 'Malaria Lab System API v1',
        endpoints: {
          auth: '/api/auth',
          users: '/api/users',
          patients: '/api/patients',
          tests: '/api/tests',
          upload: '/api/upload',
          diagnosis: '/api/diagnosis',
          reports: '/api/reports',
          integration: '/api/integration'
        },
        documentation: '/api-docs',
        version: '1.0.0'
      });
    });
  }

  /**
   * Setup error handling
   */
  setupErrorHandling() {
    // 404 handler
    this.app.use(notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);
  }

  /**
   * Get allowed CORS origins
   */
  getAllowedOrigins() {
    const origins = [
      process.env.FRONTEND_URL || 'http://localhost:3000',
      'http://localhost:3000', // Development fallback
      'http://localhost:3001', // Alternative development port
    ];

    // Add additional origins from environment
    if (process.env.ADDITIONAL_ORIGINS) {
      const additionalOrigins = process.env.ADDITIONAL_ORIGINS.split(',');
      origins.push(...additionalOrigins);
    }

    // In production, be more restrictive
    if (process.env.NODE_ENV === 'production') {
      return origins.filter(origin => !origin.includes('localhost'));
    }

    return origins;
  }

  /**
   * Verify JSON payload
   */
  verifyJsonPayload(req, res, buf, encoding) {
    try {
      JSON.parse(buf.toString(encoding));
    } catch (error) {
      logger.warn('Invalid JSON payload received:', {
        error: error.message,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      throw new Error('Invalid JSON');
    }
  }

  /**
   * Health check endpoint
   */
  async healthCheck(req, res) {
    try {
      const { databaseConfig } = require('./config/database');
      const diagnosisService = require('./services/diagnosisService');

      // Check database health
      const dbHealth = await databaseConfig.healthCheck();
      
      // Check Flask API health
      const flaskHealth = await diagnosisService.healthCheck();

      // Check system resources
      const memoryUsage = process.memoryUsage();
      const uptime = process.uptime();

      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: `${Math.floor(uptime / 60)} minutes`,
        environment: process.env.NODE_ENV || 'development',
        version: process.env.npm_package_version || '1.0.0',
        services: {
          database: {
            status: dbHealth.status,
            message: dbHealth.message
          },
          flaskAPI: {
            status: flaskHealth.status,
            available: flaskHealth.status === 'healthy'
          },
          memory: {
            used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
            external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`
          }
        }
      };

      // Determine overall health status
      if (dbHealth.status !== 'healthy') {
        health.status = 'unhealthy';
      } else if (flaskHealth.status !== 'healthy') {
        health.status = 'degraded';
      }

      const statusCode = health.status === 'healthy' ? 200 : 
                        health.status === 'degraded' ? 200 : 503;

      res.status(statusCode).json(health);

    } catch (error) {
      logger.error('Health check failed:', error);
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check failed'
      });
    }
  }

  /**
   * API status endpoint
   */
  async getApiStatus(req, res) {
    try {
      const { socketService } = require('./socket');
      
      const status = {
        api: 'online',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        version: process.env.npm_package_version || '1.0.0',
        features: {
          authentication: true,
          fileUpload: true,
          diagnosis: true,
          realTimeUpdates: !!socketService.io,
          reporting: true,
          audit: true
        },
        limits: {
          maxFileSize: '10MB',
          maxFilesPerUpload: 20,
          requestTimeout: '5 minutes'
        },
        documentation: '/api-docs'
      };

      res.json(status);

    } catch (error) {
      logger.error('API status check failed:', error);
      res.status(500).json({
        api: 'error',
        timestamp: new Date().toISOString(),
        error: 'Status check failed'
      });
    }
  }

  /**
   * Get Express application instance
   */
  getInstance() {
    return this.app;
  }

  /**
   * Validate environment and setup
   */
  validateSetup() {
    try {
      // Validate required environment variables
      validateEnvironment();
      
      logger.info('Application setup validation passed');
      return true;
    } catch (error) {
      logger.error('Application setup validation failed:', error);
      throw error;
    }
  }

  /**
   * Graceful shutdown
   */
  async gracefulShutdown() {
    logger.info('Starting graceful shutdown...');
    
    try {
      // Close database connection
      const mongoose = require('mongoose');
      await mongoose.connection.close();
      logger.info('Database connection closed');

      // Close socket connections
      const { socketService } = require('./socket');
      if (socketService.io) {
        socketService.io.close();
        logger.info('Socket.io server closed');
      }

      // Flush audit logs
      const auditService = require('./services/auditService');
      await auditService.flush();
      logger.info('Audit logs flushed');

      logger.info('Graceful shutdown completed');
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      throw error;
    }
  }

  /**
   * Setup global error handlers
   */
  setupGlobalErrorHandlers(server) {
    const { 
      handleUncaughtException, 
      handleUnhandledRejection,
      handleGracefulShutdown 
    } = require('./middleware/errorHandler');

    handleUncaughtException();
    handleUnhandledRejection(server);
    handleGracefulShutdown(server);
  }

  /**
   * Initialize application with all dependencies
   */
  async initialize() {
    try {
      // Validate setup
      this.validateSetup();

      // Initialize database
      const { initializeDatabase } = require('./config/database');
      await initializeDatabase();
      logger.info('Database initialized');

      // Test Flask API connection
      const diagnosisService = require('./services/diagnosisService');
      const apiTest = await diagnosisService.testApiConnection();
      if (apiTest.connection === 'successful') {
        logger.info('Flask API connection verified');
      } else {
        logger.warn('Flask API connection failed:', apiTest.error);
      }

      logger.info('Application initialized successfully');
      return true;

    } catch (error) {
      logger.error('Application initialization failed:', error);
      throw error;
    }
  }
}

module.exports = App;
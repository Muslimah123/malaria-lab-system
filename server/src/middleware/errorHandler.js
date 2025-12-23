// 📁 server/src/middleware/errorHandler.js
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');
const auditService = require('../services/auditService');

/**
 * Global error handling middleware
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error details
  logger.error('Error caught by global handler:', {
    error: error.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user: req.user?.username || 'anonymous',
    body: sanitizeBody(req.body),
    query: req.query,
    params: req.params
  });

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message).join(', ');
    error = new AppError(message, 400);
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = `Duplicate value for ${field}: ${value}. Please use another value.`;
    error = new AppError(message, 400);
  }

  // Mongoose ObjectId error
  if (err.name === 'CastError') {
    const message = `Invalid ${err.path}: ${err.value}`;
    error = new AppError(message, 400);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token', 401);
  }

  if (err.name === 'TokenExpiredError') {
    error = new AppError('Token expired', 401);
  }

  // Multer errors (handled elsewhere but just in case)
  if (err.code && err.code.startsWith('LIMIT_')) {
    error = new AppError(`Upload error: ${err.message}`, 400);
  }

  // MongoDB connection errors
  if (err.name === 'MongooseServerSelectionError') {
    error = new AppError('Database connection failed', 503);
  }

  // Redis connection errors
  if (err.code === 'ECONNREFUSED' && err.port === 6379) {
    error = new AppError('Cache service unavailable', 503);
  }

  // Network/timeout errors
  if (err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
    error = new AppError('External service unavailable', 503);
  }

  // File system errors
  if (err.code === 'ENOENT') {
    error = new AppError('File not found', 404);
  }

  if (err.code === 'EACCES') {
    error = new AppError('File access denied', 403);
  }

  // Memory/resource errors
  if (err.code === 'ENOMEM') {
    error = new AppError('Insufficient memory', 507);
  }

  // Default to AppError if not already
  if (!(error instanceof AppError)) {
    error = new AppError(error.message || 'Server Error', error.statusCode || 500);
  }

  // Log security-related errors to audit system
  if (error.statusCode === 401 || error.statusCode === 403) {
    auditService.log({
      action: 'security_error',
      userId: req.user?._id || 'anonymous',
      userInfo: req.user ? { username: req.user.username, email: req.user.email, role: req.user.role } : {},
      resourceType: 'system',
      resourceId: 'error_handler',
      details: {
        error: error.message,
        statusCode: error.statusCode,
        endpoint: req.originalUrl,
        method: req.method
      },
      requestInfo: {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        method: req.method,
        endpoint: req.originalUrl
      },
      status: 'failure',
      riskLevel: 'high'
    });
  }

  // Send error response
  res.status(error.statusCode).json({
    success: false,
    message: error.message,
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      error: err
    })
  });
};

/**
 * Handle 404 errors (route not found)
 */
const notFoundHandler = (req, res, next) => {
  const message = `Route ${req.originalUrl} not found`;
  
  logger.warn('404 Not Found:', {
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(404).json({
    success: false,
    message
  });
};

/**
 * Async error wrapper to catch async/await errors
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Validate required environment variables
 */
const validateEnvironment = () => {
  const requiredEnvVars = [
    'NODE_ENV',
    'PORT',
    'MONGODB_URI',
    'JWT_SECRET',
    'FLASK_API_URL'
  ];

  const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
  
  if (missing.length > 0) {
    throw new AppError(`Missing required environment variables: ${missing.join(', ')}`, 500);
  }
};

/**
 * Handle uncaught exceptions
 */
const handleUncaughtException = () => {
  process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT EXCEPTION! 💥 Shutting down...', err);
    
    // Log to audit system if possible
    try {
      auditService.log({
        action: 'uncaught_exception',
        userId: 'system',
        resourceType: 'system',
        resourceId: 'uncaught_exception',
        details: {
          error: err.message,
          stack: err.stack
        },
        status: 'failure',
        riskLevel: 'critical'
      });
    } catch (auditError) {
      logger.error('Failed to log uncaught exception to audit:', auditError);
    }

    process.exit(1);
  });
};

/**
 * Handle unhandled promise rejections
 */
const handleUnhandledRejection = (server) => {
  process.on('unhandledRejection', (err, promise) => {
    logger.error('UNHANDLED REJECTION! 💥 Shutting down...', err);
    
    // Log to audit system if possible
    try {
      auditService.log({
        action: 'unhandled_rejection',
        userId: 'system',
        resourceType: 'system',
        resourceId: 'unhandled_rejection',
        details: {
          error: err.message,
          stack: err.stack
        },
        status: 'failure',
        riskLevel: 'critical'
      });
    } catch (auditError) {
      logger.error('Failed to log unhandled rejection to audit:', auditError);
    }

    server.close(() => {
      process.exit(1);
    });
  });
};

/**
 * Handle graceful shutdown
 */
const handleGracefulShutdown = (server) => {
  const signals = ['SIGTERM', 'SIGINT'];
  
  signals.forEach(signal => {
    process.on(signal, () => {
      logger.info(`${signal} received. Shutting down gracefully...`);
      
      server.close((err) => {
        if (err) {
          logger.error('Error during graceful shutdown:', err);
          process.exit(1);
        }
        
        logger.info('Process terminated gracefully');
        process.exit(0);
      });
    });
  });
};

/**
 * Handle SIGTERM for container environments
 */
const handleSIGTERM = (server) => {
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    
    // Close server
    server.close(() => {
      logger.info('HTTP server closed.');
      
      // Close database connections
      const mongoose = require('mongoose');
      mongoose.connection.close(false, () => {
        logger.info('MongoDB connection closed.');
        process.exit(0);
      });
    });
  });
};

/**
 * Monitor memory usage and warn if getting high
 */
const monitorMemoryUsage = () => {
  setInterval(() => {
    const memUsage = process.memoryUsage();
    const memUsageMB = {
      rss: Math.round(memUsage.rss / 1024 / 1024),
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
      external: Math.round(memUsage.external / 1024 / 1024)
    };

    // Warn if memory usage is high
    if (memUsageMB.heapUsed > 500) { // 500MB threshold
      logger.warn('High memory usage detected:', memUsageMB);
    }

    // Log memory stats every hour
    const now = new Date();
    if (now.getMinutes() === 0 && now.getSeconds() < 30) {
      logger.info('Memory usage:', memUsageMB);
    }
  }, 30000); // Check every 30 seconds
};

/**
 * Log request duration for performance monitoring
 */
const requestDurationLogger = (req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log slow requests
    if (duration > 5000) { // 5 seconds threshold
      logger.warn('Slow request detected:', {
        duration: `${duration}ms`,
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        user: req.user?.username || 'anonymous'
      });
    }
    
    // Log to debug for all requests in development
    if (process.env.NODE_ENV === 'development') {
      logger.debug(`${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
    }
  });
  
  next();
};

/**
 * Handle operational errors differently from programming errors
 */
const isOperationalError = (error) => {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  
  // Common operational errors
  const operationalErrors = [
    'ValidationError',
    'CastError',
    'MongooseServerSelectionError',
    'JsonWebTokenError',
    'TokenExpiredError'
  ];
  
  return operationalErrors.includes(error.name);
};

/**
 * Send error response based on environment
 */
const sendErrorResponse = (err, req, res) => {
  if (process.env.NODE_ENV === 'development') {
    // Development: send full error details
    return res.status(err.statusCode || 500).json({
      success: false,
      message: err.message,
      error: err,
      stack: err.stack,
      request: {
        url: req.originalUrl,
        method: req.method,
        body: sanitizeBody(req.body),
        query: req.query,
        params: req.params
      }
    });
  }
  
  // Production: send limited error details
  if (err.isOperational || isOperationalError(err)) {
    return res.status(err.statusCode || 500).json({
      success: false,
      message: err.message
    });
  }
  
  // Programming errors: don't leak details
  logger.error('Programming error:', err);
  
  return res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
};

/**
 * Sanitize request body for logging (remove sensitive data)
 */
const sanitizeBody = (body) => {
  if (!body || typeof body !== 'object') return body;
  
  const sanitized = { ...body };
  const sensitiveFields = [
    'password', 'currentPassword', 'newPassword', 'confirmPassword',
    'token', 'refreshToken', 'accessToken',
    'secret', 'apiKey', 'privateKey',
    'ssn', 'socialSecurityNumber', 'creditCard', 'cvv'
  ];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
};

/**
 * Create error response for API
 */
const createErrorResponse = (message, statusCode = 500, details = null) => {
  return {
    success: false,
    message,
    statusCode,
    ...(details && { details }),
    timestamp: new Date().toISOString()
  };
};

/**
 * Handle specific database errors
 */
const handleDatabaseError = (err) => {
  if (err.name === 'MongooseError') {
    return new AppError('Database operation failed', 500);
  }
  
  if (err.name === 'MongooseServerSelectionError') {
    return new AppError('Database connection failed', 503);
  }
  
  if (err.name === 'MongooseTimeoutError') {
    return new AppError('Database operation timed out', 408);
  }
  
  return err;
};

module.exports = {
  errorHandler,
  notFoundHandler,
  asyncHandler,
  validateEnvironment,
  handleUncaughtException,
  handleUnhandledRejection,
  handleGracefulShutdown,
  handleSIGTERM,
  monitorMemoryUsage,
  requestDurationLogger,
  isOperationalError,
  sendErrorResponse,
  sanitizeBody,
  createErrorResponse,
  handleDatabaseError
};
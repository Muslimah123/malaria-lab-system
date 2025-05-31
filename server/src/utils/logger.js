// 📁 server/src/utils/logger.js
const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    
    // Add stack trace for errors
    if (stack) {
      log += `\n${stack}`;
    }
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      log += `\n${JSON.stringify(meta, null, 2)}`;
    }
    
    return log;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create transports
const transports = [
  // Console transport
  new winston.transports.Console({
    level: process.env.LOG_LEVEL || 'info',
    format: consoleFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // File transport for all logs
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    level: 'info',
    format: fileFormat,
    maxsize: 10485760, // 10MB
    maxFiles: 5,
    tailable: true
  }),

  // File transport for error logs only
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileFormat,
    maxsize: 10485760, // 10MB
    maxFiles: 10,
    tailable: true
  })
];

// Add audit log transport for production
if (process.env.NODE_ENV === 'production') {
  transports.push(
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      level: 'warn',
      format: fileFormat,
      maxsize: 52428800, // 50MB
      maxFiles: 20,
      tailable: true
    })
  );
}

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  transports,
  exitOnError: false,
  silent: process.env.NODE_ENV === 'test'
});

// Add request ID tracking
logger.addRequestId = (req, res, next) => {
  const requestId = require('crypto').randomUUID();
  req.requestId = requestId;
  res.set('X-Request-ID', requestId);
  
  // Create child logger with request ID
  req.logger = logger.child({ requestId });
  
  next();
};

// Enhanced logging methods with context
logger.logWithContext = (level, message, context = {}) => {
  logger.log(level, message, {
    ...context,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    service: 'malaria-lab-system'
  });
};

// Security logging
logger.security = (message, details = {}) => {
  logger.warn(message, {
    type: 'security',
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Performance logging
logger.performance = (message, duration, details = {}) => {
  logger.info(message, {
    type: 'performance',
    duration: `${duration}ms`,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Business logic logging
logger.business = (action, details = {}) => {
  logger.info(`Business action: ${action}`, {
    type: 'business',
    action,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Database operation logging
logger.database = (operation, collection, details = {}) => {
  logger.debug(`Database operation: ${operation}`, {
    type: 'database',
    operation,
    collection,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// API call logging
logger.api = (method, url, statusCode, duration, details = {}) => {
  const level = statusCode >= 400 ? 'warn' : 'info';
  logger.log(level, `API Call: ${method} ${url}`, {
    type: 'api',
    method,
    url,
    statusCode,
    duration: `${duration}ms`,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// External service logging
logger.external = (service, operation, status, details = {}) => {
  const level = status === 'success' ? 'info' : 'warn';
  logger.log(level, `External service: ${service} - ${operation}`, {
    type: 'external',
    service,
    operation,
    status,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// User activity logging
logger.userActivity = (userId, action, details = {}) => {
  logger.info(`User activity: ${action}`, {
    type: 'user_activity',
    userId,
    action,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// System monitoring logging
logger.system = (metric, value, details = {}) => {
  logger.info(`System metric: ${metric}`, {
    type: 'system',
    metric,
    value,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// File operation logging
logger.file = (operation, filename, details = {}) => {
  logger.debug(`File operation: ${operation}`, {
    type: 'file',
    operation,
    filename,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Diagnosis operation logging
logger.diagnosis = (testId, status, details = {}) => {
  logger.info(`Diagnosis: ${testId} - ${status}`, {
    type: 'diagnosis',
    testId,
    status,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Request/Response logging middleware
logger.requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log incoming request
  logger.info('Incoming request', {
    type: 'request',
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user?.username || 'anonymous',
    requestId: req.requestId
  });

  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const level = res.statusCode >= 400 ? 'warn' : 'info';
    
    logger.log(level, 'Request completed', {
      type: 'response',
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      user: req.user?.username || 'anonymous',
      requestId: req.requestId
    });
  });

  next();
};

// Log rotation cleanup
logger.cleanup = () => {
  const fs = require('fs');
  const path = require('path');
  
  try {
    const files = fs.readdirSync(logsDir);
    const now = Date.now();
    const maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    
    files.forEach(file => {
      const filePath = path.join(logsDir, file);
      const stats = fs.statSync(filePath);
      
      if (now - stats.mtime.getTime() > maxAge) {
        fs.unlinkSync(filePath);
        logger.info(`Cleaned up old log file: ${file}`);
      }
    });
  } catch (error) {
    logger.error('Log cleanup failed:', error);
  }
};

// Log system startup
logger.startup = (config = {}) => {
  logger.info('🚀 System starting up', {
    type: 'startup',
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    platform: process.platform,
    pid: process.pid,
    memory: process.memoryUsage(),
    ...config,
    timestamp: new Date().toISOString()
  });
};

// Log system shutdown
logger.shutdown = (reason = 'Unknown') => {
  logger.info('🛑 System shutting down', {
    type: 'shutdown',
    reason,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
};

// Create structured error logging
logger.error = (message, error = null, context = {}) => {
  const logData = {
    message,
    ...context,
    timestamp: new Date().toISOString()
  };

  if (error) {
    logData.error = {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code,
      statusCode: error.statusCode
    };
  }

  winston.createLogger.prototype.error.call(logger, logData);
};

// Export logger with additional utilities
module.exports = logger;

// Handle process exit to flush logs
process.on('exit', () => {
  logger.shutdown('Process exit');
});

// Cleanup old logs on startup (in production)
if (process.env.NODE_ENV === 'production') {
  setInterval(() => {
    logger.cleanup();
  }, 24 * 60 * 60 * 1000); // Daily cleanup
}
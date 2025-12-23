// 📁 server/src/config/timeout.js
// Centralized timeout configuration for the malaria lab system

const timeoutConfig = {
  // Flask API timeouts
  flask: {
    // Main API timeout for image processing
    apiTimeout: parseInt(process.env.FLASK_API_TIMEOUT) || 600000, // 10 minutes
    // Health check timeout
    healthCheckTimeout: parseInt(process.env.FLASK_HEALTH_TIMEOUT) || 10000, // 10 seconds
    // Memory status check timeout
    memoryCheckTimeout: parseInt(process.env.FLASK_MEMORY_TIMEOUT) || 5000, // 5 seconds
    // Retry configuration
    retryAttempts: parseInt(process.env.FLASK_API_RETRY_ATTEMPTS) || 3,
    retryDelay: parseInt(process.env.FLASK_API_RETRY_DELAY) || 5000, // 5 seconds
  },

  // Database timeouts
  database: {
    serverSelectionTimeout: parseInt(process.env.MONGODB_SERVER_SELECTION_TIMEOUT) || 5000,
    socketTimeout: parseInt(process.env.MONGODB_SOCKET_TIMEOUT) || 45000,
    connectTimeout: parseInt(process.env.MONGODB_CONNECT_TIMEOUT) || 10000,
  },

  // HTTP server timeouts
  server: {
    requestTimeout: parseInt(process.env.SERVER_REQUEST_TIMEOUT) || 300000, // 5 minutes
    keepAliveTimeout: parseInt(process.env.SERVER_KEEPALIVE_TIMEOUT) || 65000,
    headersTimeout: parseInt(process.env.SERVER_HEADERS_TIMEOUT) || 66000,
  },

  // Socket timeouts
  socket: {
    connectionTimeout: parseInt(process.env.SOCKET_CONNECTION_TIMEOUT) || 10000,
    socketTimeout: parseInt(process.env.SOCKET_TIMEOUT) || 45000,
    pingTimeout: parseInt(process.env.SOCKET_PING_TIMEOUT) || 60000,
    pingInterval: parseInt(process.env.SOCKET_PING_INTERVAL) || 25000,
  },

  // Client API timeouts
  client: {
    requestTimeout: parseInt(process.env.CLIENT_REQUEST_TIMEOUT) || 30000, // 30 seconds
    uploadTimeout: parseInt(process.env.CLIENT_UPLOAD_TIMEOUT) || 300000, // 5 minutes
  },

  // Integration timeouts
  integration: {
    externalApiTimeout: parseInt(process.env.EXTERNAL_API_TIMEOUT) || 5000,
    hospitalSyncTimeout: parseInt(process.env.HOSPITAL_SYNC_TIMEOUT) || 10000,
  },

  // Audit and batch processing
  audit: {
    batchTimeout: parseInt(process.env.AUDIT_BATCH_TIMEOUT) || 5000,
    flushTimeout: parseInt(process.env.AUDIT_FLUSH_TIMEOUT) || 10000,
  }
};

// Helper function to get timeout in human-readable format
const formatTimeout = (ms) => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${Math.round(ms/1000)}s`;
  if (ms < 3600000) return `${Math.round(ms/1000/60)}m`;
  return `${Math.round(ms/1000/60/60)}h`;
};

// Helper function to validate timeout values
const validateTimeout = (timeout, min = 1000, max = 3600000) => {
  if (timeout < min) {
    console.warn(`⚠️  Timeout value ${timeout}ms is below minimum ${min}ms, using ${min}ms`);
    return min;
  }
  if (timeout > max) {
    console.warn(`⚠️  Timeout value ${timeout}ms is above maximum ${max}ms, using ${max}ms`);
    return max;
  }
  return timeout;
};

// Apply validation to all timeouts
Object.keys(timeoutConfig).forEach(category => {
  Object.keys(timeoutConfig[category]).forEach(key => {
    if (key.includes('Timeout')) {
      timeoutConfig[category][key] = validateTimeout(timeoutConfig[category][key]);
    }
  });
});

// Log timeout configuration on startup
const logTimeoutConfig = () => {
  console.log('🔧 Timeout Configuration:');
  Object.keys(timeoutConfig).forEach(category => {
    console.log(`  ${category}:`);
    Object.keys(timeoutConfig[category]).forEach(key => {
      const value = timeoutConfig[category][key];
      if (key.includes('Timeout')) {
        console.log(`    ${key}: ${formatTimeout(value)} (${value}ms)`);
      } else {
        console.log(`    ${key}: ${value}`);
      }
    });
  });
};

module.exports = {
  timeoutConfig,
  formatTimeout,
  validateTimeout,
  logTimeoutConfig
};

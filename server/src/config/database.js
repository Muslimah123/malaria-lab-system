// 📁 server/src/config/database.js
const mongoose = require('mongoose');
const logger = require('../utils/logger');

class DatabaseConfig {
  constructor() {
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxRetries = 5;
    this.retryDelay = 5000; // 5 seconds
  }

  async connect() {
    try {
      // MongoDB connection options
      const options = {
        // Connection pool settings
        maxPoolSize: 10, // Maintain up to 10 socket connections
        serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
        socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
        family: 4, // Use IPv4, skip trying IPv6
        
        // Buffering settings
        bufferMaxEntries: 0, // Disable mongoose buffering
        bufferCommands: false, // Disable mongoose buffering
        
        // Retry settings
        retryWrites: true,
        retryReads: true,
        
        // Additional settings
        connectTimeoutMS: 10000, // Give up initial connection after 10 seconds
        heartbeatFrequencyMS: 2000, // Check server status every 2 seconds
      };

      const mongoUri = this.getConnectionString();
      
      // Connect to MongoDB
      await mongoose.connect(mongoUri, options);
      
      this.isConnected = true;
      this.connectionAttempts = 0;
      
      logger.info('✅ Connected to MongoDB successfully');
      logger.info(`📊 Database: ${mongoose.connection.name}`);
      
      // Set up connection event listeners
      this.setupEventListeners();
      
      return mongoose.connection;
      
    } catch (error) {
      this.connectionAttempts++;
      logger.error(`❌ MongoDB connection failed (attempt ${this.connectionAttempts}):`, error.message);
      
      if (this.connectionAttempts < this.maxRetries) {
        logger.info(`🔄 Retrying connection in ${this.retryDelay / 1000} seconds...`);
        await this.delay(this.retryDelay);
        return this.connect();
      } else {
        logger.error(`💥 Max connection attempts (${this.maxRetries}) reached. Exiting...`);
        process.exit(1);
      }
    }
  }

  getConnectionString() {
    const {
      MONGODB_URI,
      MONGODB_HOST = 'localhost',
      MONGODB_PORT = '27017',
      MONGODB_DATABASE = 'malaria_lab',
      MONGODB_USERNAME,
      MONGODB_PASSWORD,
      NODE_ENV = 'development'
    } = process.env;

    // If MONGODB_URI is provided, use it directly
    if (MONGODB_URI) {
      return MONGODB_URI;
    }

    // Build connection string from individual components
    let connectionString = 'mongodb://';
    
    // Add authentication if provided
    if (MONGODB_USERNAME && MONGODB_PASSWORD) {
      connectionString += `${MONGODB_USERNAME}:${MONGODB_PASSWORD}@`;
    }
    
    connectionString += `${MONGODB_HOST}:${MONGODB_PORT}/${MONGODB_DATABASE}`;
    
    // Add additional options for production
    if (NODE_ENV === 'production') {
      connectionString += '?retryWrites=true&w=majority';
    }
    
    return connectionString;
  }

  setupEventListeners() {
    const db = mongoose.connection;

    // Connection events
    db.on('connected', () => {
      logger.info('🔗 Mongoose connected to MongoDB');
    });

    db.on('error', (error) => {
      logger.error('❌ MongoDB connection error:', error);
      this.isConnected = false;
    });

    db.on('disconnected', () => {
      logger.warn('⚠️ Mongoose disconnected from MongoDB');
      this.isConnected = false;
      
      // Attempt to reconnect
      if (process.env.NODE_ENV !== 'test') {
        this.reconnect();
      }
    });

    db.on('reconnected', () => {
      logger.info('🔄 Mongoose reconnected to MongoDB');
      this.isConnected = true;
    });

    // Process events for graceful shutdown
    process.on('SIGINT', this.gracefulShutdown.bind(this));
    process.on('SIGTERM', this.gracefulShutdown.bind(this));
    process.on('SIGUSR2', this.gracefulShutdown.bind(this)); // Nodemon restart
  }

  async reconnect() {
    if (this.isConnected) return;

    try {
      logger.info('🔄 Attempting to reconnect to MongoDB...');
      await this.connect();
    } catch (error) {
      logger.error('Failed to reconnect to MongoDB:', error.message);
      
      // Retry after delay
      setTimeout(() => {
        this.reconnect();
      }, this.retryDelay);
    }
  }

  async gracefulShutdown(signal) {
    logger.info(`📴 Received ${signal}. Gracefully shutting down database connection...`);
    
    try {
      await mongoose.connection.close();
      logger.info('✅ MongoDB connection closed successfully');
      process.exit(0);
    } catch (error) {
      logger.error('❌ Error during MongoDB shutdown:', error);
      process.exit(1);
    }
  }

  // Health check method
  async healthCheck() {
    try {
      if (!this.isConnected) {
        return { status: 'disconnected', message: 'Not connected to database' };
      }

      // Ping the database
      await mongoose.connection.db.admin().ping();
      
      return {
        status: 'healthy',
        message: 'Database connection is healthy',
        details: {
          connected: this.isConnected,
          database: mongoose.connection.name,
          host: mongoose.connection.host,
          port: mongoose.connection.port,
          readyState: mongoose.connection.readyState // 1 = connected
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        message: 'Database health check failed',
        error: error.message
      };
    }
  }

  // Database statistics
  async getStats() {
    try {
      const stats = await mongoose.connection.db.stats();
      
      return {
        database: mongoose.connection.name,
        collections: stats.collections,
        documents: stats.objects,
        dataSize: this.formatBytes(stats.dataSize),
        storageSize: this.formatBytes(stats.storageSize),
        indexes: stats.indexes,
        indexSize: this.formatBytes(stats.indexSize),
        avgObjectSize: this.formatBytes(stats.avgObjSize)
      };
    } catch (error) {
      logger.error('Error fetching database statistics:', error);
      return null;
    }
  }

  // Utility methods
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Database maintenance utilities
  async createIndexes() {
    try {
      logger.info('🔧 Creating database indexes...');
      
      // Let Mongoose handle index creation automatically
      await mongoose.connection.syncIndexes();
      
      logger.info('✅ Database indexes created successfully');
    } catch (error) {
      logger.error('❌ Error creating indexes:', error);
      throw error;
    }
  }

  async dropDatabase() {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Cannot drop database in production environment');
    }
    
    try {
      await mongoose.connection.dropDatabase();
      logger.info('🗑️ Database dropped successfully');
    } catch (error) {
      logger.error('❌ Error dropping database:', error);
      throw error;
    }
  }

  // Backup and restore utilities (placeholder)
  async createBackup() {
    // Implementation for database backup
    logger.info('💾 Creating database backup...');
    // This would typically use mongodump or a cloud backup service
  }

  async restoreBackup(backupPath) {
    // Implementation for database restore
    logger.info(`📥 Restoring database from ${backupPath}...`);
    // This would typically use mongorestore
  }
}

// Export singleton instance
const databaseConfig = new DatabaseConfig();

// Initialize database connection
const initializeDatabase = async () => {
  try {
    await databaseConfig.connect();
    
    // Create indexes after connection
    if (process.env.NODE_ENV !== 'test') {
      await databaseConfig.createIndexes();
    }
    
    return databaseConfig;
  } catch (error) {
    logger.error('Failed to initialize database:', error);
    throw error;
  }
};

module.exports = {
  databaseConfig,
  initializeDatabase,
  healthCheck: () => databaseConfig.healthCheck(),
  getStats: () => databaseConfig.getStats()
};
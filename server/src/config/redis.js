// 📁 server/src/config/redis.js
const redis = require('redis');
const logger = require('../utils/logger');

class RedisConfig {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      // Build Redis URL from environment variables
      const redisHost = process.env.REDIS_HOST || 'localhost';
      const redisPort = process.env.REDIS_PORT || 6379;
      const redisPassword = process.env.REDIS_PASSWORD;
      
      // Use Redis URL format for better compatibility
      let redisUrl = process.env.REDIS_URL;
      
      if (!redisUrl) {
        // Build URL from components
        if (redisPassword) {
          redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}`;
        } else {
          redisUrl = `redis://${redisHost}:${redisPort}`;
        }
      }

      logger.info(`Attempting to connect to Redis at: ${redisUrl.replace(/:[^:@]*@/, ':****@')}`);

      // Create Redis client with URL
      this.client = redis.createClient({
        url: redisUrl,
        socket: {
          connectTimeout: 5000,
          reconnectStrategy: (retries) => {
            if (retries > 10) {
              logger.error('Redis: Max reconnection attempts reached');
              return false;
            }
            const delay = Math.min(retries * 100, 3000);
            logger.info(`Redis: Reconnecting in ${delay}ms (attempt ${retries})`);
            return delay;
          }
        }
      });

      // Set up event handlers
      this.client.on('error', (err) => {
        logger.error('Redis connection error:', err);
        this.isConnected = false;
      });

      this.client.on('connect', () => {
        logger.info('Redis client connected');
        this.isConnected = true;
      });

      this.client.on('ready', () => {
        logger.info('Redis client ready');
        this.isConnected = true;
      });

      this.client.on('end', () => {
        logger.info('Redis client disconnected');
        this.isConnected = false;
      });

      // Connect to Redis
      await this.client.connect();
      
      // Test the connection
      await this.client.ping();
      logger.info('✅ Redis connection successful');
      
      return this.client;

    } catch (error) {
      logger.error('Failed to connect to Redis:', error);
      throw error;
    }
  }

  async disconnect() {
    if (this.client) {
      await this.client.quit();
      logger.info('Redis client disconnected');
    }
  }

  getClient() {
    if (!this.client) {
      throw new Error('Redis client not initialized. Call connect() first.');
    }
    return this.client;
  }

  isReady() {
    return this.isConnected && this.client && this.client.isReady;
  }
}

// Export singleton instance
const redisConfig = new RedisConfig();

module.exports = {
  redisConfig,
  getRedisClient: () => redisConfig.getClient(),
  connectRedis: () => redisConfig.connect(),
  disconnectRedis: () => redisConfig.disconnect(),
  isRedisReady: () => redisConfig.isReady()
};
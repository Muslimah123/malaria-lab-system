// 📁 server/src/middleware/rateLimit.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');
const logger = require('../utils/logger');

// Initialize Redis client for rate limiting
let redisClient;
try {
  redisClient = redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD,
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3
  });

  redisClient.on('error', (err) => {
    logger.warn('Redis rate limiting unavailable, using memory store:', err.message);
  });

  redisClient.connect().catch(() => {
    logger.warn('Redis connection failed, rate limiting will use memory store');
  });
} catch (error) {
  logger.warn('Redis initialization failed, rate limiting will use memory store:', error.message);
}

/**
 * Create rate limiter with Redis store (fallback to memory)
 */
const createRateLimiter = (options) => {
  const defaultOptions = {
    legacyHeaders: false,
    standardHeaders: true,
    handler: (req, res) => {
      logger.warn('Rate limit exceeded:', {
        ip: req.ip,
        endpoint: req.originalUrl,
        userAgent: req.get('User-Agent'),
        user: req.user?.username || 'anonymous'
      });

      res.status(429).json({
        success: false,
        message: 'Too many requests, please try again later.',
        retryAfter: Math.round(options.windowMs / 1000)
      });
    },
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise IP address
      return req.user ? `user:${req.user._id}` : `ip:${req.ip}`;
    }
  };

  // Use Redis store if available
  if (redisClient && redisClient.isReady) {
    defaultOptions.store = new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    });
  }

  return rateLimit({
    ...defaultOptions,
    ...options
  });
};

/**
 * General API rate limiter
 */
const generalLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each user/IP to 1000 requests per windowMs
  message: 'Too many requests from this user/IP, please try again later.',
  skip: (req) => {
    // Skip rate limiting for health checks and certain endpoints
    const skipPaths = ['/health', '/api/health', '/favicon.ico'];
    return skipPaths.includes(req.path);
  }
});

/**
 * Authentication rate limiter (stricter for login attempts)
 */
const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  skipSuccessfulRequests: true, // Don't count successful requests
  keyGenerator: (req) => `login:${req.ip}`, // Always use IP for login attempts
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      email: req.body?.email
    });

    res.status(429).json({
      success: false,
      message: 'Too many login attempts, please try again in 15 minutes.',
      retryAfter: 900 // 15 minutes in seconds
    });
  }
});

/**
 * Password reset rate limiter
 */
const passwordResetLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset requests per hour
  keyGenerator: (req) => `password-reset:${req.ip}`,
  handler: (req, res) => {
    logger.warn('Password reset rate limit exceeded:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      email: req.body?.email
    });

    res.status(429).json({
      success: false,
      message: 'Too many password reset attempts, please try again in 1 hour.',
      retryAfter: 3600
    });
  }
});

/**
 * Token refresh rate limiter
 */
const refreshLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each user to 10 token refresh requests per windowMs
  keyGenerator: (req) => {
    // Extract user ID from refresh token if possible
    const refreshToken = req.body?.refreshToken;
    if (refreshToken) {
      try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.decode(refreshToken);
        return `refresh:${decoded?.userId || req.ip}`;
      } catch {
        return `refresh:${req.ip}`;
      }
    }
    return `refresh:${req.ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many token refresh attempts, please try again later.',
      retryAfter: 900
    });
  }
});

/**
 * File upload rate limiter
 */
const uploadLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50, // Limit each user to 50 file uploads per 10 minutes
  keyGenerator: (req) => req.user ? `upload:${req.user._id}` : `upload:${req.ip}`,
  handler: (req, res) => {
    logger.warn('Upload rate limit exceeded:', {
      ip: req.ip,
      user: req.user?.username || 'anonymous',
      fileCount: req.files?.length || 0
    });

    res.status(429).json({
      success: false,
      message: 'Too many file uploads, please try again later.',
      retryAfter: 600
    });
  }
});

/**
 * Diagnosis analysis rate limiter (for Flask API calls)
 */
const diagnosisLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // Limit each user to 100 diagnosis requests per hour
  keyGenerator: (req) => req.user ? `diagnosis:${req.user._id}` : `diagnosis:${req.ip}`,
  handler: (req, res) => {
    logger.warn('Diagnosis rate limit exceeded:', {
      ip: req.ip,
      user: req.user?.username || 'anonymous'
    });

    res.status(429).json({
      success: false,
      message: 'Too many diagnosis requests, please try again later.',
      retryAfter: 3600
    });
  }
});

/**
 * Search rate limiter
 */
const searchLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100, // Limit each user to 100 search requests per 5 minutes
  keyGenerator: (req) => req.user ? `search:${req.user._id}` : `search:${req.ip}`,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many search requests, please try again later.',
      retryAfter: 300
    });
  }
});

/**
 * Export rate limiter
 */
const exportLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each user to 20 export requests per hour
  keyGenerator: (req) => req.user ? `export:${req.user._id}` : `export:${req.ip}`,
  handler: (req, res) => {
    logger.warn('Export rate limit exceeded:', {
      ip: req.ip,
      user: req.user?.username || 'anonymous',
      endpoint: req.originalUrl
    });

    res.status(429).json({
      success: false,
      message: 'Too many export requests, please try again later.',
      retryAfter: 3600
    });
  }
});

/**
 * Admin operations rate limiter
 */
const adminLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 200, // Higher limit for admin operations
  keyGenerator: (req) => `admin:${req.user?._id || req.ip}`,
  skip: (req) => {
    // Only apply to admin users
    return !req.user || req.user.role !== 'admin';
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many admin requests, please try again later.',
      retryAfter: 300
    });
  }
});

/**
 * Dynamic rate limiter based on user role
 */
const dynamicRoleBasedLimiter = (req, res, next) => {
  const user = req.user;
  
  if (!user) {
    // Anonymous users get strict limits
    return createRateLimiter({
      windowMs: 15 * 60 * 1000,
      max: 50,
      keyGenerator: () => `anon:${req.ip}`
    })(req, res, next);
  }

  // Different limits based on role
  const roleLimits = {
    admin: { windowMs: 15 * 60 * 1000, max: 2000 },
    supervisor: { windowMs: 15 * 60 * 1000, max: 1500 },
    technician: { windowMs: 15 * 60 * 1000, max: 1000 }
  };

  const limits = roleLimits[user.role] || roleLimits.technician;
  
  return createRateLimiter({
    ...limits,
    keyGenerator: () => `role:${user.role}:${user._id}`
  })(req, res, next);
};

/**
 * Sliding window rate limiter for critical operations
 */
const criticalOperationLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Very strict limit for critical operations
  keyGenerator: (req) => `critical:${req.user?._id || req.ip}`,
  handler: (req, res) => {
    logger.error('Critical operation rate limit exceeded:', {
      ip: req.ip,
      user: req.user?.username || 'anonymous',
      endpoint: req.originalUrl,
      method: req.method
    });

    res.status(429).json({
      success: false,
      message: 'Critical operation rate limit exceeded. Please contact system administrator.',
      retryAfter: 3600
    });
  }
});

/**
 * Middleware to add rate limit headers
 */
const addRateLimitHeaders = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Add custom rate limit info headers
    if (req.rateLimit) {
      res.set({
        'X-RateLimit-Limit': req.rateLimit.limit,
        'X-RateLimit-Remaining': req.rateLimit.remaining,
        'X-RateLimit-Reset': new Date(Date.now() + req.rateLimit.msBeforeNext).toISOString()
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

/**
 * Bypass rate limiting for certain conditions
 */
const bypassRateLimit = (req, res, next) => {
  // Bypass for localhost in development
  if (process.env.NODE_ENV === 'development' && req.ip === '127.0.0.1') {
    return next();
  }
  
  // Bypass for health checks
  if (req.path.includes('/health')) {
    return next();
  }
  
  // Bypass for admin users on certain endpoints (with caution)
  if (req.user && req.user.role === 'admin' && req.path.includes('/api/admin/emergency')) {
    return next();
  }
  
  next();
};

/**
 * Rate limit statistics
 */
const getRateLimitStats = async () => {
  try {
    if (!redisClient || !redisClient.isReady) {
      return { error: 'Redis not available' };
    }

    const keys = await redisClient.keys('rl:*');
    const stats = {
      totalKeys: keys.length,
      activeUsers: 0,
      topEndpoints: [],
      timestamp: new Date()
    };

    // Analyze patterns (sample implementation)
    const patterns = {};
    keys.forEach(key => {
      const parts = key.split(':');
      if (parts.length > 2) {
        const pattern = parts[1];
        patterns[pattern] = (patterns[pattern] || 0) + 1;
      }
    });

    stats.patterns = patterns;
    return stats;

  } catch (error) {
    logger.error('Rate limit stats error:', error);
    return { error: error.message };
  }
};

/**
 * Clear rate limits for a user (admin operation)
 */
const clearUserRateLimit = async (userId) => {
  try {
    if (!redisClient || !redisClient.isReady) {
      throw new Error('Redis not available');
    }

    const patterns = [`rl:user:${userId}:*`, `rl:*:${userId}:*`];
    let deletedCount = 0;

    for (const pattern of patterns) {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(...keys);
        deletedCount += keys.length;
      }
    }

    logger.info(`Cleared ${deletedCount} rate limit entries for user ${userId}`);
    return deletedCount;

  } catch (error) {
    logger.error('Clear user rate limit error:', error);
    throw error;
  }
};

module.exports = {
  generalLimiter,
  loginLimiter,
  passwordResetLimiter,
  refreshLimiter,
  uploadLimiter,
  diagnosisLimiter,
  searchLimiter,
  exportLimiter,
  adminLimiter,
  dynamicRoleBasedLimiter,
  criticalOperationLimiter,
  addRateLimitHeaders,
  bypassRateLimit,
  getRateLimitStats,
  clearUserRateLimit,
  createRateLimiter
};
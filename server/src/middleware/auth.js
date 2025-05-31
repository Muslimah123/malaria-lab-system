// 📁 server/src/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authService = require('../services/authService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

/**
 * Main authentication middleware
 */
const auth = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No valid token provided.'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token using auth service
    const decoded = await authService.verifyToken(token);

    // Get user from database
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      await logUnauthorizedAccess(req, decoded.userId, 'User not found or inactive');
      return res.status(401).json({
        success: false,
        message: 'Access denied. User not found or inactive.'
      });
    }

    // Check if user account is locked or suspended
    if (user.accountStatus === 'locked' || user.accountStatus === 'suspended') {
      await logUnauthorizedAccess(req, user._id, `Account ${user.accountStatus}`);
      return res.status(401).json({
        success: false,
        message: `Access denied. Account is ${user.accountStatus}.`
      });
    }

    // Update last access time
    await updateUserLastAccess(user._id);

    // Attach user and token info to request object
    req.user = user;
    req.token = token;
    req.tokenExpiry = decoded.exp;
    req.sessionId = decoded.sessionId;

    next();

  } catch (error) {
    logger.error('Authentication middleware error:', error);

    // Log unauthorized access attempt
    await logUnauthorizedAccess(req, null, error.message);

    if (error instanceof AppError) {
      return res.status(401).json({
        success: false,
        message: error.message
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Access denied. Invalid token.'
    });
  }
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token provided, continue without authentication
      req.user = null;
      return next();
    }

    const token = authHeader.substring(7);
    const decoded = await authService.verifyToken(token);

    const user = await User.findById(decoded.userId);
    if (user && user.isActive) {
      req.user = user;
      req.token = token;
      req.tokenExpiry = decoded.exp;
    } else {
      req.user = null;
    }

    next();

  } catch (error) {
    // On error, continue without authentication
    req.user = null;
    next();
  }
};

/**
 * Role-based authorization middleware
 */
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userRole = req.user.role;
    const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

    if (!rolesArray.includes(userRole)) {
      // Log unauthorized access attempt
      auditService.log({
        action: 'unauthorized_access_attempt',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'system',
        resourceId: 'role_access',
        details: {
          requiredRoles: rolesArray,
          userRole: userRole,
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
        riskLevel: 'medium'
      });

      return res.status(403).json({
        success: false,
        message: `Access denied. Required role: ${rolesArray.join(' or ')}`
      });
    }

    next();
  };
};

/**
 * Permission-based authorization middleware
 */
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!req.user.permissions || !req.user.permissions[permission]) {
      // Log unauthorized access attempt
      auditService.log({
        action: 'unauthorized_access_attempt',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'system',
        resourceId: 'permission_access',
        details: {
          requiredPermission: permission,
          userPermissions: Object.keys(req.user.permissions || {}),
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
        riskLevel: 'medium'
      });

      return res.status(403).json({
        success: false,
        message: `Access denied. Required permission: ${permission}`
      });
    }

    next();
  };
};

/**
 * Resource ownership middleware
 */
const requireOwnership = (resourceParam = 'id', userField = '_id') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const resourceId = req.params[resourceParam];
    const userId = req.user[userField];

    // Admins and supervisors can access any resource
    if (['admin', 'supervisor'].includes(req.user.role)) {
      return next();
    }

    // Check if user owns the resource
    if (resourceId !== userId.toString()) {
      // Log unauthorized access attempt
      auditService.log({
        action: 'unauthorized_access_attempt',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'system',
        resourceId: resourceId,
        details: {
          reason: 'Resource ownership check failed',
          requestedResource: resourceId,
          userId: userId.toString(),
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

      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only access your own resources.'
      });
    }

    next();
  };
};

/**
 * API key authentication middleware
 */
const apiKeyAuth = async (req, res, next) => {
  try {
    const apiKey = req.header('X-API-Key');
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required'
      });
    }

    // In a real implementation, you'd validate against stored API keys
    const validApiKey = process.env.API_KEY || 'your-api-key-here';
    
    if (apiKey !== validApiKey) {
      await logUnauthorizedAccess(req, null, 'Invalid API key');
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    // Set request source
    req.apiAuthenticated = true;
    req.source = 'api';

    next();

  } catch (error) {
    logger.error('API key authentication error:', error);
    return res.status(401).json({
      success: false,
      message: 'API authentication failed'
    });
  }
};

/**
 * Rate limiting by user
 */
const userRateLimit = (maxRequests = 100, windowMs = 60000) => {
  const userRequests = new Map();

  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userId = req.user._id.toString();
    const now = Date.now();
    const windowStart = now - windowMs;

    // Get user's request history
    if (!userRequests.has(userId)) {
      userRequests.set(userId, []);
    }

    const userHistory = userRequests.get(userId);
    
    // Remove old requests outside the window
    const validRequests = userHistory.filter(timestamp => timestamp > windowStart);
    userRequests.set(userId, validRequests);

    // Check if user has exceeded rate limit
    if (validRequests.length >= maxRequests) {
      // Log rate limit violation
      auditService.log({
        action: 'rate_limit_exceeded',
        userId: req.user._id,
        userInfo: { username: req.user.username, email: req.user.email, role: req.user.role },
        resourceType: 'system',
        resourceId: 'rate_limit',
        details: {
          requests: validRequests.length,
          maxRequests,
          windowMs,
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
        riskLevel: 'medium'
      });

      return res.status(429).json({
        success: false,
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }

    // Add current request to history
    validRequests.push(now);
    userRequests.set(userId, validRequests);

    next();
  };
};

/**
 * Session validation middleware
 */
const validateSession = async (req, res, next) => {
  try {
    if (!req.sessionId) {
      return next(); // No session to validate
    }

    const session = await authService.getSession(req.sessionId);
    
    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Invalid session'
      });
    }

    // Update session access time
    await authService.updateSessionAccess(req.sessionId);

    req.session = session;
    next();

  } catch (error) {
    logger.error('Session validation error:', error);
    return res.status(401).json({
      success: false,
      message: 'Session validation failed'
    });
  }
};

/**
 * Helper function to log unauthorized access attempts
 */
async function logUnauthorizedAccess(req, userId = null, reason = 'Unknown') {
  try {
    await auditService.log({
      action: 'unauthorized_access_attempt',
      userId: userId || 'anonymous',
      userInfo: userId ? { userId } : {},
      resourceType: 'system',
      resourceId: 'authentication',
      details: {
        reason,
        endpoint: req.originalUrl,
        method: req.method,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()
      },
      requestInfo: {
        ipAddress: req.ip || req.connection?.remoteAddress,
        userAgent: req.get('User-Agent'),
        method: req.method,
        endpoint: req.originalUrl
      },
      status: 'failure',
      riskLevel: 'high'
    });
  } catch (auditError) {
    logger.error('Failed to log unauthorized access:', auditError);
  }
}

/**
 * Helper function to update user last access time
 */
async function updateUserLastAccess(userId) {
  try {
    // Update asynchronously without blocking the request
    setImmediate(async () => {
      try {
        await User.findByIdAndUpdate(userId, { 
          lastLogin: new Date() 
        });
      } catch (updateError) {
        logger.error('Failed to update user last access:', updateError);
      }
    });
  } catch (error) {
    logger.error('Update user last access error:', error);
  }
}

/**
 * Middleware to check if user is admin
 */
const requireAdmin = (req, res, next) => {
  return requireRole('admin')(req, res, next);
};

/**
 * Middleware to check if user is supervisor or admin
 */
const requireSupervisor = (req, res, next) => {
  return requireRole(['supervisor', 'admin'])(req, res, next);
};

/**
 * Middleware to check if user can upload samples
 */
const canUploadSamples = (req, res, next) => {
  return requirePermission('canUploadSamples')(req, res, next);
};

/**
 * Middleware to check if user can view all tests
 */
const canViewAllTests = (req, res, next) => {
  return requirePermission('canViewAllTests')(req, res, next);
};

/**
 * Middleware to check if user can delete tests
 */
const canDeleteTests = (req, res, next) => {
  return requirePermission('canDeleteTests')(req, res, next);
};

/**
 * Middleware to check if user can manage users
 */
const canManageUsers = (req, res, next) => {
  return requirePermission('canManageUsers')(req, res, next);
};

/**
 * Middleware to check if user can export reports
 */
const canExportReports = (req, res, next) => {
  return requirePermission('canExportReports')(req, res, next);
};

module.exports = {
  auth,
  optionalAuth,
  requireRole,
  requirePermission,
  requireOwnership,
  apiKeyAuth,
  userRateLimit,
  validateSession,
  // Convenience methods
  requireAdmin,
  requireSupervisor,
  canUploadSamples,
  canViewAllTests,
  canDeleteTests,
  canManageUsers,
  canExportReports
};
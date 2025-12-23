// 📁 server/src/middleware/validation.js
const { validationResult } = require('express-validator');
const { AppError } = require('../utils/errorTypes');
const logger = require('../utils/logger');

/**
 * Main validation middleware using express-validator
 */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = formatValidationErrors(errors.array());
    
    logger.warn('Request validation failed:', {
      endpoint: req.originalUrl,
      method: req.method,
      errors: formattedErrors,
      body: sanitizeRequestBody(req.body),
      query: req.query,
      params: req.params
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: formattedErrors
    });
  }

  next();
};

/**
 * Format validation errors for better readability
 */
const formatValidationErrors = (errors) => {
  const formatted = {};
  
  errors.forEach(error => {
    const field = error.param;
    if (!formatted[field]) {
      formatted[field] = [];
    }
    formatted[field].push(error.msg);
  });

  return formatted;
};

/**
 * Sanitize request body for logging (remove sensitive data)
 */
const sanitizeRequestBody = (body) => {
  if (!body || typeof body !== 'object') return body;
  
  const sanitized = { ...body };
  const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'ssn', 'creditCard'];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
};

/**
 * Custom validation for MongoDB ObjectId
 */
const validateObjectId = (paramName = 'id') => {
  return (req, res, next) => {
    const id = req.params[paramName];
    const objectIdRegex = /^[0-9a-fA-F]{24}$/;
    
    if (!objectIdRegex.test(id)) {
      return res.status(400).json({
        success: false,
        message: `Invalid ${paramName}. Must be a valid MongoDB ObjectId.`
      });
    }
    
    next();
  };
};

/**
 * Validate patient ID format
 */
const validatePatientId = (req, res, next) => {
  const patientId = req.params.patientId || req.body.patientId;
  
  if (!patientId) {
    return next(); // Let other validation handle required checks
  }

  // Patient ID format: PAT-YYYYMMDD-XXX
  const patientIdRegex = /^PAT-\d{8}-\d{3}$/;
  
  if (!patientIdRegex.test(patientId)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid patient ID format. Expected format: PAT-YYYYMMDD-XXX'
    });
  }
  
  next();
};

/**
 * Validate test ID format
 */
const validateTestId = (req, res, next) => {
  const testId = req.params.testId || req.body.testId;
  
  if (!testId) {
    return next(); // Let other validation handle required checks
  }

  // Test ID format: TEST-YYYYMMDD-XXX
  const testIdRegex = /^TEST-\d{8}-\d{3}$/;
  
  if (!testIdRegex.test(testId)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid test ID format. Expected format: TEST-YYYYMMDD-XXX'
    });
  }
  
  next();
};

/**
 * Validate date range
 */
const validateDateRange = (req, res, next) => {
  const { startDate, endDate } = req.query;
  
  if (startDate && endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({
        success: false,
        message: 'Invalid date format. Use ISO 8601 format (YYYY-MM-DD)'
      });
    }
    
    if (start > end) {
      return res.status(400).json({
        success: false,
        message: 'Start date must be before end date'
      });
    }
    
    // Check if date range is not too large (e.g., more than 1 year)
    const maxDays = 365;
    const daysDiff = (end - start) / (1000 * 60 * 60 * 24);
    
    if (daysDiff > maxDays) {
      return res.status(400).json({
        success: false,
        message: `Date range cannot exceed ${maxDays} days`
      });
    }
  }
  
  next();
};

/**
 * Validate pagination parameters
 */
const validatePagination = (req, res, next) => {
  const { page, limit } = req.query;
  
  if (page) {
    const pageNum = parseInt(page);
    if (isNaN(pageNum) || pageNum < 1) {
      return res.status(400).json({
        success: false,
        message: 'Page must be a positive integer'
      });
    }
    if (pageNum > 10000) {
      return res.status(400).json({
        success: false,
        message: 'Page number too large'
      });
    }
  }
  
  if (limit) {
    const limitNum = parseInt(limit);
    if (isNaN(limitNum) || limitNum < 1) {
      return res.status(400).json({
        success: false,
        message: 'Limit must be a positive integer'
      });
    }
    if (limitNum > 1000) {
      return res.status(400).json({
        success: false,
        message: 'Limit cannot exceed 1000'
      });
    }
  }
  
  next();
};

/**
 * Validate email format
 */
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate phone number format
 */
const validatePhoneNumber = (phone) => {
  // Support international format
  const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
  return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 7;
};

/**
 * Validate password strength
 */
const validatePasswordStrength = (req, res, next) => {
  const password = req.body.password || req.body.newPassword;
  
  if (!password) {
    return next(); // Let other validation handle required checks
  }

  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  const errors = [];

  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }
  if (!hasUpperCase) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!hasLowerCase) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!hasNumbers) {
    errors.push('Password must contain at least one number');
  }
  if (!hasSpecialChar) {
    errors.push('Password must contain at least one special character');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Password does not meet security requirements',
      errors: { password: errors }
    });
  }

  next();
};

/**
 * Validate file upload
 */
const validateFileUpload = (allowedTypes = [], maxSize = 10485760) => {
  return (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No files uploaded'
      });
    }

    const errors = [];

    req.files.forEach((file, index) => {
      // Check file type
      if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
        errors.push(`File ${index + 1}: Invalid file type. Allowed types: ${allowedTypes.join(', ')}`);
      }

      // Check file size
      if (file.size > maxSize) {
        errors.push(`File ${index + 1}: File size exceeds limit of ${formatFileSize(maxSize)}`);
      }

      // Check file name
      if (!file.originalname || file.originalname.trim() === '') {
        errors.push(`File ${index + 1}: Invalid file name`);
      }

      // Check for potentially dangerous file names
      const dangerousChars = /[<>:"|?*\x00-\x1f]/;
      if (dangerousChars.test(file.originalname)) {
        errors.push(`File ${index + 1}: File name contains invalid characters`);
      }
    });

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'File validation failed',
        errors: { files: errors }
      });
    }

    next();
  };
};

/**
 * Validate JSON request body
 */
const validateJSON = (req, res, next) => {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    const contentType = req.get('Content-Type');
    
    if (contentType && contentType.includes('application/json')) {
      try {
        if (req.body === undefined) {
          return res.status(400).json({
            success: false,
            message: 'Invalid JSON in request body'
          });
        }
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: 'Invalid JSON in request body'
        });
      }
    }
  }
  
  next();
};

/**
 * Validate search query
 */
const validateSearchQuery = (req, res, next) => {
  const { q, search, query } = req.query;
  const searchTerm = q || search || query;
  
  if (searchTerm) {
    // Check minimum length
    if (searchTerm.length < 2) {
      return res.status(400).json({
        success: false,
        message: 'Search term must be at least 2 characters long'
      });
    }
    
    // Check maximum length
    if (searchTerm.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Search term cannot exceed 100 characters'
      });
    }
    
    // Check for dangerous patterns
    const dangerousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi
    ];
    
    if (dangerousPatterns.some(pattern => pattern.test(searchTerm))) {
      return res.status(400).json({
        success: false,
        message: 'Search term contains invalid patterns'
      });
    }
  }
  
  next();
};

/**
 * Validate sort parameters
 */
const validateSortParams = (allowedFields = []) => {
  return (req, res, next) => {
    const { sortBy, sortOrder } = req.query;
    
    if (sortBy && allowedFields.length > 0) {
      if (!allowedFields.includes(sortBy)) {
        return res.status(400).json({
          success: false,
          message: `Invalid sort field. Allowed fields: ${allowedFields.join(', ')}`
        });
      }
    }
    
    if (sortOrder && !['asc', 'desc'].includes(sortOrder.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: 'Sort order must be "asc" or "desc"'
      });
    }
    
    next();
  };
};

/**
 * Validate request size
 */
const validateRequestSize = (maxSize = 1048576) => { // 1MB default
  return (req, res, next) => {
    const contentLength = req.get('Content-Length');
    
    if (contentLength && parseInt(contentLength) > maxSize) {
      return res.status(413).json({
        success: false,
        message: `Request size exceeds limit of ${formatFileSize(maxSize)}`
      });
    }
    
    next();
  };
};

/**
 * Validate IP address format
 */
const validateIPAddress = (ip) => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

/**
 * Sanitize input to prevent XSS
 */
const sanitizeInput = (req, res, next) => {
  const sanitizeValue = (value) => {
    if (typeof value === 'string') {
      return value
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
    }
    return value;
  };

  const sanitizeObject = (obj) => {
    if (obj && typeof obj === 'object') {
      Object.keys(obj).forEach(key => {
        if (typeof obj[key] === 'object') {
          sanitizeObject(obj[key]);
        } else {
          obj[key] = sanitizeValue(obj[key]);
        }
      });
    }
  };

  // Sanitize body
  if (req.body) {
    sanitizeObject(req.body);
  }

  // Sanitize query
  if (req.query) {
    sanitizeObject(req.query);
  }

  next();
};

/**
 * Format file size helper
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Validate required environment variables
 */
const validateEnvironment = () => {
  const requiredEnvVars = [
    'JWT_SECRET',
    'MONGODB_URI',
    'FLASK_API_URL'
  ];

  const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
};

module.exports = {
  validateRequest,
  validateObjectId,
  validatePatientId,
  validateTestId,
  validateDateRange,
  validatePagination,
  validateEmail,
  validatePhoneNumber,
  validatePasswordStrength,
  validateFileUpload,
  validateJSON,
  validateSearchQuery,
  validateSortParams,
  validateRequestSize,
  validateIPAddress,
  sanitizeInput,
  validateEnvironment,
  formatValidationErrors,
  sanitizeRequestBody
};
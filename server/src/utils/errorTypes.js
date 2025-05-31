// 📁 server/src/utils/errorTypes.js

/**
 * Base Application Error class
 * All custom errors should extend this class
 */
class AppError extends Error {
  constructor(message, statusCode = 500, isOperational = true) {
    super(message);
    
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Convert error to JSON for API responses
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      statusCode: this.statusCode,
      isOperational: this.isOperational,
      timestamp: this.timestamp,
      ...(process.env.NODE_ENV === 'development' && { stack: this.stack })
    };
  }
}

/**
 * Authentication and Authorization Errors
 */
class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401);
    this.type = 'AUTHENTICATION_ERROR';
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Access denied') {
    super(message, 403);
    this.type = 'AUTHORIZATION_ERROR';
  }
}

class TokenExpiredError extends AppError {
  constructor(message = 'Token has expired') {
    super(message, 401);
    this.type = 'TOKEN_EXPIRED_ERROR';
  }
}

class InvalidTokenError extends AppError {
  constructor(message = 'Invalid token provided') {
    super(message, 401);
    this.type = 'INVALID_TOKEN_ERROR';
  }
}

/**
 * Validation Errors
 */
class ValidationError extends AppError {
  constructor(message = 'Validation failed', details = null) {
    super(message, 400);
    this.type = 'VALIDATION_ERROR';
    this.details = details;
  }
}

class RequiredFieldError extends ValidationError {
  constructor(fieldName) {
    super(`Required field missing: ${fieldName}`);
    this.type = 'REQUIRED_FIELD_ERROR';
    this.fieldName = fieldName;
  }
}

class InvalidFormatError extends ValidationError {
  constructor(fieldName, expectedFormat) {
    super(`Invalid format for ${fieldName}. Expected: ${expectedFormat}`);
    this.type = 'INVALID_FORMAT_ERROR';
    this.fieldName = fieldName;
    this.expectedFormat = expectedFormat;
  }
}

class InvalidValueError extends ValidationError {
  constructor(fieldName, value, allowedValues = null) {
    const message = allowedValues 
      ? `Invalid value for ${fieldName}: ${value}. Allowed values: ${allowedValues.join(', ')}`
      : `Invalid value for ${fieldName}: ${value}`;
    super(message);
    this.type = 'INVALID_VALUE_ERROR';
    this.fieldName = fieldName;
    this.value = value;
    this.allowedValues = allowedValues;
  }
}

/**
 * Resource Errors
 */
class NotFoundError extends AppError {
  constructor(resource = 'Resource', id = null) {
    const message = id ? `${resource} with ID '${id}' not found` : `${resource} not found`;
    super(message, 404);
    this.type = 'NOT_FOUND_ERROR';
    this.resource = resource;
    this.resourceId = id;
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409);
    this.type = 'CONFLICT_ERROR';
  }
}

class DuplicateResourceError extends ConflictError {
  constructor(resource, field, value) {
    super(`${resource} with ${field} '${value}' already exists`);
    this.type = 'DUPLICATE_RESOURCE_ERROR';
    this.resource = resource;
    this.field = field;
    this.value = value;
  }
}

/**
 * File and Upload Errors
 */
class FileError extends AppError {
  constructor(message, statusCode = 400) {
    super(message, statusCode);
    this.type = 'FILE_ERROR';
  }
}

class FileTooLargeError extends FileError {
  constructor(maxSize) {
    super(`File size exceeds maximum allowed size of ${maxSize}`);
    this.type = 'FILE_TOO_LARGE_ERROR';
    this.maxSize = maxSize;
  }
}

class InvalidFileTypeError extends FileError {
  constructor(allowedTypes) {
    super(`Invalid file type. Allowed types: ${allowedTypes.join(', ')}`);
    this.type = 'INVALID_FILE_TYPE_ERROR';
    this.allowedTypes = allowedTypes;
  }
}

class CorruptedFileError extends FileError {
  constructor(message = 'File appears to be corrupted') {
    super(message);
    this.type = 'CORRUPTED_FILE_ERROR';
  }
}

class FileNotFoundError extends NotFoundError {
  constructor(filename) {
    super('File', filename);
    this.type = 'FILE_NOT_FOUND_ERROR';
  }
}

/**
 * Database Errors
 */
class DatabaseError extends AppError {
  constructor(message = 'Database operation failed', statusCode = 500) {
    super(message, statusCode);
    this.type = 'DATABASE_ERROR';
  }
}

class ConnectionError extends DatabaseError {
  constructor(message = 'Database connection failed') {
    super(message, 503);
    this.type = 'CONNECTION_ERROR';
  }
}

class TransactionError extends DatabaseError {
  constructor(message = 'Database transaction failed') {
    super(message);
    this.type = 'TRANSACTION_ERROR';
  }
}

class DataIntegrityError extends DatabaseError {
  constructor(message = 'Data integrity constraint violated') {
    super(message, 400);
    this.type = 'DATA_INTEGRITY_ERROR';
  }
}

/**
 * External Service Errors
 */
class ExternalServiceError extends AppError {
  constructor(service, message = 'External service error', statusCode = 503) {
    super(`${service}: ${message}`, statusCode);
    this.type = 'EXTERNAL_SERVICE_ERROR';
    this.service = service;
  }
}

class FlaskAPIError extends ExternalServiceError {
  constructor(message = 'Flask API error', statusCode = 503) {
    super('Flask Diagnosis API', message, statusCode);
    this.type = 'FLASK_API_ERROR';
  }
}

class TimeoutError extends ExternalServiceError {
  constructor(service, timeout) {
    super(service, `Request timed out after ${timeout}ms`, 408);
    this.type = 'TIMEOUT_ERROR';
    this.timeout = timeout;
  }
}

/**
 * Business Logic Errors
 */
class BusinessLogicError extends AppError {
  constructor(message, statusCode = 400) {
    super(message, statusCode);
    this.type = 'BUSINESS_LOGIC_ERROR';
  }
}

class DiagnosisError extends BusinessLogicError {
  constructor(message = 'Diagnosis processing failed') {
    super(message);
    this.type = 'DIAGNOSIS_ERROR';
  }
}

class TestStateError extends BusinessLogicError {
  constructor(currentState, requiredState) {
    super(`Test is in '${currentState}' state, but '${requiredState}' state is required for this operation`);
    this.type = 'TEST_STATE_ERROR';
    this.currentState = currentState;
    this.requiredState = requiredState;
  }
}

class PatientStateError extends BusinessLogicError {
  constructor(message = 'Invalid patient state for this operation') {
    super(message);
    this.type = 'PATIENT_STATE_ERROR';
  }
}

/**
 * Rate Limiting and Security Errors
 */
class RateLimitError extends AppError {
  constructor(retryAfter = 60) {
    super('Rate limit exceeded. Too many requests.');
    this.statusCode = 429;
    this.type = 'RATE_LIMIT_ERROR';
    this.retryAfter = retryAfter;
  }
}

class SecurityError extends AppError {
  constructor(message = 'Security violation detected', statusCode = 403) {
    super(message, statusCode);
    this.type = 'SECURITY_ERROR';
  }
}

class SuspiciousActivityError extends SecurityError {
  constructor(message = 'Suspicious activity detected') {
    super(message, 403);
    this.type = 'SUSPICIOUS_ACTIVITY_ERROR';
  }
}

/**
 * Configuration and Environment Errors
 */
class ConfigurationError extends AppError {
  constructor(message = 'Configuration error', statusCode = 500) {
    super(message, statusCode, false); // Not operational
    this.type = 'CONFIGURATION_ERROR';
  }
}

class EnvironmentError extends ConfigurationError {
  constructor(missingVars) {
    super(`Missing required environment variables: ${missingVars.join(', ')}`);
    this.type = 'ENVIRONMENT_ERROR';
    this.missingVars = missingVars;
  }
}

/**
 * System and Resource Errors
 */
class SystemError extends AppError {
  constructor(message = 'System error', statusCode = 500) {
    super(message, statusCode, false); // Not operational
    this.type = 'SYSTEM_ERROR';
  }
}

class ResourceExhaustedError extends SystemError {
  constructor(resource = 'system resources') {
    super(`${resource} exhausted`, 507);
    this.type = 'RESOURCE_EXHAUSTED_ERROR';
    this.resource = resource;
  }
}

class MaintenanceError extends AppError {
  constructor(message = 'System is under maintenance') {
    super(message, 503);
    this.type = 'MAINTENANCE_ERROR';
  }
}

/**
 * Integration Errors
 */
class IntegrationError extends AppError {
  constructor(integration, message = 'Integration failed', statusCode = 502) {
    super(`${integration}: ${message}`, statusCode);
    this.type = 'INTEGRATION_ERROR';
    this.integration = integration;
  }
}

class HospitalIntegrationError extends IntegrationError {
  constructor(message = 'Hospital system integration failed') {
    super('Hospital System', message);
    this.type = 'HOSPITAL_INTEGRATION_ERROR';
  }
}

/**
 * Error Factory - Create errors from different sources
 */
class ErrorFactory {
  /**
   * Create AppError from Express validator errors
   */
  static fromValidationResult(validationResult) {
    const errors = validationResult.array();
    const details = {};
    
    errors.forEach(error => {
      if (!details[error.param]) {
        details[error.param] = [];
      }
      details[error.param].push(error.msg);
    });

    return new ValidationError('Validation failed', details);
  }

  /**
   * Create AppError from Mongoose error
   */
  static fromMongooseError(error) {
    if (error.name === 'ValidationError') {
      const details = {};
      Object.keys(error.errors).forEach(key => {
        details[key] = [error.errors[key].message];
      });
      return new ValidationError('Validation failed', details);
    }

    if (error.name === 'CastError') {
      return new InvalidFormatError(error.path, 'valid ObjectId');
    }

    if (error.code === 11000) {
      const field = Object.keys(error.keyValue)[0];
      const value = error.keyValue[field];
      return new DuplicateResourceError('Resource', field, value);
    }

    return new DatabaseError(error.message);
  }

  /**
   * Create AppError from HTTP response
   */
  static fromHTTPResponse(response, service = 'External Service') {
    const { status, statusText, data } = response;
    const message = data?.message || statusText || 'Unknown error';
    
    if (status >= 500) {
      return new ExternalServiceError(service, message, status);
    }
    
    if (status === 404) {
      return new NotFoundError('Resource');
    }
    
    if (status === 401) {
      return new AuthenticationError(message);
    }
    
    if (status === 403) {
      return new AuthorizationError(message);
    }
    
    if (status === 429) {
      return new RateLimitError();
    }
    
    return new AppError(message, status);
  }
}

/**
 * Error Helper functions
 */
const isOperationalError = (error) => {
  return error instanceof AppError && error.isOperational;
};

const formatErrorForAPI = (error) => {
  if (error instanceof AppError) {
    return error.toJSON();
  }
  
  return {
    name: error.name || 'Error',
    message: error.message || 'Unknown error',
    statusCode: error.statusCode || 500,
    isOperational: false,
    timestamp: new Date().toISOString()
  };
};

const logError = (error, context = {}) => {
  const logger = require('./logger');
  
  logger.error('Application error:', error, {
    type: error.type || 'UNKNOWN_ERROR',
    isOperational: error.isOperational || false,
    ...context
  });
};

module.exports = {
  // Base errors
  AppError,
  
  // Authentication errors
  AuthenticationError,
  AuthorizationError,
  TokenExpiredError,
  InvalidTokenError,
  
  // Validation errors
  ValidationError,
  RequiredFieldError,
  InvalidFormatError,
  InvalidValueError,
  
  // Resource errors
  NotFoundError,
  ConflictError,
  DuplicateResourceError,
  
  // File errors
  FileError,
  FileTooLargeError,
  InvalidFileTypeError,
  CorruptedFileError,
  FileNotFoundError,
  
  // Database errors
  DatabaseError,
  ConnectionError,
  TransactionError,
  DataIntegrityError,
  
  // External service errors
  ExternalServiceError,
  FlaskAPIError,
  TimeoutError,
  
  // Business logic errors
  BusinessLogicError,
  DiagnosisError,
  TestStateError,
  PatientStateError,
  
  // Security errors
  RateLimitError,
  SecurityError,
  SuspiciousActivityError,
  
  // System errors
  ConfigurationError,
  EnvironmentError,
  SystemError,
  ResourceExhaustedError,
  MaintenanceError,
  
  // Integration errors
  IntegrationError,
  HospitalIntegrationError,
  
  // Utilities
  ErrorFactory,
  isOperationalError,
  formatErrorForAPI,
  logError
};
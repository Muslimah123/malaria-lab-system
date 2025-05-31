// 📁 server/src/utils/constants.js

/**
 * User Roles and Permissions
 */
const USER_ROLES = {
  ADMIN: 'admin',
  SUPERVISOR: 'supervisor',
  TECHNICIAN: 'technician'
};

const DEFAULT_PERMISSIONS = {
  [USER_ROLES.ADMIN]: {
    canUploadSamples: true,
    canViewAllTests: true,
    canDeleteTests: true,
    canManageUsers: true,
    canExportReports: true
  },
  [USER_ROLES.SUPERVISOR]: {
    canUploadSamples: true,
    canViewAllTests: true,
    canDeleteTests: false,
    canManageUsers: false,
    canExportReports: true
  },
  [USER_ROLES.TECHNICIAN]: {
    canUploadSamples: true,
    canViewAllTests: false,
    canDeleteTests: false,
    canManageUsers: false,
    canExportReports: true
  }
};

/**
 * Test Status and Priority
 */
const TEST_STATUS = {
  PENDING: 'pending',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled'
};

const TEST_PRIORITY = {
  LOW: 'low',
  NORMAL: 'normal',
  HIGH: 'high',
  URGENT: 'urgent'
};

const SAMPLE_TYPES = {
  BLOOD_SMEAR: 'blood_smear',
  THICK_SMEAR: 'thick_smear',
  THIN_SMEAR: 'thin_smear'
};

/**
 * Diagnosis Results
 */
const DIAGNOSIS_STATUS = {
  POSITIVE: 'POS',
  NEGATIVE: 'NEG'
};

const PARASITE_TYPES = {
  PLASMODIUM_FALCIPARUM: 'PF',
  PLASMODIUM_MALARIAE: 'PM',
  PLASMODIUM_OVALE: 'PO',
  PLASMODIUM_VIVAX: 'PV'
};

const PARASITE_NAMES = {
  [PARASITE_TYPES.PLASMODIUM_FALCIPARUM]: 'Plasmodium Falciparum',
  [PARASITE_TYPES.PLASMODIUM_MALARIAE]: 'Plasmodium Malariae',
  [PARASITE_TYPES.PLASMODIUM_OVALE]: 'Plasmodium Ovale',
  [PARASITE_TYPES.PLASMODIUM_VIVAX]: 'Plasmodium Vivax'
};

const SEVERITY_LEVELS = {
  NEGATIVE: 'negative',
  MILD: 'mild',
  MODERATE: 'moderate',
  SEVERE: 'severe'
};

/**
 * Patient Information
 */
const GENDER_OPTIONS = {
  MALE: 'male',
  FEMALE: 'female',
  OTHER: 'other',
  UNKNOWN: 'unknown'
};

const BLOOD_TYPES = {
  A_POSITIVE: 'A+',
  A_NEGATIVE: 'A-',
  B_POSITIVE: 'B+',
  B_NEGATIVE: 'B-',
  AB_POSITIVE: 'AB+',
  AB_NEGATIVE: 'AB-',
  O_POSITIVE: 'O+',
  O_NEGATIVE: 'O-',
  UNKNOWN: 'unknown'
};

/**
 * File Upload Constants
 */
const ALLOWED_IMAGE_TYPES = [
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/tiff',
  'image/tif'
];

const ALLOWED_IMAGE_EXTENSIONS = [
  '.jpg',
  '.jpeg',
  '.png',
  '.tiff',
  '.tif'
];

const FILE_SIZE_LIMITS = {
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  MAX_FILES_PER_REQUEST: 20,
  MIN_FILE_SIZE: 1024, // 1KB
  MAX_TOTAL_SIZE: 100 * 1024 * 1024 // 100MB total
};

/**
 * Upload Session Status
 */
const UPLOAD_SESSION_STATUS = {
  ACTIVE: 'active',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
  EXPIRED: 'expired'
};

const UPLOAD_FILE_STATUS = {
  UPLOADING: 'uploading',
  COMPLETED: 'completed',
  FAILED: 'failed',
  PROCESSING: 'processing'
};

/**
 * Audit Log Constants
 */
const AUDIT_ACTIONS = {
  // Authentication
  LOGIN: 'login',
  LOGOUT: 'logout',
  FAILED_LOGIN: 'failed_login',
  PASSWORD_CHANGE: 'password_change',
  
  // User management
  USER_CREATED: 'user_created',
  USER_UPDATED: 'user_updated',
  USER_DELETED: 'user_deleted',
  USER_ACTIVATED: 'user_activated',
  USER_DEACTIVATED: 'user_deactivated',
  
  // Patient management
  PATIENT_CREATED: 'patient_created',
  PATIENT_UPDATED: 'patient_updated',
  PATIENT_DELETED: 'patient_deleted',
  PATIENT_VIEWED: 'patient_viewed',
  
  // Test operations
  TEST_CREATED: 'test_created',
  TEST_UPDATED: 'test_updated',
  TEST_DELETED: 'test_deleted',
  TEST_STARTED: 'test_started',
  TEST_COMPLETED: 'test_completed',
  TEST_CANCELLED: 'test_cancelled',
  
  // Sample operations
  SAMPLE_UPLOADED: 'sample_uploaded',
  SAMPLE_DELETED: 'sample_deleted',
  SAMPLE_DOWNLOADED: 'sample_downloaded',
  
  // Diagnosis operations
  DIAGNOSIS_COMPLETED: 'diagnosis_completed',
  DIAGNOSIS_REVIEWED: 'diagnosis_reviewed',
  DIAGNOSIS_OVERRIDDEN: 'diagnosis_overridden',
  
  // Report operations
  REPORT_GENERATED: 'report_generated',
  REPORT_EXPORTED: 'report_exported',
  REPORT_PRINTED: 'report_printed',
  REPORT_SHARED: 'report_shared',
  
  // Integration operations
  DATA_EXPORTED_TO_HOSPITAL: 'data_exported_to_hospital',
  API_CALL_MADE: 'api_call_made',
  INTEGRATION_FAILED: 'integration_failed',
  
  // System operations
  SYSTEM_BACKUP: 'system_backup',
  SYSTEM_MAINTENANCE: 'system_maintenance',
  DATABASE_CLEANUP: 'database_cleanup',
  
  // Security events
  UNAUTHORIZED_ACCESS_ATTEMPT: 'unauthorized_access_attempt',
  DATA_BREACH_DETECTED: 'data_breach_detected',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity'
};

const RISK_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

const RESOURCE_TYPES = {
  USER: 'user',
  PATIENT: 'patient',
  TEST: 'test',
  DIAGNOSIS: 'diagnosis',
  SAMPLE: 'sample',
  REPORT: 'report',
  SYSTEM: 'system'
};

/**
 * API Response Status
 */
const API_STATUS = {
  SUCCESS: 'success',
  ERROR: 'error',
  FAILURE: 'failure',
  PARTIAL: 'partial'
};

/**
 * Environment Constants
 */
const ENVIRONMENTS = {
  DEVELOPMENT: 'development',
  STAGING: 'staging',
  PRODUCTION: 'production',
  TEST: 'test'
};

const LOG_LEVELS = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
  VERBOSE: 'verbose'
};

/**
 * Rate Limiting Constants
 */
const RATE_LIMITS = {
  GENERAL: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000
  },
  LOGIN: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5
  },
  PASSWORD_RESET: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3
  },
  FILE_UPLOAD: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 50
  },
  DIAGNOSIS: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100
  }
};

/**
 * Database Configuration
 */
const DB_CONFIG = {
  CONNECTION_TIMEOUT: 10000, // 10 seconds
  SOCKET_TIMEOUT: 45000, // 45 seconds
  MAX_POOL_SIZE: 10,
  SERVER_SELECTION_TIMEOUT: 5000 // 5 seconds
};

/**
 * JWT Configuration
 */
const JWT_CONFIG = {
  DEFAULT_EXPIRES_IN: '1h',
  REFRESH_EXPIRES_IN: '7d',
  ALGORITHM: 'HS256',
  ISSUER: 'malaria-lab-system',
  AUDIENCE: 'malaria-lab-users'
};

/**
 * Flask API Configuration
 */
const FLASK_API_CONFIG = {
  TIMEOUT: 300000, // 5 minutes
  RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 5000, // 5 seconds
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  SUPPORTED_FORMATS: ALLOWED_IMAGE_TYPES
};

/**
 * Report Export Formats
 */
const EXPORT_FORMATS = {
  PDF: 'pdf',
  JSON: 'json',
  CSV: 'csv',
  XLSX: 'xlsx'
};

/**
 * Integration Status
 */
const INTEGRATION_STATUS = {
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  FAILED: 'failed',
  RETRYING: 'retrying'
};

/**
 * System Health Status
 */
const HEALTH_STATUS = {
  HEALTHY: 'healthy',
  UNHEALTHY: 'unhealthy',
  DEGRADED: 'degraded',
  UNKNOWN: 'unknown'
};

/**
 * Cache Configuration
 */
const CACHE_CONFIG = {
  DEFAULT_TTL: 3600, // 1 hour
  SESSION_TTL: 86400, // 24 hours
  RATE_LIMIT_TTL: 900, // 15 minutes
  BLACKLIST_TTL: 3600 // 1 hour
};

/**
 * File Storage Configuration
 */
const STORAGE_CONFIG = {
  UPLOAD_DIR: 'uploads',
  IMAGE_DIR: 'images',
  THUMBNAIL_DIR: 'thumbnails',
  TEMP_DIR: 'temp',
  EXPORT_DIR: 'exports',
  BACKUP_DIR: 'backups'
};

/**
 * Socket Events
 */
const SOCKET_EVENTS = {
  // Connection events
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  ERROR: 'error',
  
  // Test events
  TEST_CREATED: 'test:created',
  TEST_UPDATED: 'test:updated',
  TEST_STATUS_CHANGED: 'test:statusChanged',
  TEST_ASSIGNED: 'test:assigned',
  
  // Upload events
  UPLOAD_PROGRESS: 'upload:progress',
  UPLOAD_COMPLETED: 'upload:completed',
  UPLOAD_FAILED: 'upload:failed',
  
  // Diagnosis events
  DIAGNOSIS_STARTED: 'diagnosis:started',
  DIAGNOSIS_COMPLETED: 'diagnosis:completed',
  DIAGNOSIS_FAILED: 'diagnosis:failed',
  DIAGNOSIS_REVIEWED: 'diagnosis:reviewed',
  
  // Notification events
  NOTIFICATION: 'notification',
  ALERT: 'alert',
  WARNING: 'warning'
};

/**
 * Default Configuration Values
 */
const DEFAULTS = {
  PAGE_SIZE: 20,
  MAX_PAGE_SIZE: 100,
  SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
  PASSWORD_MIN_LENGTH: 8,
  USERNAME_MIN_LENGTH: 3,
  USERNAME_MAX_LENGTH: 50,
  RETENTION_PERIOD_DAYS: 2555, // ~7 years
  CLEANUP_INTERVAL_HOURS: 24
};

/**
 * Validation Patterns
 */
const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PHONE: /^\+?[\d\s\-\(\)]+$/,
  PATIENT_ID: /^PAT-\d{8}-\d{3}$/,
  TEST_ID: /^TEST-\d{8}-\d{3}$/,
  USERNAME: /^[a-zA-Z0-9_]+$/,
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
  MONGODB_OBJECT_ID: /^[0-9a-fA-F]{24}$/
};

/**
 * HTTP Status Codes
 */
const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
  INSUFFICIENT_STORAGE: 507
};

/**
 * Quality Thresholds
 */
const QUALITY_THRESHOLDS = {
  MIN_CONFIDENCE: 0.7,
  MIN_IMAGE_WIDTH: 100,
  MIN_IMAGE_HEIGHT: 100,
  MAX_IMAGE_WIDTH: 4000,
  MAX_IMAGE_HEIGHT: 4000,
  MIN_ASPECT_RATIO: 0.5,
  MAX_ASPECT_RATIO: 2.0
};

/**
 * Error Codes
 */
const ERROR_CODES = {
  // Authentication
  AUTH_TOKEN_MISSING: 'AUTH_TOKEN_MISSING',
  AUTH_TOKEN_INVALID: 'AUTH_TOKEN_INVALID',
  AUTH_TOKEN_EXPIRED: 'AUTH_TOKEN_EXPIRED',
  AUTH_CREDENTIALS_INVALID: 'AUTH_CREDENTIALS_INVALID',
  AUTH_PERMISSION_DENIED: 'AUTH_PERMISSION_DENIED',
  
  // Validation
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  REQUIRED_FIELD_MISSING: 'REQUIRED_FIELD_MISSING',
  INVALID_FORMAT: 'INVALID_FORMAT',
  INVALID_VALUE: 'INVALID_VALUE',
  
  // Resources
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RESOURCE_CONFLICT: 'RESOURCE_CONFLICT',
  RESOURCE_DUPLICATE: 'RESOURCE_DUPLICATE',
  
  // Files
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  FILE_INVALID_TYPE: 'FILE_INVALID_TYPE',
  FILE_CORRUPTED: 'FILE_CORRUPTED',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  
  // System
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  SYSTEM_MAINTENANCE: 'SYSTEM_MAINTENANCE'
};

module.exports = {
  USER_ROLES,
  DEFAULT_PERMISSIONS,
  TEST_STATUS,
  TEST_PRIORITY,
  SAMPLE_TYPES,
  DIAGNOSIS_STATUS,
  PARASITE_TYPES,
  PARASITE_NAMES,
  SEVERITY_LEVELS,
  GENDER_OPTIONS,
  BLOOD_TYPES,
  ALLOWED_IMAGE_TYPES,
  ALLOWED_IMAGE_EXTENSIONS,
  FILE_SIZE_LIMITS,
  UPLOAD_SESSION_STATUS,
  UPLOAD_FILE_STATUS,
  AUDIT_ACTIONS,
  RISK_LEVELS,
  RESOURCE_TYPES,
  API_STATUS,
  ENVIRONMENTS,
  LOG_LEVELS,
  RATE_LIMITS,
  DB_CONFIG,
  JWT_CONFIG,
  FLASK_API_CONFIG,
  EXPORT_FORMATS,
  INTEGRATION_STATUS,
  HEALTH_STATUS,
  CACHE_CONFIG,
  STORAGE_CONFIG,
  SOCKET_EVENTS,
  DEFAULTS,
  VALIDATION_PATTERNS,
  HTTP_STATUS,
  QUALITY_THRESHOLDS,
  ERROR_CODES
};
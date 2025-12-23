// 📁 client/src/utils/constants.js
// Updated to match your backend structure exactly

// Application Routes
export const ROUTES = {
  // Public routes
  LOGIN: '/login',
  FORGOT_PASSWORD: '/forgot-password',
  RESET_PASSWORD: '/reset-password',
  
  // Protected routes
  DASHBOARD: '/dashboard',
  UPLOAD: '/upload',
  RESULTS: '/results',
  HISTORY: '/history',
  PATIENTS: '/patients',
  USERS: '/users',
  SETTINGS: '/settings',
  PROFILE: '/profile',
  AUDIT: '/audit',
  REPORTS: '/reports'
};

// User Roles (matching your backend User model)
export const USER_ROLES = {
  ADMIN: 'admin',
  SUPERVISOR: 'supervisor',
  TECHNICIAN: 'technician'
};

// User Permissions (matching your backend User model permissions structure)
export const PERMISSIONS = {
  CAN_UPLOAD_SAMPLES: 'canUploadSamples',
  CAN_VIEW_ALL_TESTS: 'canViewAllTests',
  CAN_DELETE_TESTS: 'canDeleteTests',
  CAN_MANAGE_USERS: 'canManageUsers',
  CAN_EXPORT_REPORTS: 'canExportReports'
};

// Test Statuses (matching backend Test model)
export const TEST_STATUSES = {
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress', // alias for processing
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  REJECTED: 'rejected',
  REVIEW: 'review',
  ERROR: 'error',
  FAILED: 'failed',
  CANCELLED: 'cancelled'
};

// Test Results (matching backend output)
export const TEST_RESULTS = {
  POSITIVE: 'POSITIVE',
  NEGATIVE: 'NEGATIVE'
};

// Test Priorities
export const TEST_PRIORITIES = {
  LOW: 'low',
  NORMAL: 'normal',
  HIGH: 'high',
  URGENT: 'urgent'
};

// Sample Types
export const SAMPLE_TYPES = {
  BLOOD_SMEAR: 'blood_smear',
  THICK_SMEAR: 'thick_smear',
  THIN_SMEAR: 'thin_smear'
};

// Patient Gender Options (matching your backend Patient model)
export const GENDER_OPTIONS = [
  { value: 'male', label: 'Male' },
  { value: 'female', label: 'Female' },
  { value: 'other', label: 'Other' },
  { value: 'unknown', label: 'Unknown' }
];

// Blood Type Options (matching your backend Patient model)
export const BLOOD_TYPES = [
  'A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'unknown'
];

// Upload Configuration
export const UPLOAD_CONFIG = {
  MAX_FILES: 10,
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/tiff'],
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks
  ALLOWED_EXTENSIONS: ['.jpg', '.jpeg', '.png', '.tiff', '.tif']
};

// Audit Log Actions (matching your backend auditService)
export const AUDIT_ACTIONS = {
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
  
  // Security events
  UNAUTHORIZED_ACCESS_ATTEMPT: 'unauthorized_access_attempt',
  DATA_BREACH_DETECTED: 'data_breach_detected',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity'
};

// Audit Risk Levels (matching your backend auditService)
export const AUDIT_RISK_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

// Audit Statuses
export const AUDIT_STATUSES = {
  SUCCESS: 'success',
  FAILURE: 'failure',
  PARTIAL: 'partial'
};

// Patient ID Format (matching your backend Patient model)
export const PATIENT_ID_FORMAT = /^PAT-\d{8}-\d{3}$/;

// API Response Status
export const API_STATUS = {
  SUCCESS: 'success',
  ERROR: 'error',
  LOADING: 'loading'
};

// Notification Types
export const NOTIFICATION_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info'
};

// Dashboard Refresh Intervals
export const REFRESH_INTERVALS = {
  DASHBOARD: 30000, // 30 seconds
  TESTS: 15000, // 15 seconds
  UPLOADS: 5000, // 5 seconds
  REAL_TIME: 1000 // 1 second
};

// File Processing Stages
export const PROCESSING_STAGES = {
  PREPROCESSING: 'preprocessing',
  SEGMENTATION: 'segmentation',
  FEATURE_EXTRACTION: 'feature_extraction',
  CLASSIFICATION: 'classification',
  REPORT_GENERATION: 'report_generation'
};

// Date Formats
export const DATE_FORMATS = {
  DISPLAY: 'MMM DD, YYYY',
  DISPLAY_WITH_TIME: 'MMM DD, YYYY HH:mm',
  INPUT: 'YYYY-MM-DD',
  ISO: 'YYYY-MM-DDTHH:mm:ss.sssZ',
  TIME_ONLY: 'HH:mm'
};

// Validation Rules
export const VALIDATION_RULES = {
  PASSWORD: {
    MIN_LENGTH: 6,
    PATTERN: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    MESSAGE: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
  },
  EMAIL: {
    PATTERN: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
    MESSAGE: 'Please enter a valid email address'
  },
  PHONE: {
    PATTERN: /^[\+]?[1-9][\d]{0,15}$/,
    MESSAGE: 'Please enter a valid phone number'
  },
  USERNAME: {
    MIN_LENGTH: 3,
    MAX_LENGTH: 50,
    PATTERN: /^[a-zA-Z0-9_-]+$/,
    MESSAGE: 'Username can only contain letters, numbers, hyphens, and underscores'
  }
};

// Error Messages
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network error - please check your connection',
  UNAUTHORIZED: 'Your session has expired. Please log in again.',
  FORBIDDEN: 'You do not have permission to perform this action',
  NOT_FOUND: 'The requested resource was not found',
  SERVER_ERROR: 'An internal server error occurred. Please try again later.',
  VALIDATION_ERROR: 'Please check your input and try again',
  UPLOAD_ERROR: 'File upload failed. Please try again.',
  PROCESSING_ERROR: 'Processing failed. Please try again.'
};

// Success Messages
export const SUCCESS_MESSAGES = {
  LOGIN: 'Login successful',
  LOGOUT: 'Logout successful',
  REGISTER: 'Registration successful',
  PASSWORD_CHANGED: 'Password changed successfully',
  PASSWORD_RESET: 'Password reset email sent',
  PROFILE_UPDATED: 'Profile updated successfully',
  PATIENT_CREATED: 'Patient created successfully',
  PATIENT_UPDATED: 'Patient updated successfully',
  TEST_CREATED: 'Test created successfully',
  UPLOAD_COMPLETE: 'Files uploaded successfully',
  PROCESSING_COMPLETE: 'Processing completed successfully'
};

// Local Storage Keys
export const STORAGE_KEYS = {
  AUTH_TOKEN: 'authToken',
  REFRESH_TOKEN: 'refreshToken',
  USER_PREFERENCES: 'userPreferences',
  THEME: 'theme',
  LANGUAGE: 'language'
};

// Token management
export const TOKEN_KEY = 'authToken';

// Socket configuration
export const SOCKET_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:3001';

// Socket Events
export const SOCKET_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  ERROR: 'error',
  
  // Authentication events
  AUTHENTICATED: 'authenticated',
  UNAUTHENTICATED: 'unauthenticated',
  
  // Test events
  TEST_CREATED: 'test_created',
  TEST_UPDATED: 'test_updated',
  TEST_COMPLETED: 'test_completed',
  TEST_FAILED: 'test_failed',
  
  // Upload events
  UPLOAD_PROGRESS: 'upload_progress',
  UPLOAD_COMPLETED: 'upload_completed',
  UPLOAD_FAILED: 'upload_failed',
  
  // Diagnosis events
  DIAGNOSIS_STARTED: 'diagnosis_started',
  DIAGNOSIS_COMPLETED: 'diagnosis_completed',
  DIAGNOSIS_FAILED: 'diagnosis_failed',
  
  // Notification events
  NOTIFICATION: 'notification',
  ALERT: 'alert',
  
  // System events
  SYSTEM_UPDATE: 'system_update',
  MAINTENANCE: 'maintenance'
};

// Upload Statuses
export const UPLOAD_STATUSES = {
  PENDING: 'pending',
  UPLOADING: 'uploading',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled'
};

// Theme Configuration
export const THEME_CONFIG = {
  COLORS: {
    PRIMARY: {
      50: '#eff6ff',
      100: '#dbeafe',
      200: '#bfdbfe',
      300: '#93c5fd',
      400: '#60a5fa',
      500: '#3b82f6',
      600: '#2563eb',
      700: '#1d4ed8',
      800: '#1e40af',
      900: '#1e3a8a'
    },
    SUCCESS: '#10b981',
    WARNING: '#f59e0b',
    ERROR: '#ef4444',
    INFO: '#3b82f6'
  }
};

// Pagination Defaults
export const PAGINATION_DEFAULTS = {
  PAGE: 1,
  LIMIT: 20,
  MAX_LIMIT: 100
};

// Environment Configuration
export const ENV_CONFIG = {
  DEVELOPMENT: 'development',
  PRODUCTION: 'production',
  TEST: 'test'
};

// Role-based Navigation Items (for generating menus)
export const NAVIGATION_ITEMS = {
  [USER_ROLES.TECHNICIAN]: [
    { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'dashboard' },
    { path: ROUTES.UPLOAD, label: 'Upload Samples', icon: 'upload' },
    { path: ROUTES.RESULTS, label: 'Results', icon: 'results' },
    { path: ROUTES.HISTORY, label: 'Test History', icon: 'history' },
    { path: ROUTES.PATIENTS, label: 'Patients', icon: 'patients' },
    { path: ROUTES.PROFILE, label: 'Profile', icon: 'profile' }
  ],
  [USER_ROLES.SUPERVISOR]: [
    { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'dashboard' },
    { path: ROUTES.UPLOAD, label: 'Upload Samples', icon: 'upload' },
    { path: ROUTES.RESULTS, label: 'Results', icon: 'results' },
    { path: ROUTES.HISTORY, label: 'Test History', icon: 'history' },
    { path: ROUTES.PATIENTS, label: 'Patients', icon: 'patients' },
    { path: ROUTES.REPORTS, label: 'Reports', icon: 'reports' },
    { path: ROUTES.AUDIT, label: 'Audit Logs', icon: 'audit' },
    { path: ROUTES.PROFILE, label: 'Profile', icon: 'profile' }
  ],
  [USER_ROLES.ADMIN]: [
    { path: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'dashboard' },
    { path: ROUTES.UPLOAD, label: 'Upload Samples', icon: 'upload' },
    { path: ROUTES.RESULTS, label: 'Results', icon: 'results' },
    { path: ROUTES.HISTORY, label: 'Test History', icon: 'history' },
    { path: ROUTES.PATIENTS, label: 'Patients', icon: 'patients' },
    { path: ROUTES.USERS, label: 'User Management', icon: 'users' },
    { path: ROUTES.REPORTS, label: 'Reports', icon: 'reports' },
    { path: ROUTES.AUDIT, label: 'Audit Logs', icon: 'audit' },
    { path: ROUTES.SETTINGS, label: 'Settings', icon: 'settings' },
    { path: ROUTES.PROFILE, label: 'Profile', icon: 'profile' }
  ]
};
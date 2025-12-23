// 📁 client/src/types/user.types.ts
// TypeScript interfaces for enhanced user management system

/**
 * Base User interface matching the User model
 */
export interface User {
  _id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'admin' | 'supervisor' | 'technician';
  isActive: boolean;
  phoneNumber?: string;
  department: string;
  licenseNumber?: string;
  permissions: {
    canUploadSamples: boolean;
    canViewAllTests: boolean;
    canDeleteTests: boolean;
    canManageUsers: boolean;
    canExportReports: boolean;
  };
  createdAt: string;
  updatedAt: string;
  lastLogin?: string;
}

/**
 * Enhanced User with Test Statistics
 * This is what the backend returns in the enhanced endpoints
 */
export interface UserWithStats extends User {
  // Test processing statistics
  testsProcessed: number;
  completedTests: number;
  pendingTests: number;
  failedTests: number;
  
  // Performance metrics
  successRate: number; // Percentage (0-100)
  avgProcessingTime?: number; // Average processing time in minutes
  
  // Activity tracking
  lastTestDate?: string; // ISO date string of last test processed
  
  // Computed fields for display
  fullName?: string; // firstName + lastName
}

/**
 * Top Performer data structure
 */
export interface TopPerformer {
  _id: string;
  firstName: string;
  lastName: string;
  fullName: string;
  email: string;
  role: string;
  department?: string;
  testsProcessed: number;
  completedTests: number;
  failedTests: number;
  successRate: number;
  performanceScore: number; // Weighted performance score
  avgProcessingTime?: number; // In minutes
  lastLogin?: string;
}

/**
 * System-wide User Statistics
 */
export interface UserStatistics {
  // Basic counts
  totalUsers: number;
  activeUsers: number;
  inactiveUsers: number;
  
  // Test-related statistics
  totalTestsProcessed: number;
  totalCompletedTests: number;
  totalPendingTests: number;
  totalFailedTests: number;
  avgTestsPerUser: number;
  
  // Performance metrics
  overallSuccessRate: number; // Percentage
  activeUserPercentage: number; // Percentage
  
  // Role distribution
  adminCount: number;
  supervisorCount: number;
  technicianCount: number;
  usersWithNoTests: number;
}

/**
 * API Response for user list with statistics
 */
export interface UsersListResponse {
  success: boolean;
  data: UserWithStats[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  statistics: {
    totalUsers: number;
    totalTestsProcessed: number;
    averageTestsPerUser: number;
    averageSuccessRate: number;
  };
}

/**
 * API Response for user search
 */
export interface UsersSearchResponse {
  success: boolean;
  data: UserWithStats[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  searchQuery: string;
}

/**
 * API Response for user statistics
 */
export interface UserStatisticsResponse {
  success: boolean;
  data: UserStatistics;
}

/**
 * API Response for top performers
 */
export interface TopPerformersResponse {
  success: boolean;
  data: TopPerformer[];
  metadata: {
    requestedLimit: number;
    actualLimit: number;
    resultCount: number;
    generatedAt: string;
  };
}

/**
 * User filter options
 */
export interface UserFilters {
  role: 'all' | 'admin' | 'supervisor' | 'technician';
  status: 'all' | 'active' | 'inactive';
  page?: number;
  limit?: number;
}

/**
 * User search parameters
 */
export interface UserSearchParams extends UserFilters {
  query: string;
}

/**
 * API Request types
 */
export interface UpdateUserRoleRequest {
  role: 'admin' | 'supervisor' | 'technician';
}

export interface ResetPasswordRequest {
  newPassword: string;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: 'admin' | 'supervisor' | 'technician';
  phoneNumber?: string;
  department?: string;
  licenseNumber?: string;
}

export interface UpdateUserRequest {
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  department?: string;
  licenseNumber?: string;
  isActive?: boolean;
}

/**
 * Redux State types
 */
export interface UsersState {
  // Core data
  users: UserWithStats[];
  isLoading: boolean;
  error: string | null;
  
  // Pagination
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  
  // Statistics
  statistics: {
    totalUsers: number;
    totalTestsProcessed: number;
    averageTestsPerUser: number;
    averageSuccessRate: number;
  };
  
  // System statistics
  systemStatistics: UserStatistics;
  isLoadingStatistics: boolean;
  statisticsError: string | null;
  
  // Top performers
  topPerformers: TopPerformer[];
  isLoadingTopPerformers: boolean;
  topPerformersError: string | null;
  
  // Search
  searchResults: UserWithStats[];
  isSearching: boolean;
  searchError: string | null;
  lastSearchQuery: string;
  
  // UI state
  filters: UserFilters;
  selectedUsers: string[];
  
  // Action states
  isUpdatingRole: boolean;
  isTogglingStatus: boolean;
  isResettingPassword: boolean;
  isDeleting: boolean;
  
  // Messages
  successMessage: string | null;
  
  // Metadata
  lastUpdated: string | null;
}

/**
 * User table column configuration
 */
export interface UserTableColumn {
  key: keyof UserWithStats | 'actions';
  label: string;
  sortable?: boolean;
  width?: string;
  render?: (user: UserWithStats) => React.ReactNode;
}

/**
 * User action types for context menus/buttons
 */
export type UserAction = 
  | 'view'
  | 'edit'
  | 'updateRole'
  | 'toggleStatus'
  | 'resetPassword'
  | 'delete'
  | 'viewTests'
  | 'exportData';

/**
 * User performance metrics for charts/dashboards
 */
export interface UserPerformanceMetrics {
  userId: string;
  userName: string;
  testsProcessed: number;
  successRate: number;
  avgProcessingTime: number;
  trend: 'up' | 'down' | 'stable';
  periodComparison: {
    current: number;
    previous: number;
    change: number; // Percentage change
  };
}

/**
 * Batch operation types
 */
export interface BatchUserOperation {
  type: 'updateRole' | 'toggleStatus' | 'delete' | 'export';
  userIds: string[];
  params?: Record<string, any>;
}

/**
 * User export options
 */
export interface UserExportOptions {
  format: 'csv' | 'xlsx' | 'pdf';
  includeStatistics: boolean;
  includeTestData: boolean;
  dateRange?: {
    start: string;
    end: string;
  };
  filters?: UserFilters;
}

/**
 * Error types for better error handling
 */
export interface UserApiError {
  message: string;
  code?: string;
  field?: string;
  details?: Record<string, any>;
}

/**
 * Success response type
 */
export interface UserApiSuccess<T = any> {
  success: true;
  data: T;
  message?: string;
}

/**
 * Generic API response type
 */
export type UserApiResponse<T = any> = UserApiSuccess<T> | {
  success: false;
  error: UserApiError;
};

/**
 * Utility types
 */
export type UserRole = User['role'];
export type UserPermission = keyof User['permissions'];
export type UserId = string;
export type UserEmail = string;

/**
 * Form validation types
 */
export interface UserFormErrors {
  username?: string;
  email?: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  licenseNumber?: string;
  general?: string;
}

/**
 * User card/list item props
 */
export interface UserCardProps {
  user: UserWithStats;
  showStats?: boolean;
  showActions?: boolean;
  compact?: boolean;
  onClick?: (user: UserWithStats) => void;
  onAction?: (action: UserAction, user: UserWithStats) => void;
}

/**
 * User statistics card props
 */
export interface UserStatsCardProps {
  statistics: UserStatistics;
  loading?: boolean;
  error?: string | null;
  onRefresh?: () => void;
}

export default User;
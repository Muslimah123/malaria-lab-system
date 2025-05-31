// 📁 server/src/services/auditService.js
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

class AuditService {
  constructor() {
    this.batchSize = 100;
    this.batchTimeout = 5000; // 5 seconds
    this.pendingLogs = [];
    this.batchTimer = null;
    this.isProcessing = false;
  }

  /**
   * Log an audit event
   * @param {Object} logData - Audit log data
   */
  async log(logData) {
    try {
      // Validate required fields
      this.validateLogData(logData);

      // Enrich log data with additional context
      const enrichedLogData = this.enrichLogData(logData);

      // Add to batch for processing
      this.addToBatch(enrichedLogData);

      // Process batch if it's full or start timer
      if (this.pendingLogs.length >= this.batchSize) {
        await this.processBatch();
      } else {
        this.startBatchTimer();
      }

    } catch (error) {
      logger.error('Audit logging failed:', error);
      // Don't throw error for audit logging failure to avoid breaking main flow
    }
  }

  /**
   * Log multiple events at once
   */
  async logBatch(logDataArray) {
    try {
      const enrichedLogs = logDataArray.map(logData => {
        this.validateLogData(logData);
        return this.enrichLogData(logData);
      });

      await AuditLog.insertMany(enrichedLogs);
      logger.debug(`Batch logged ${enrichedLogs.length} audit events`);

    } catch (error) {
      logger.error('Batch audit logging failed:', error);
    }
  }

  /**
   * Validate audit log data
   */
  validateLogData(logData) {
    const requiredFields = ['action', 'userId', 'resourceType', 'resourceId'];
    
    for (const field of requiredFields) {
      if (!logData[field]) {
        throw new Error(`Missing required audit field: ${field}`);
      }
    }

    // Validate action is in allowed list
    const validActions = [
      // Authentication
      'login', 'logout', 'failed_login', 'password_change',
      // User management
      'user_created', 'user_updated', 'user_deleted', 'user_activated', 'user_deactivated',
      // Patient management
      'patient_created', 'patient_updated', 'patient_deleted', 'patient_viewed',
      // Test operations
      'test_created', 'test_updated', 'test_deleted', 'test_started', 'test_completed', 'test_cancelled',
      // Sample operations
      'sample_uploaded', 'sample_deleted', 'sample_downloaded',
      // Diagnosis operations
      'diagnosis_completed', 'diagnosis_reviewed', 'diagnosis_overridden',
      // Report operations
      'report_generated', 'report_exported', 'report_printed', 'report_shared',
      // Integration operations
      'data_exported_to_hospital', 'api_call_made', 'integration_failed',
      // System operations
      'system_backup', 'system_maintenance', 'database_cleanup',
      // Security events
      'unauthorized_access_attempt', 'data_breach_detected', 'suspicious_activity'
    ];

    if (!validActions.includes(logData.action)) {
      logger.warn(`Unknown audit action: ${logData.action}`);
    }

    // Validate resource type
    const validResourceTypes = ['user', 'patient', 'test', 'diagnosis', 'sample', 'report', 'system'];
    if (!validResourceTypes.includes(logData.resourceType)) {
      logger.warn(`Unknown resource type: ${logData.resourceType}`);
    }

    // Validate risk level
    if (logData.riskLevel && !['low', 'medium', 'high', 'critical'].includes(logData.riskLevel)) {
      logData.riskLevel = 'low'; // Default to low risk
    }

    // Validate status
    if (logData.status && !['success', 'failure', 'partial'].includes(logData.status)) {
      logData.status = 'success'; // Default to success
    }
  }

  /**
   * Enrich log data with additional context
   */
  enrichLogData(logData) {
    const enriched = {
      ...logData,
      // Set defaults
      status: logData.status || 'success',
      riskLevel: logData.riskLevel || 'low',
      source: logData.source || 'web_app',
      environment: process.env.NODE_ENV || 'development',
      
      // Add timestamp if not provided
      timestamp: logData.timestamp || new Date(),
      
      // Add server information
      serverInfo: {
        hostname: require('os').hostname(),
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid
      }
    };

    // Sanitize sensitive data
    enriched.userInfo = this.sanitizeUserInfo(logData.userInfo);
    enriched.details = this.sanitizeDetails(logData.details);

    return enriched;
  }

  /**
   * Sanitize user information to remove sensitive data
   */
  sanitizeUserInfo(userInfo) {
    if (!userInfo) return {};

    const sanitized = { ...userInfo };
    
    // Remove sensitive fields
    delete sanitized.password;
    delete sanitized.socialSecurityNumber;
    delete sanitized.creditCard;
    
    // Truncate email for privacy
    if (sanitized.email) {
      const [localPart, domain] = sanitized.email.split('@');
      if (localPart.length > 3) {
        sanitized.email = `${localPart.substring(0, 3)}***@${domain}`;
      }
    }

    return sanitized;
  }

  /**
   * Sanitize details to remove sensitive data
   */
  sanitizeDetails(details) {
    if (!details) return {};

    const sanitized = { ...details };
    
    // Remove or mask sensitive fields
    if (sanitized.password) sanitized.password = '[REDACTED]';
    if (sanitized.token) sanitized.token = '[REDACTED]';
    if (sanitized.secret) sanitized.secret = '[REDACTED]';
    if (sanitized.apiKey) sanitized.apiKey = '[REDACTED]';
    
    // Truncate large text fields
    if (sanitized.notes && sanitized.notes.length > 1000) {
      sanitized.notes = sanitized.notes.substring(0, 1000) + '... [TRUNCATED]';
    }

    return sanitized;
  }

  /**
   * Add log to batch processing queue
   */
  addToBatch(logData) {
    this.pendingLogs.push(logData);
  }

  /**
   * Start batch processing timer
   */
  startBatchTimer() {
    if (this.batchTimer) {
      return; // Timer already running
    }

    this.batchTimer = setTimeout(async () => {
      await this.processBatch();
    }, this.batchTimeout);
  }

  /**
   * Process pending logs batch
   */
  async processBatch() {
    if (this.isProcessing || this.pendingLogs.length === 0) {
      return;
    }

    this.isProcessing = true;

    try {
      // Clear timer
      if (this.batchTimer) {
        clearTimeout(this.batchTimer);
        this.batchTimer = null;
      }

      // Get logs to process
      const logsToProcess = [...this.pendingLogs];
      this.pendingLogs = [];

      // Insert logs to database
      if (logsToProcess.length > 0) {
        await AuditLog.insertMany(logsToProcess);
        logger.debug(`Processed batch of ${logsToProcess.length} audit logs`);
      }

    } catch (error) {
      logger.error('Batch processing failed:', error);
      
      // Put logs back in queue for retry
      this.pendingLogs.unshift(...this.pendingLogs);
      
      // Limit queue size to prevent memory issues
      if (this.pendingLogs.length > 1000) {
        this.pendingLogs = this.pendingLogs.slice(0, 1000);
        logger.warn('Audit log queue truncated due to processing failures');
      }

    } finally {
      this.isProcessing = false;
      
      // Schedule next batch if there are pending logs
      if (this.pendingLogs.length > 0) {
        this.startBatchTimer();
      }
    }
  }

  /**
   * Force flush all pending logs
   */
  async flush() {
    await this.processBatch();
  }

  /**
   * Get audit logs by user
   */
  async getLogsByUser(userId, options = {}) {
    try {
      const {
        page = 1,
        limit = 50,
        startDate,
        endDate,
        action,
        resourceType,
        riskLevel
      } = options;

      const filter = { user: userId };
      
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }
      
      if (action) filter.action = action;
      if (resourceType) filter.resourceType = resourceType;
      if (riskLevel) filter.riskLevel = riskLevel;

      const skip = (page - 1) * limit;

      const [logs, total] = await Promise.all([
        AuditLog.find(filter)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('user', 'username email role'),
        AuditLog.countDocuments(filter)
      ]);

      return {
        logs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };

    } catch (error) {
      logger.error('Get logs by user failed:', error);
      throw error;
    }
  }

  /**
   * Get audit logs by resource
   */
  async getLogsByResource(resourceType, resourceId, options = {}) {
    try {
      const { limit = 50 } = options;

      const logs = await AuditLog.find({
        resourceType,
        resourceId
      })
        .sort({ createdAt: -1 })
        .limit(limit)
        .populate('user', 'username email role');

      return logs;

    } catch (error) {
      logger.error('Get logs by resource failed:', error);
      throw error;
    }
  }

  /**
   * Get high-risk audit events
   */
  async getHighRiskEvents(options = {}) {
    try {
      const {
        page = 1,
        limit = 50,
        startDate,
        endDate
      } = options;

      const filter = {
        riskLevel: { $in: ['high', 'critical'] }
      };
      
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }

      const skip = (page - 1) * limit;

      const [logs, total] = await Promise.all([
        AuditLog.find(filter)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('user', 'username email role'),
        AuditLog.countDocuments(filter)
      ]);

      return {
        logs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };

    } catch (error) {
      logger.error('Get high-risk events failed:', error);
      throw error;
    }
  }

  /**
   * Get audit statistics
   */
  async getAuditStatistics(options = {}) {
    try {
      const {
        startDate,
        endDate,
        groupBy = 'day'
      } = options;

      const matchCondition = {};
      
      if (startDate || endDate) {
        matchCondition.createdAt = {};
        if (startDate) matchCondition.createdAt.$gte = new Date(startDate);
        if (endDate) matchCondition.createdAt.$lte = new Date(endDate);
      }

      // Get overall statistics
      const overallStats = await AuditLog.aggregate([
        { $match: matchCondition },
        {
          $group: {
            _id: null,
            totalEvents: { $sum: 1 },
            successfulEvents: { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
            failedEvents: { $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] } },
            lowRiskEvents: { $sum: { $cond: [{ $eq: ['$riskLevel', 'low'] }, 1, 0] } },
            mediumRiskEvents: { $sum: { $cond: [{ $eq: ['$riskLevel', 'medium'] }, 1, 0] } },
            highRiskEvents: { $sum: { $cond: [{ $eq: ['$riskLevel', 'high'] }, 1, 0] } },
            criticalRiskEvents: { $sum: { $cond: [{ $eq: ['$riskLevel', 'critical'] }, 1, 0] } },
            uniqueUsers: { $addToSet: '$user' }
          }
        },
        {
          $project: {
            totalEvents: 1,
            successfulEvents: 1,
            failedEvents: 1,
            lowRiskEvents: 1,
            mediumRiskEvents: 1,
            highRiskEvents: 1,
            criticalRiskEvents: 1,
            uniqueUsers: { $size: '$uniqueUsers' },
            successRate: { $divide: ['$successfulEvents', '$totalEvents'] }
          }
        }
      ]);

      // Get action distribution
      const actionStats = await AuditLog.aggregate([
        { $match: matchCondition },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Get timeline data
      let groupByExpression;
      switch (groupBy) {
        case 'hour':
          groupByExpression = {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' },
            hour: { $hour: '$createdAt' }
          };
          break;
        case 'week':
          groupByExpression = {
            year: { $year: '$createdAt' },
            week: { $week: '$createdAt' }
          };
          break;
        case 'month':
          groupByExpression = {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          };
          break;
        default: // day
          groupByExpression = {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' }
          };
      }

      const timelineStats = await AuditLog.aggregate([
        { $match: matchCondition },
        {
          $group: {
            _id: groupByExpression,
            totalEvents: { $sum: 1 },
            successfulEvents: { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
            failedEvents: { $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] } },
            highRiskEvents: { $sum: { $cond: [{ $in: ['$riskLevel', ['high', 'critical']] }, 1, 0] } }
          }
        },
        { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1, '_id.week': 1 } }
      ]);

      return {
        overall: overallStats[0] || {
          totalEvents: 0,
          successfulEvents: 0,
          failedEvents: 0,
          lowRiskEvents: 0,
          mediumRiskEvents: 0,
          highRiskEvents: 0,
          criticalRiskEvents: 0,
          uniqueUsers: 0,
          successRate: 0
        },
        actionDistribution: actionStats,
        timeline: timelineStats
      };

    } catch (error) {
      logger.error('Get audit statistics failed:', error);
      throw error;
    }
  }

  /**
   * Search audit logs
   */
  async searchLogs(searchQuery, options = {}) {
    try {
      const {
        page = 1,
        limit = 50,
        startDate,
        endDate,
        riskLevel,
        status
      } = options;

      const filter = {
        $or: [
          { action: { $regex: searchQuery, $options: 'i' } },
          { resourceName: { $regex: searchQuery, $options: 'i' } },
          { 'details.description': { $regex: searchQuery, $options: 'i' } },
          { 'userInfo.username': { $regex: searchQuery, $options: 'i' } }
        ]
      };

      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }

      if (riskLevel) filter.riskLevel = riskLevel;
      if (status) filter.status = status;

      const skip = (page - 1) * limit;

      const [logs, total] = await Promise.all([
        AuditLog.find(filter)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('user', 'username email role'),
        AuditLog.countDocuments(filter)
      ]);

      return {
        logs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };

    } catch (error) {
      logger.error('Search logs failed:', error);
      throw error;
    }
  }

  /**
   * Export audit logs
   */
  async exportLogs(options = {}) {
    try {
      const {
        format = 'json',
        startDate,
        endDate,
        limit = 10000
      } = options;

      const filter = {};
      
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }

      const logs = await AuditLog.find(filter)
        .sort({ createdAt: -1 })
        .limit(limit)
        .populate('user', 'username email role')
        .lean();

      // Remove sensitive data for export
      const sanitizedLogs = logs.map(log => {
        const sanitized = { ...log };
        delete sanitized.requestInfo?.ipAddress;
        delete sanitized.__v;
        return sanitized;
      });

      if (format === 'csv') {
        return this.convertLogsToCSV(sanitizedLogs);
      }

      return {
        format: 'json',
        data: sanitizedLogs,
        exportedAt: new Date(),
        totalRecords: sanitizedLogs.length
      };

    } catch (error) {
      logger.error('Export logs failed:', error);
      throw error;
    }
  }

  /**
   * Convert logs to CSV format
   */
  convertLogsToCSV(logs) {
    if (logs.length === 0) {
      return 'No data to export';
    }

    const headers = [
      'Timestamp',
      'Action', 
      'User',
      'Resource Type',
      'Resource ID',
      'Status',
      'Risk Level',
      'IP Address',
      'Description'
    ];

    const rows = logs.map(log => [
      log.createdAt,
      log.action,
      log.userInfo?.username || 'Unknown',
      log.resourceType,
      log.resourceId,
      log.status,
      log.riskLevel,
      log.requestInfo?.ipAddress || 'Unknown',
      log.details?.description || ''
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    return csvContent;
  }

  /**
   * Clean up old audit logs
   */
  async cleanupOldLogs(retentionDays = 2555) { // 7 years default
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await AuditLog.deleteMany({
        createdAt: { $lt: cutoffDate },
        retentionPeriod: { $lte: retentionDays }
      });

      logger.info(`Cleaned up ${result.deletedCount} old audit logs`);
      return result.deletedCount;

    } catch (error) {
      logger.error('Audit log cleanup failed:', error);
      throw error;
    }
  }
}

module.exports = new AuditService();
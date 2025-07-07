// 📁 server/src/controllers/analyticsController.js
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const Patient = require('../models/Patient');
const User = require('../models/User');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class AnalyticsController {
  /**
   * Get dashboard statistics for today
   */
  async getDashboardStats(req, res, next) {
    try {
      const user = req.user;
      const today = new Date();
      const startOfDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
      const endOfDay = new Date(startOfDay.getTime() + 24 * 60 * 60 * 1000);

      // Base query - filter by user role
      let baseQuery = {
        createdAt: { $gte: startOfDay, $lt: endOfDay },
        isActive: true
      };

      // Technicians see only their own tests
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }

      // Get today's test statistics
      const [
        todayTests,
        completedTests,
        pendingTests,
        failedTests,
        todayDiagnoses
      ] = await Promise.all([
        Test.countDocuments(baseQuery),
        Test.countDocuments({ ...baseQuery, status: 'completed' }),
        Test.countDocuments({ ...baseQuery, status: 'pending' }),
        Test.countDocuments({ ...baseQuery, status: 'failed' }),
        this.getTodayDiagnoses(baseQuery)
      ]);

      // Get quick actions based on user role
      const quickActions = this.getQuickActions(user.role);

      // Get recent activities
      const recentActivities = await this.getRecentActivities(user, 5);

      // Get severity breakdown for positive cases
      const severityBreakdown = await this.getSeverityBreakdown(baseQuery);

      const stats = {
        todayStats: {
          totalTests: todayTests,
          completedTests,
          pendingTests,
          failedTests,
          positiveResults: todayDiagnoses.positive,
          negativeResults: todayDiagnoses.negative,
          positivesRate: todayTests > 0 ? ((todayDiagnoses.positive / todayTests) * 100).toFixed(1) : '0'
        },
        severityBreakdown,
        quickActions,
        recentActivities,
        alerts: await this.getDashboardAlerts(user)
      };

      res.json({
        success: true,
        data: stats
      });

    } catch (error) {
      console.error('REAL error in dashboard stats:', error.stack || error);
      logger.error('Get dashboard stats error:', error);
      next(new AppError('Failed to retrieve dashboard statistics', 500));
    }
  }

  /**
   * Get comprehensive analytics data
   */
  async getAnalytics(req, res, next) {
    try {
      const { period = 'month', startDate, endDate } = req.query;
      const user = req.user;

      // Calculate date range
      const dateRange = this.calculateDateRange(period, startDate, endDate);

      // Base query with date range
      let baseQuery = {
        createdAt: { $gte: dateRange.start, $lte: dateRange.end },
        isActive: true
      };

      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }

      // Get comprehensive analytics
      const [
        testTrends,
        diagnosisDistribution,
        parasiteTypeDistribution,
        severityTrends,
        technicianPerformance,
        monthlyComparison,
        qualityMetrics
      ] = await Promise.all([
        this.getTestTrends(dateRange, baseQuery),
        this.getDiagnosisDistribution(baseQuery),
        this.getParasiteTypeDistribution(baseQuery),
        this.getSeverityTrends(dateRange, baseQuery),
        user.role !== 'technician' ? this.getTechnicianPerformance(dateRange) : null,
        this.getMonthlyComparison(dateRange, baseQuery),
        this.getQualityMetrics(baseQuery)
      ]);

      const analytics = {
        period: {
          type: period,
          start: dateRange.start,
          end: dateRange.end,
          description: this.getPeriodDescription(period, dateRange)
        },
        testTrends,
        diagnosisDistribution,
        parasiteTypeDistribution,
        severityTrends,
        monthlyComparison,
        qualityMetrics
      };

      // Include technician performance for supervisors/admins
      if (technicianPerformance) {
        analytics.technicianPerformance = technicianPerformance;
      }

      res.json({
        success: true,
        data: analytics
      });

    } catch (error) {
      logger.error('Get analytics error:', error);
      next(new AppError('Failed to retrieve analytics data', 500));
    }
  }

  /**
   * Get test volume trends
   */
  async getTestTrends(dateRange, baseQuery) {
    try {
      const dailyStats = await Test.aggregate([
        { $match: baseQuery },
        {
          $group: {
            _id: {
              year: { $year: '$createdAt' },
              month: { $month: '$createdAt' },
              day: { $dayOfMonth: '$createdAt' }
            },
            totalTests: { $sum: 1 },
            completedTests: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            pendingTests: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            },
            failedTests: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            }
          }
        },
        {
          $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
        }
      ]);

      return dailyStats.map(stat => ({
        date: new Date(stat._id.year, stat._id.month - 1, stat._id.day),
        totalTests: stat.totalTests,
        completedTests: stat.completedTests,
        pendingTests: stat.pendingTests,
        failedTests: stat.failedTests,
        completionRate: stat.totalTests > 0 ? ((stat.completedTests / stat.totalTests) * 100).toFixed(1) : '0'
      }));

    } catch (error) {
      logger.error('Get test trends error:', error);
      return [];
    }
  }

  /**
   * Get diagnosis distribution (positive vs negative)
   */
  async getDiagnosisDistribution(baseQuery) {
    try {
      // Get completed tests
      const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id');
      const testIds = completedTests.map(test => test._id);

      const distribution = await DiagnosisResult.aggregate([
        { $match: { test: { $in: testIds } } },
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 },
            avgConfidence: { $avg: '$mostProbableParasite.confidence' }
          }
        }
      ]);

      const total = distribution.reduce((sum, item) => sum + item.count, 0);

      return {
        positive: distribution.find(d => d._id === 'POS')?.count || 0,
        negative: distribution.find(d => d._id === 'NEG')?.count || 0,
        total,
        positiveRate: total > 0 ? ((distribution.find(d => d._id === 'POS')?.count || 0) / total * 100).toFixed(1) : '0',
        avgConfidencePositive: distribution.find(d => d._id === 'POS')?.avgConfidence?.toFixed(2) || '0'
      };

    } catch (error) {
      logger.error('Get diagnosis distribution error:', error);
      return { positive: 0, negative: 0, total: 0, positiveRate: '0', avgConfidencePositive: '0' };
    }
  }

  /**
   * Get parasite type distribution
   */
  async getParasiteTypeDistribution(baseQuery) {
    try {
      const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id');
      const testIds = completedTests.map(test => test._id);

      const distribution = await DiagnosisResult.aggregate([
        { $match: { test: { $in: testIds }, status: 'POS' } },
        {
          $group: {
            _id: '$mostProbableParasite.type',
            count: { $sum: 1 },
            avgConfidence: { $avg: '$mostProbableParasite.confidence' },
            maxConfidence: { $max: '$mostProbableParasite.confidence' },
            minConfidence: { $min: '$mostProbableParasite.confidence' }
          }
        },
        { $sort: { count: -1 } }
      ]);

      return distribution.map(item => ({
        type: item._id,
        name: this.getParasiteName(item._id),
        count: item.count,
        avgConfidence: item.avgConfidence?.toFixed(2) || '0',
        maxConfidence: item.maxConfidence?.toFixed(2) || '0',
        minConfidence: item.minConfidence?.toFixed(2) || '0'
      }));

    } catch (error) {
      logger.error('Get parasite type distribution error:', error);
      return [];
    }
  }

  /**
   * Get severity trends over time
   */
  async getSeverityTrends(dateRange, baseQuery) {
    try {
      const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id createdAt');
      const testIds = completedTests.map(test => test._id);

      const severityData = await DiagnosisResult.aggregate([
        { $match: { test: { $in: testIds }, status: 'POS' } },
        {
          $lookup: {
            from: 'tests',
            localField: 'test',
            foreignField: '_id',
            as: 'testInfo'
          }
        },
        { $unwind: '$testInfo' },
        {
          $group: {
            _id: {
              year: { $year: '$testInfo.createdAt' },
              month: { $month: '$testInfo.createdAt' },
              severity: '$severity.level'
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { '_id.year': 1, '_id.month': 1 } }
      ]);

      // Group by month
      const monthlyData = {};
      severityData.forEach(item => {
        const monthKey = `${item._id.year}-${item._id.month.toString().padStart(2, '0')}`;
        if (!monthlyData[monthKey]) {
          monthlyData[monthKey] = { mild: 0, moderate: 0, severe: 0 };
        }
        monthlyData[monthKey][item._id.severity || 'mild'] = item.count;
      });

      return Object.entries(monthlyData).map(([month, data]) => ({
        month,
        ...data,
        total: data.mild + data.moderate + data.severe
      }));

    } catch (error) {
      logger.error('Get severity trends error:', error);
      return [];
    }
  }

  /**
   * Get technician performance metrics
   */
  async getTechnicianPerformance(dateRange) {
    try {
      const performance = await Test.aggregate([
        {
          $match: {
            createdAt: { $gte: dateRange.start, $lte: dateRange.end },
            isActive: true
          }
        },
        {
          $lookup: {
            from: 'users',
            localField: 'technician',
            foreignField: '_id',
            as: 'technicianInfo'
          }
        },
        { $unwind: '$technicianInfo' },
        {
          $group: {
            _id: '$technician',
            technicianName: { $first: { $concat: ['$technicianInfo.firstName', ' ', '$technicianInfo.lastName'] } },
            totalTests: { $sum: 1 },
            completedTests: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            pendingTests: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            },
            failedTests: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            },
            avgProcessingTime: { $avg: '$processingTime' }
          }
        },
        { $sort: { totalTests: -1 } }
      ]);

      return performance.map(perf => ({
        technicianId: perf._id,
        technicianName: perf.technicianName,
        totalTests: perf.totalTests,
        completedTests: perf.completedTests,
        pendingTests: perf.pendingTests,
        failedTests: perf.failedTests,
        completionRate: perf.totalTests > 0 ? ((perf.completedTests / perf.totalTests) * 100).toFixed(1) : '0',
        failureRate: perf.totalTests > 0 ? ((perf.failedTests / perf.totalTests) * 100).toFixed(1) : '0',
        avgProcessingTime: perf.avgProcessingTime?.toFixed(0) || '0'
      }));

    } catch (error) {
      logger.error('Get technician performance error:', error);
      return [];
    }
  }

  /**
   * Get quality metrics
   */
  async getQualityMetrics(baseQuery) {
    try {
      const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id');
      const testIds = completedTests.map(test => test._id);

      const qualityData = await DiagnosisResult.aggregate([
        { $match: { test: { $in: testIds } } },
        {
          $group: {
            _id: null,
            avgConfidence: { $avg: '$mostProbableParasite.confidence' },
            highConfidenceTests: {
              $sum: { $cond: [{ $gte: ['$mostProbableParasite.confidence', 0.8] }, 1, 0] }
            },
            lowConfidenceTests: {
              $sum: { $cond: [{ $lt: ['$mostProbableParasite.confidence', 0.6] }, 1, 0] }
            },
            totalTests: { $sum: 1 },
            avgParasiteCount: { $avg: { $sum: '$detections.parasiteCount' } },
            avgWbcCount: { $avg: { $sum: '$detections.whiteBloodCellsDetected' } }
          }
        }
      ]);

      const metrics = qualityData[0] || {};

      return {
        avgConfidence: metrics.avgConfidence?.toFixed(2) || '0',
        highConfidenceRate: metrics.totalTests > 0 ? ((metrics.highConfidenceTests / metrics.totalTests) * 100).toFixed(1) : '0',
        lowConfidenceRate: metrics.totalTests > 0 ? ((metrics.lowConfidenceTests / metrics.totalTests) * 100).toFixed(1) : '0',
        avgParasiteCount: metrics.avgParasiteCount?.toFixed(1) || '0',
        avgWbcCount: metrics.avgWbcCount?.toFixed(1) || '0',
        qualityScore: this.calculateQualityScore(metrics)
      };

    } catch (error) {
      logger.error('Get quality metrics error:', error);
      return {
        avgConfidence: '0',
        highConfidenceRate: '0',
        lowConfidenceRate: '0',
        avgParasiteCount: '0',
        avgWbcCount: '0',
        qualityScore: '0'
      };
    }
  }

  /**
   * Get today's diagnosis statistics
   */
async getTodayDiagnoses(baseQuery) {
  try {
    const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id');
    const testIds = completedTests.map(test => test._id);

    if (testIds.length === 0) {
      return { positive: 0, negative: 0 };
    }

    const diagnoses = await DiagnosisResult.aggregate([
      { $match: { test: { $in: testIds } } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    return {
      positive: diagnoses.find(d => d._id === 'POS')?.count || 0,
      negative: diagnoses.find(d => d._id === 'NEG')?.count || 0
    };

  } catch (error) {
    logger.error('Get today diagnoses error:', error);
    return { positive: 0, negative: 0 };
  }
}

  /**
   * Get severity breakdown for positive cases
   */
  async getSeverityBreakdown(baseQuery) {
    try {
      const completedTests = await Test.find({ ...baseQuery, status: 'completed' }).select('_id');
      const testIds = completedTests.map(test => test._id);

      const severityData = await DiagnosisResult.aggregate([
        { $match: { test: { $in: testIds }, status: 'POS' } },
        {
          $group: {
            _id: '$severity.level',
            count: { $sum: 1 }
          }
        }
      ]);

      const total = severityData.reduce((sum, item) => sum + item.count, 0);

      return {
        mild: severityData.find(s => s._id === 'mild')?.count || 0,
        moderate: severityData.find(s => s._id === 'moderate')?.count || 0,
        severe: severityData.find(s => s._id === 'severe')?.count || 0,
        total,
        distribution: severityData.map(item => ({
          level: item._id || 'unknown',
          count: item.count,
          percentage: total > 0 ? ((item.count / total) * 100).toFixed(1) : '0'
        }))
      };

    } catch (error) {
      logger.error('Get severity breakdown error:', error);
      return { mild: 0, moderate: 0, severe: 0, total: 0, distribution: [] };
    }
  }

  /**
   * Get recent activities for user
   */
  async getRecentActivities(user, limit = 5) {
    try {
      let query = { isActive: true };
      
      // Technicians see only their activities
      if (user.role === 'technician') {
        query.technician = user._id;
      }

      const recentTests = await Test.find(query)
        .populate('patient', 'patientId firstName lastName')
        .populate('technician', 'firstName lastName')
        .sort({ updatedAt: -1 })
        .limit(limit);

      return recentTests.map(test => ({
        id: test._id,
        type: 'test',
        action: `Test ${test.status}`,
        testId: test.testId,
        patientId: test.patient.patientId,
        patientName: `${test.patient.firstName} ${test.patient.lastName}`,
        technician: `${test.technician.firstName} ${test.technician.lastName}`,
        timestamp: test.updatedAt,
        status: test.status
      }));

    } catch (error) {
      logger.error('Get recent activities error:', error);
      return [];
    }
  }

  /**
   * Get dashboard alerts
   */
  async getDashboardAlerts(user) {
    try {
      const alerts = [];
      
      // Check for pending tests older than 24 hours
      const oldPendingTests = await Test.countDocuments({
        status: 'pending',
        createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        isActive: true,
        ...(user.role === 'technician' ? { technician: user._id } : {})
      });

      if (oldPendingTests > 0) {
        alerts.push({
          type: 'warning',
          title: 'Pending Tests',
          message: `${oldPendingTests} test(s) have been pending for more than 24 hours`,
          action: 'View pending tests',
          actionUrl: '/tests?status=pending'
        });
      }

      // Check for failed tests today
      const today = new Date();
      const startOfDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
      
      const failedToday = await Test.countDocuments({
        status: 'failed',
        createdAt: { $gte: startOfDay },
        isActive: true,
        ...(user.role === 'technician' ? { technician: user._id } : {})
      });

      if (failedToday > 0) {
        alerts.push({
          type: 'error',
          title: 'Failed Tests',
          message: `${failedToday} test(s) failed today and may need attention`,
          action: 'View failed tests',
          actionUrl: '/tests?status=failed'
        });
      }

      // Check for positive results today (for supervisors)
      if (['supervisor', 'admin'].includes(user.role)) {
        const positivesToday = await this.getTodayDiagnoses({
          createdAt: { $gte: startOfDay },
          isActive: true
        });

        if (positivesToday.positive > 0) {
          alerts.push({
            type: 'info',
            title: 'Positive Results',
            message: `${positivesToday.positive} positive result(s) detected today`,
            action: 'View results',
            actionUrl: '/results?status=positive'
          });
        }
      }

      return alerts;

    } catch (error) {
      logger.error('Get dashboard alerts error:', error);
      return [];
    }
  }

  /**
   * Get quick actions based on user role
   */
  getQuickActions(role) {
    const baseActions = [
      {
        title: 'Upload New Sample',
        description: 'Start a new malaria test',
        icon: 'upload',
        url: '/upload',
        color: 'primary'
      },
      {
        title: 'View Reports',
        description: 'Access test reports',
        icon: 'file-text',
        url: '/reports',
        color: 'secondary'
      }
    ];

    if (['supervisor', 'admin'].includes(role)) {
      baseActions.push(
        {
          title: 'Analytics',
          description: 'View detailed analytics',
          icon: 'bar-chart',
          url: '/analytics',
          color: 'info'
        },
        {
          title: 'Manage Users',
          description: 'User management',
          icon: 'users',
          url: '/users',
          color: 'warning'
        }
      );
    }

    return baseActions;
  }

  /**
   * Calculate date range based on period
   */
  calculateDateRange(period, startDate, endDate) {
    const now = new Date();
    
    if (startDate && endDate) {
      return {
        start: new Date(startDate),
        end: new Date(endDate)
      };
    }

    switch (period) {
      case 'day':
        return {
          start: new Date(now.getFullYear(), now.getMonth(), now.getDate()),
          end: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
        };
      case 'week':
        const weekStart = new Date(now);
        weekStart.setDate(now.getDate() - now.getDay());
        weekStart.setHours(0, 0, 0, 0);
        return {
          start: weekStart,
          end: new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000)
        };
      case 'year':
        return {
          start: new Date(now.getFullYear(), 0, 1),
          end: new Date(now.getFullYear() + 1, 0, 1)
        };
      case 'month':
      default:
        return {
          start: new Date(now.getFullYear(), now.getMonth(), 1),
          end: new Date(now.getFullYear(), now.getMonth() + 1, 1)
        };
    }
  }

  /**
   * Get period description for display
   */
  getPeriodDescription(period, dateRange) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    const start = dateRange.start.toLocaleDateString('en-US', options);
    const end = dateRange.end.toLocaleDateString('en-US', options);
    
    switch (period) {
      case 'day':
        return `Today (${start})`;
      case 'week':
        return `This Week (${start} - ${end})`;
      case 'year':
        return `This Year (${dateRange.start.getFullYear()})`;
      case 'month':
        return `This Month (${dateRange.start.toLocaleDateString('en-US', { year: 'numeric', month: 'long' })})`;
      default:
        return `${start} - ${end}`;
    }
  }

  /**
   * Calculate overall quality score
   */
  calculateQualityScore(metrics) {
    if (!metrics.totalTests || metrics.totalTests === 0) return '0';

    const confidenceScore = (metrics.avgConfidence || 0) * 100;
    const highConfidenceRate = metrics.totalTests > 0 ? (metrics.highConfidenceTests / metrics.totalTests) * 100 : 0;
    const lowConfidencePenalty = metrics.totalTests > 0 ? (metrics.lowConfidenceTests / metrics.totalTests) * 20 : 0;

    const qualityScore = Math.max(0, (confidenceScore * 0.6 + highConfidenceRate * 0.4 - lowConfidencePenalty));
    
    return qualityScore.toFixed(1);
  }

  /**
   * Get monthly comparison with previous month
   */
  async getMonthlyComparison(dateRange, baseQuery) {
    try {
      // Current period
      const currentStats = await this.getPeriodStats({ ...baseQuery });

      // Previous period
      const previousStart = new Date(dateRange.start);
      previousStart.setMonth(previousStart.getMonth() - 1);
      const previousEnd = new Date(dateRange.end);
      previousEnd.setMonth(previousEnd.getMonth() - 1);

      const previousQuery = {
        ...baseQuery,
        createdAt: { $gte: previousStart, $lt: previousEnd }
      };
      const previousStats = await this.getPeriodStats(previousQuery);

      return {
        current: currentStats,
        previous: previousStats,
        changes: {
          totalTests: this.calculatePercentageChange(previousStats.totalTests, currentStats.totalTests),
          positiveTests: this.calculatePercentageChange(previousStats.positiveTests, currentStats.positiveTests),
          completionRate: this.calculatePercentageChange(previousStats.completionRate, currentStats.completionRate)
        }
      };

    } catch (error) {
      logger.error('Get monthly comparison error:', error);
      return {
        current: { totalTests: 0, positiveTests: 0, completionRate: 0 },
        previous: { totalTests: 0, positiveTests: 0, completionRate: 0 },
        changes: { totalTests: 0, positiveTests: 0, completionRate: 0 }
      };
    }
  }

  /**
   * Get period statistics
   */
  async getPeriodStats(query) {
    try {
      const totalTests = await Test.countDocuments(query);
      const completedTests = await Test.countDocuments({ ...query, status: 'completed' });
      
      const completedTestIds = await Test.find({ ...query, status: 'completed' }).select('_id');
      const testIds = completedTestIds.map(test => test._id);
      
      const positiveTests = await DiagnosisResult.countDocuments({
        test: { $in: testIds },
        status: 'POS'
      });

      return {
        totalTests,
        positiveTests,
        completionRate: totalTests > 0 ? (completedTests / totalTests) * 100 : 0
      };

    } catch (error) {
      logger.error('Get period stats error:', error);
      return { totalTests: 0, positiveTests: 0, completionRate: 0 };
    }
  }

  /**
   * Calculate percentage change between two values
   */
  calculatePercentageChange(oldValue, newValue) {
    if (oldValue === 0) return newValue > 0 ? 100 : 0;
    return ((newValue - oldValue) / oldValue) * 100;
  }

  /**
   * Get human-readable parasite name
   */
  getParasiteName(type) {
    const parasiteNames = {
      'PF': 'Plasmodium Falciparum',
      'PV': 'Plasmodium Vivax',
      'PM': 'Plasmodium Malariae',
      'PO': 'Plasmodium Ovale',
      'PK': 'Plasmodium Knowlesi'
    };
    return parasiteNames[type] || type;
  }
}

module.exports = new AnalyticsController();
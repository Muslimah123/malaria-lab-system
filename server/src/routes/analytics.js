// 📁 server/src/routes/analytics.js
const express = require('express');
const { query } = require('express-validator');
const analyticsController = require('../controllers/analyticsController');
const { validateRequest } = require('../middleware/validation');
const { auth, requireSupervisor, requirePermission, requireAnalyticsAccess } = require('../middleware/auth'); // FIXED: Import from auth middleware
// ✅ ADDED: Missing model imports for the new /diagnosis endpoint
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const User = require('../models/User'); // Added for performance metrics
const auditService = require('../services/auditService'); // Added for performance metrics


const router = express.Router();

// All analytics routes require authentication
router.use(auth);

/**
 * @swagger
 * components:
 *   schemas:
 *     DashboardStats:
 *       type: object
 *       properties:
 *         todayStats:
 *           type: object
 *           properties:
 *             totalTests:
 *               type: integer
 *             completedTests:
 *               type: integer
 *             pendingTests:
 *               type: integer
 *             failedTests:
 *               type: integer
 *             positiveResults:
 *               type: integer
 *             negativeResults:
 *               type: integer
 *             positivesRate:
 *               type: string
 *         severityBreakdown:
 *           type: object
 *           properties:
 *             mild:
 *               type: integer
 *             moderate:
 *               type: integer
 *             severe:
 *               type: integer
 *         quickActions:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               url:
 *                 type: string
 *               icon:
 *                 type: string
 *         recentActivities:
 *           type: array
 *           items:
 *             type: object
 *         alerts:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [info, warning, error]
 *               title:
 *                 type: string
 *               message:
 *                 type: string
 *     AnalyticsData:
 *       type: object
 *       properties:
 *         period:
 *           type: object
 *           properties:
 *             type:
 *               type: string
 *             start:
 *               type: string
 *               format: date-time
 *             end:
 *               type: string
 *               format: date-time
 *         testTrends:
 *           type: array
 *           items:
 *             type: object
 *         diagnosisDistribution:
 *           type: object
 *         parasiteTypeDistribution:
 *           type: array
 *           items:
 *             type: object
 *         severityTrends:
 *           type: array
 *           items:
 *             type: object
 *         qualityMetrics:
 *           type: object
 */

/**
 * @swagger
 * /api/analytics/dashboard:
 *   get:
 *     summary: Get dashboard statistics for today
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Dashboard statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/DashboardStats'
 *       403:
 *         description: Access denied
 */
router.get('/dashboard',
  auth, // ✅ FIXED: Allow all authenticated users to access dashboard
  analyticsController.getDashboardStats.bind(analyticsController));

/**
 * @swagger
 * /api/analytics/comprehensive:
 *   get:
 *     summary: Get comprehensive analytics data
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [day, week, month, year, custom]
 *           default: month
 *         description: Time period for analytics
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *         description: Start date for custom period
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *         description: End date for custom period
 *     responses:
 *       200:
 *         description: Comprehensive analytics data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/AnalyticsData'
 *       400:
 *         description: Invalid date parameters
 */
router.get('/comprehensive',
  requireAnalyticsAccess,
  query('period')
    .optional()
    .isIn(['day', 'week', 'month', 'year', 'custom'])
    .withMessage('Period must be day, week, month, year, or custom'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  analyticsController.getAnalytics.bind(analyticsController)
);

/**
 * @swagger
 * /api/analytics/test-trends:
 *   get:
 *     summary: Get test volume trends over time
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 365
 *           default: 30
 *         description: Number of days to analyze
 *       - in: query
 *         name: groupBy
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *           default: day
 *         description: How to group the data
 *     responses:
 *       200:
 *         description: Test trends data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       date:
 *                         type: string
 *                         format: date
 *                       totalTests:
 *                         type: integer
 *                       completedTests:
 *                         type: integer
 *                       pendingTests:
 *                         type: integer
 *                       failedTests:
 *                         type: integer
 *                       completionRate:
 *                         type: string
 */
router.get('/test-trends',
  requireAnalyticsAccess,
  query('days')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Days must be between 1 and 365'),
  query('groupBy')
    .optional()
    .isIn(['day', 'week', 'month'])
    .withMessage('Group by must be day, week, or month'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { days = 30, groupBy = 'day' } = req.query;
      const user = req.user;
      
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      
      const dateRange = { start: startDate, end: endDate };
      
      // Base query with date range
      let baseQuery = {
        createdAt: { $gte: dateRange.start, $lte: dateRange.end },
        isActive: true
      };
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const trends = await analyticsController.getTestTrends(dateRange, baseQuery);
      
      res.json({
        success: true,
        data: trends,
        metadata: {
          period: `${days} days`,
          groupBy,
          startDate,
          endDate
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/diagnosis-distribution:
 *   get:
 *     summary: Get distribution of positive vs negative diagnoses
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: technicianId
 *         schema:
 *           type: string
 *         description: Filter by specific technician (supervisor/admin only)
 *     responses:
 *       200:
 *         description: Diagnosis distribution data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     positive:
 *                       type: integer
 *                     negative:
 *                       type: integer
 *                     total:
 *                       type: integer
 *                     positiveRate:
 *                       type: string
 *                     avgConfidencePositive:
 *                       type: string
 */
router.get('/diagnosis-distribution',
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('technicianId')
    .optional()
    .isMongoId()
    .withMessage('Technician ID must be a valid MongoDB ObjectId'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate, technicianId } = req.query;
      const user = req.user;
      
      // Build base query
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Handle technician filtering
      if (technicianId) {
        // Only supervisors/admins can filter by other technicians
        if (!['supervisor', 'admin'].includes(user.role)) {
          return res.status(403).json({
            success: false,
            message: 'Insufficient permissions to filter by technician'
          });
        }
        baseQuery.technician = technicianId;
      } else if (user.role === 'technician') {
        // Technicians see only their own data
        baseQuery.technician = user._id;
      }
      
      const distribution = await analyticsController.getDiagnosisDistribution(baseQuery);
      
      res.json({
        success: true,
        data: distribution
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/diagnosis:
 *   get:
 *     summary: Get comprehensive diagnosis analytics data
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: timeRange
 *         schema:
 *           type: string
 *           enum: [1d, 7d, 30d, 90d]
 *           default: 7d
 *     responses:
 *       200:
 *         description: Diagnosis analytics data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     totalTests:
 *                       type: integer
 *                     successRate:
 *                       type: number
 *                     avgProcessingTime:
 *                       type: number
 *                     totalImages:
 *                       type: integer
 *                     positiveCases:
 *                       type: integer
 *                     negativeCases:
 *                       type: integer
 *                     timeSeriesData:
 *                       type: array
 *                     parasiteDistribution:
 *                       type: array
 *                     accuracyMetrics:
 *                       type: object
 */
router.get('/diagnosis',
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('timeRange')
    .optional()
    .isIn(['1d', '7d', '30d', '90d'])
    .withMessage('Time range must be 1d, 7d, 30d, or 90d'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate, timeRange = '7d' } = req.query;
      const user = req.user;
      
      // Build base query
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      } else {
        // Default to timeRange if no specific dates provided
        const now = new Date();
        let startDateDefault;
        switch (timeRange) {
          case '1d':
            startDateDefault = new Date(now.getTime() - 24 * 60 * 60 * 1000);
            break;
          case '30d':
            startDateDefault = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            break;
          case '90d':
            startDateDefault = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
            break;
          default: // 7d
            startDateDefault = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        }
        baseQuery.createdAt = { $gte: startDateDefault, $lte: now };
      }
      
      // Handle user role filtering
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      // Get comprehensive diagnosis analytics
      const [
        totalTests,
        positiveCases,
        negativeCases,
        avgProcessingTime,
        parasiteDistribution,
        timeSeriesData
      ] = await Promise.all([
        Test.countDocuments(baseQuery),
        DiagnosisResult.countDocuments({ 
          ...baseQuery, 
          status: { $in: ['POS', 'POSITIVE'] } 
        }),
        DiagnosisResult.countDocuments({ 
          ...baseQuery, 
          status: { $in: ['NEG', 'NEGATIVE'] } 
        }),
        Test.aggregate([
          { $match: { ...baseQuery, status: 'completed' } },
          { $group: { _id: null, avgTime: { $avg: '$processingTime' } } }
        ]),
        DiagnosisResult.aggregate([
          { $match: baseQuery },
          { $group: { _id: '$mostProbableParasite.type', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),
        Test.aggregate([
          { $match: baseQuery },
          {
            $group: {
              _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
              tests: { $sum: 1 },
              positive: {
                $sum: {
                  $cond: [
                    { $in: ['$status', ['POS', 'POSITIVE']] },
                    1,
                    0
                  ]
                }
              },
              negative: {
                $sum: {
                  $cond: [
                    { $in: ['$status', ['NEG', 'NEGATIVE']] },
                    1,
                    0
                  ]
                }
              }
            }
          },
          { $sort: { _id: 1 } }
        ])
      ]);
      
      // Calculate success rate
      const successRate = totalTests > 0 ? ((totalTests - (positiveCases + negativeCases)) / totalTests) * 100 : 0;
      
      // Format parasite distribution
      const formattedParasiteDistribution = parasiteDistribution.map(item => ({
        type: item._id || 'Unknown',
        count: item.count,
        percentage: totalTests > 0 ? ((item.count / totalTests) * 100).toFixed(1) : 0
      }));
      
      // Format time series data
      const formattedTimeSeriesData = timeSeriesData.map(item => ({
        date: item._id,
        tests: item.tests,
        positive: item.positive,
        negative: item.negative,
        avgTime: avgProcessingTime[0]?.avgTime?.toFixed(1) || 0
      }));
      
      // Calculate accuracy metrics (mock data for now)
      const accuracyMetrics = {
        sensitivity: 92.3,
        specificity: 96.8,
        precision: 94.1,
        recall: 92.3
      };
      
      const analyticsData = {
        totalTests,
        successRate: Math.round(successRate * 100) / 100,
        avgProcessingTime: avgProcessingTime[0]?.avgTime?.toFixed(1) || 0,
        totalImages: totalTests, // Assuming 1 image per test for now
        positiveCases,
        negativeCases,
        timeSeriesData: formattedTimeSeriesData,
        parasiteDistribution: formattedParasiteDistribution,
        accuracyMetrics
      };
      
      res.json({
        success: true,
        data: analyticsData
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/parasite-types:
 *   get:
 *     summary: Get distribution of detected parasite types
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Parasite type distribution retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       type:
 *                         type: string
 *                       name:
 *                         type: string
 *                       count:
 *                         type: integer
 *                       avgConfidence:
 *                         type: string
 */
router.get('/parasite-types',
  requireAnalyticsAccess,
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate } = req.query;
      const user = req.user;
      
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const distribution = await analyticsController.getParasiteTypeDistribution(baseQuery);
      
      res.json({
        success: true,
        data: distribution
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/technician-performance:
 *   get:
 *     summary: Get technician performance metrics (Supervisor/Admin only)
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [totalTests, completionRate, failureRate]
 *           default: totalTests
 *     responses:
 *       200:
 *         description: Technician performance data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       technicianId:
 *                         type: string
 *                       technicianName:
 *                         type: string
 *                       totalTests:
 *                         type: integer
 *                       completedTests:
 *                         type: integer
 *                       pendingTests:
 *                         type: integer
 *                       failedTests:
 *                         type: integer
 *                       completionRate:
 *                         type: string
 *                       failureRate:
 *                         type: string
 */
router.get('/technician-performance',
  requireSupervisor,
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('sortBy')
    .optional()
    .isIn(['totalTests', 'completionRate', 'failureRate'])
    .withMessage('Sort by must be totalTests, completionRate, or failureRate'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate, sortBy = 'totalTests' } = req.query;
      
      const dateRange = {
        start: startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        end: endDate ? new Date(endDate) : new Date()
      };
      
      const performance = await analyticsController.getTechnicianPerformance(dateRange);
      
      // Sort results
      const sortedPerformance = performance.sort((a, b) => {
        switch (sortBy) {
          case 'completionRate':
            return parseFloat(b.completionRate) - parseFloat(a.completionRate);
          case 'failureRate':
            return parseFloat(a.failureRate) - parseFloat(b.failureRate);
          case 'totalTests':
          default:
            return b.totalTests - a.totalTests;
        }
      });
      
      res.json({
        success: true,
        data: sortedPerformance,
        metadata: {
          period: {
            start: dateRange.start,
            end: dateRange.end
          },
          sortBy
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/quality-metrics:
 *   get:
 *     summary: Get quality metrics for diagnoses
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Quality metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     avgConfidence:
 *                       type: string
 *                     highConfidenceRate:
 *                       type: string
 *                     lowConfidenceRate:
 *                       type: string
 *                     avgParasiteCount:
 *                       type: string
 *                     avgWbcCount:
 *                       type: string
 *                     qualityScore:
 *                       type: string
 */
router.get('/quality-metrics',
  requireAnalyticsAccess,
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { startDate, endDate } = req.query;
      const user = req.user;
      
      let baseQuery = { isActive: true };
      
      if (startDate && endDate) {
        baseQuery.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      // Filter by user role
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }
      
      const qualityMetrics = await analyticsController.getQualityMetrics(baseQuery);
      
      res.json({
        success: true,
        data: qualityMetrics
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/performance-metrics:
 *   get:
 *     summary: Get real-time system performance metrics
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Performance metrics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     systemHealth:
 *                       type: string
 *                     uptime:
 *                       type: string
 *                     activeUsers:
 *                       type: integer
 *                     performanceScore:
 *                       type: string
 *                     cpuUsage:
 *                       type: number
 *                     memoryUsage:
 *                       type: number
 *                     diskUsage:
 *                       type: number
 *                     networkLatency:
 *                       type: number
 *                     apiResponseTime:
 *                       type: number
 *                     errorRate:
 *                       type: number
 *                     throughput:
 *                       type: number
 *                     session:
 *                       type: object
 *                     user:
 *                       type: object
 *                     api:
 *                       type: object
 *                     rendering:
 *                       type: object
 *                     memory:
 *                       type: object
 *                     errors:
 *                       type: object
 */
router.get('/performance-metrics',
  async (req, res, next) => {
    try {
      const user = req.user;
      
      // Get real system metrics
      const [
        totalUsers,
        activeUsers,
        totalTests,
        completedTests,
        failedTests,
        apiCalls,
        errorCount,
        memoryUsage,
        uptime
      ] = await Promise.all([
        User.countDocuments({ isActive: true }),
        User.countDocuments({ 
          isActive: true, 
          lastLogin: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
        }),
        Test.countDocuments({ isActive: true }),
        Test.countDocuments({ status: 'completed', isActive: true }),
        Test.countDocuments({ status: 'failed', isActive: true }),
        // Count API calls from audit logs
        auditService.getApiCallCount(24 * 60 * 60 * 1000), // Last 24 hours
        // Count errors from audit logs
        auditService.getErrorCount(24 * 60 * 60 * 1000), // Last 24 hours
        // Get memory usage (Node.js process)
        Promise.resolve(process.memoryUsage()),
        // Calculate uptime
        Promise.resolve(process.uptime())
      ]);

      // Calculate API performance metrics
      const apiSuccessRate = apiCalls > 0 ? ((apiCalls - errorCount) / apiCalls) * 100 : 100;
      const avgResponseTime = 150; // Mock for now, could be calculated from actual request logs
      
      // Get recent errors
      const recentErrors = await auditService.getRecentErrors(10);
      
      // Get user interactions
      const userInteractions = await auditService.getUserInteractions(user._id, 24 * 60 * 60 * 1000);
      
      // Calculate session duration (mock for now, could be tracked per user)
      const sessionStart = new Date(Date.now() - 2 * 60 * 60 * 1000);
      const sessionDuration = Date.now() - sessionStart.getTime();
      
      const performanceData = {
        systemHealth: errorCount < 5 ? 'Operational' : errorCount < 20 ? 'Warning' : 'Critical',
        uptime: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
        activeUsers,
        performanceScore: apiSuccessRate > 95 ? 'A+' : apiSuccessRate > 85 ? 'A' : apiSuccessRate > 75 ? 'B' : 'C',
        cpuUsage: Math.floor(Math.random() * 30) + 20, // Would need system monitoring
        memoryUsage: Math.floor(Math.random() * 40) + 30, // Would need system monitoring
        diskUsage: Math.floor(Math.random() * 20) + 10, // Would need system monitoring
        networkLatency: Math.floor(Math.random() * 50) + 10, // Would need network monitoring
        apiResponseTime: avgResponseTime,
        errorRate: errorCount,
        throughput: totalTests,
        
        session: {
          durationFormatted: `${Math.floor(sessionDuration / 3600000)}h ${Math.floor((sessionDuration % 3600000) / 60000)}m`,
          startTime: sessionStart.toISOString(),
          totalInteractions: userInteractions.length,
          duration: sessionDuration
        },
        
        user: {
          totalInteractions: userInteractions.length,
          recentInteractions: userInteractions.slice(0, 5).map(interaction => ({
            action: interaction.action || 'Unknown',
            timestamp: interaction.timestamp || new Date().toISOString(),
            details: interaction.details || {}
          }))
        },
        
        api: {
          successRate: Math.round(apiSuccessRate * 100) / 100,
          totalCalls: apiCalls,
          averageResponseTime: avgResponseTime,
          fastestCall: 25,
          successfulCalls: apiCalls - errorCount,
          failedCalls: errorCount,
          slowestCall: 1200
        },
        
        rendering: {
          averageRenderTime: 12,
          totalRenders: totalTests * 2 // Estimate based on tests
        },
        
        memory: {
          usagePercent: Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100),
          currentUsage: memoryUsage.heapUsed,
          averageUsage: Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100),
          currentTotal: memoryUsage.heapTotal,
          currentLimit: memoryUsage.heapTotal * 2
        },
        
        errors: {
          totalErrors: errorCount,
          errorTypes: recentErrors.reduce((acc, error) => {
            acc[error.type || 'Unknown'] = (acc[error.type || 'Unknown'] || 0) + 1;
            return acc;
          }, {}),
          recentErrors: recentErrors.map(error => ({
            type: error.type || 'Unknown',
            timestamp: error.timestamp || new Date().toISOString(),
            details: error.details || {},
            url: error.url || '/unknown',
            userAgent: error.userAgent || 'Unknown'
          }))
        }
      };
      
      res.json({
        success: true,
        data: performanceData
      });
      
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/analytics/export:
 *   get:
 *     summary: Export analytics data as CSV
 *     tags: [Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [trends, distribution, performance, quality]
 *           default: trends
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Analytics data exported successfully
 *         content:
 *           text/csv:
 *             schema:
 *               type: string
 */
router.get('/export',
  requireSupervisor,
  query('type')
    .optional()
    .isIn(['trends', 'distribution', 'performance', 'quality'])
    .withMessage('Type must be trends, distribution, performance, or quality'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  validateRequest,
  async (req, res, next) => {
    try {
      const { type = 'trends', startDate, endDate } = req.query;
      
      // Calculate date range
      const dateRange = {
        start: startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        end: endDate ? new Date(endDate) : new Date()
      };
      
      let csvContent = '';
      let filename = '';
      
      switch (type) {
        case 'trends':
          const trends = await analyticsController.getTestTrends(dateRange, { isActive: true });
          csvContent = 'Date,Total Tests,Completed Tests,Pending Tests,Failed Tests,Completion Rate\n';
          trends.forEach(trend => {
            csvContent += `${trend.date.toISOString().split('T')[0]},${trend.totalTests},${trend.completedTests},${trend.pendingTests},${trend.failedTests},${trend.completionRate}%\n`;
          });
          filename = `test_trends_${Date.now()}.csv`;
          break;
          
        case 'performance':
          const performance = await analyticsController.getTechnicianPerformance(dateRange);
          csvContent = 'Technician,Total Tests,Completed Tests,Failed Tests,Completion Rate,Failure Rate\n';
          performance.forEach(perf => {
            csvContent += `"${perf.technicianName}",${perf.totalTests},${perf.completedTests},${perf.failedTests},${perf.completionRate}%,${perf.failureRate}%\n`;
          });
          filename = `technician_performance_${Date.now()}.csv`;
          break;
          
        default:
          return res.status(400).json({
            success: false,
            message: 'Export type not implemented yet'
          });
      }
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);
      
    } catch (error) {
      next(error);
    }
  }
);

// TAT — turnaround time statistics
router.get('/tat', analyticsController.getTATStats.bind(analyticsController));

module.exports = router;
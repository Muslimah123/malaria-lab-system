
// 📁 server/src/controllers/analyticsController.js - COMPLETE WORKING VERSION
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const Patient = require('../models/Patient');
const User = require('../models/User');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class AnalyticsController {
  /**
   * ✅ FIXED: Get dashboard statistics that match your Dashboard component expectations
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

      // ✅ FIXED: Technicians see only their own tests, but can still access dashboard
      if (user.role === 'technician') {
        baseQuery.technician = user._id;
      }

      // Get yesterday for comparison
      const yesterday = new Date(startOfDay.getTime() - 24 * 60 * 60 * 1000);
      const yesterdayQuery = {
        ...baseQuery,
        createdAt: { $gte: yesterday, $lt: startOfDay }
      };

      console.log('🔍 Dashboard query for user:', user.email, baseQuery);

      // Get all the data in parallel
      const [
        todayTests,
        yesterdayTests,
        completedToday,
        completedYesterday,
        pendingToday,
        pendingYesterday,
        failedToday,
        todayDiagnoses,
        yesterdayDiagnoses,
        recentTests,
        alerts,
        activePatients,
        activeUsers
      ] = await Promise.all([
        Test.countDocuments(baseQuery),
        Test.countDocuments(yesterdayQuery),
        Test.countDocuments({ ...baseQuery, status: 'completed' }),
        Test.countDocuments({ ...yesterdayQuery, status: 'completed' }),
        Test.countDocuments({ ...baseQuery, status: { $in: ['pending', 'processing'] } }),
        Test.countDocuments({ ...yesterdayQuery, status: { $in: ['pending', 'processing'] } }),
        Test.countDocuments({ ...baseQuery, status: 'failed' }),
        this.getTodayDiagnoses(baseQuery),
        this.getTodayDiagnoses(yesterdayQuery),
        this.getRecentTestsForDashboard(user, 10),
        this.getDashboardAlerts(user),
        Patient.countDocuments({ isActive: true }),
        User.countDocuments({ isActive: true, lastLogin: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } })
      ]);

      console.log('📊 Raw dashboard data:', {
        todayTests,
        yesterdayTests,
        positiveToday: todayDiagnoses.positive,
        pendingToday,
        activePatients
      });

      // Calculate percentage changes
      const calculateChange = (current, previous) => {
        if (previous === 0) return current > 0 ? "+100%" : "+0%";
        const change = Math.round(((current - previous) / previous) * 100);
        return change >= 0 ? `+${change}%` : `${change}%`;
      };

      // ✅ EXACT DATA STRUCTURE YOUR DASHBOARD EXPECTS
      const dashboardData = {
        // These fields match your selectDashboardStats selector
        todayTests,
        todayChange: calculateChange(todayTests, yesterdayTests),
        
        positiveToday: todayDiagnoses.positive,
        positiveChange: calculateChange(todayDiagnoses.positive, yesterdayDiagnoses.positive),
        
        pendingReview: pendingToday,
        pendingChange: calculateChange(pendingToday, pendingYesterday),
        
        activePatients,
        patientsChange: "+0%",
        
        // Recent tests for your TestSummary component
        recentTests: recentTests,
        
        // Urgent alerts for your CriticalAlerts component  
        urgentAlerts: alerts,
        
        // System status for your components
        systemStatus: {
          serverHealth: 'healthy',
          databaseStatus: 'connected',
          lastBackup: new Date().toISOString(),
          activeUsers: activeUsers,
          realtime: true
        },
        
        lastUpdated: new Date().toISOString()
      };

      console.log('✅ Sending dashboard data:', dashboardData);

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (error) {
      console.error('❌ Dashboard stats error:', error);
      logger.error('Get dashboard stats error:', error);
      next(new AppError('Failed to retrieve dashboard statistics', 500));
    }
  }

  /**
   * ✅ FIXED: Get recent tests formatted for Dashboard
   */
  // async getRecentTestsForDashboard(user, limit = 10) {
  //   try {
  //     let query = { isActive: true };
      
  //     // Technicians see only their activities
  //     if (user.role === 'technician') {
  //       query.technician = user._id;
  //     }

  //     const recentTests = await Test.find(query)
  //       .populate('patient', 'patientId firstName lastName')
  //       .populate('technician', 'firstName lastName')
  //       .sort({ updatedAt: -1 })
  //       .limit(limit)
  //       .lean();

  //     console.log('📋 Found recent tests:', recentTests.length);

  //     // Format for your TestSummary component
  //     const formattedTests = await Promise.all(recentTests.map(async (test) => {
  //       let result = 'pending';
        
  //       if (test.status === 'completed') {
  //         try {
  //           const diagnosis = await DiagnosisResult.findOne({ test: test._id }).lean();
  //           if (diagnosis) {
  //             result = diagnosis.status === 'POS' ? 'positive' : 'negative';
  //           } else {
  //             result = 'completed';
  //           }
  //         } catch (err) {
  //           result = 'completed';
  //         }
  //       }

  //       return {
  //         id: test._id.toString(),
  //         testId: test.testId,
  //         patientName: test.patient ? `${test.patient.firstName} ${test.patient.lastName}` : 'Unknown Patient',
  //         patientId: test.patient?.patientId || 'N/A',
  //         status: test.status,
  //         result: result,
  //         technician: test.technician ? `${test.technician.firstName} ${test.technician.lastName}` : 'Unknown',
  //         timestamp: test.updatedAt || test.createdAt,
  //         timeAgo: this.getTimeAgo(test.updatedAt || test.createdAt),
  //         priority: test.priority || 'normal',
  //         sampleType: test.sampleType || 'blood_smear'
  //       };
  //     }));

  //     return formattedTests;

  //   } catch (error) {
  //     console.error('❌ Get recent tests error:', error);
  //     return [];
  //   }
  // }
  async getRecentTestsForDashboard(user, limit = 5) { // Changed default to 5
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
      .limit(limit)
      .lean();

    console.log('📋 Found recent tests:', recentTests.length);

          // ✅ ENHANCED: Format with complete diagnosis data including severity
      const formattedTests = await Promise.all(recentTests.map(async (test) => {
        let result = 'pending';
        let severity = null;
        let parasiteType = null;
        
        if (test.status === 'completed') {
          try {
            // ✅ FIXED: Get complete diagnosis data including severity
            const diagnosis = await DiagnosisResult.findOne({ test: test._id }).lean();
            if (diagnosis) {
              // ✅ FIXED: Handle both 'POS'/'POSITIVE' and 'NEG'/'NEGATIVE' formats
              const isPositive = diagnosis.status === 'POS' || diagnosis.status === 'POSITIVE';
              result = isPositive ? 'positive' : 'negative';
              
              // Get severity and parasite info for positive cases
              if (isPositive) {
                severity = diagnosis.severity?.level || 'mild';
                parasiteType = diagnosis.mostProbableParasite?.type || 'Unknown';
                
                // Convert parasite type to readable name
                const parasiteNames = {
                  'PF': 'P. falciparum',
                  'PV': 'P. vivax', 
                  'PM': 'P. malariae',
                  'PO': 'P. ovale'
                };
                parasiteType = parasiteNames[parasiteType] || parasiteType;
              }
            } else {
              result = 'completed';
            }
          } catch (err) {
            console.error('Error fetching diagnosis for test:', test._id, err);
            result = 'completed';
          }
        }

      return {
        id: test._id.toString(),
        testId: test.testId,
        patientName: test.patient ? `${test.patient.firstName} ${test.patient.lastName}` : 'Unknown Patient',
        patientId: test.patient?.patientId || 'N/A',
        status: test.status,
        result: result,
        severity: severity, // ✅ Now included
        parasiteType: parasiteType, // ✅ Now included  
        technician: test.technician ? `${test.technician.firstName} ${test.technician.lastName}` : 'Unknown',
        timestamp: test.updatedAt || test.createdAt,
        timeAgo: this.getTimeAgo(test.updatedAt || test.createdAt),
        processedAt: this.getTimeAgo(test.updatedAt || test.createdAt),
        priority: test.priority || 'normal',
        sampleType: test.sampleType || 'blood_smear'
      };
    }));

    return formattedTests;

  } catch (error) {
    console.error('❌ Get recent tests error:', error);
    return [];
  }
}

  /**
   * ✅ FIXED: Get today's diagnosis statistics
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

      // ✅ FIXED: Handle both 'POS'/'POSITIVE' and 'NEG'/'NEGATIVE' formats
      const positiveCount = diagnoses.reduce((total, d) => {
        if (d._id === 'POS' || d._id === 'POSITIVE') {
          return total + d.count;
        }
        return total;
      }, 0);

      const negativeCount = diagnoses.reduce((total, d) => {
        if (d._id === 'NEG' || d._id === 'NEGATIVE') {
          return total + d.count;
        }
        return total;
      }, 0);

      return {
        positive: positiveCount,
        negative: negativeCount
      };

    } catch (error) {
      console.error('❌ Get today diagnoses error:', error);
      return { positive: 0, negative: 0 };
    }
  }

  /**
   * ✅ FIXED: Get dashboard alerts
   */
  async getDashboardAlerts(user) {
    try {
      const alerts = [];
      
      // Check for pending tests older than 24 hours
      let alertQuery = {
        status: 'pending',
        createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        isActive: true
      };

      if (user.role === 'technician') {
        alertQuery.technician = user._id;
      }

      const oldPendingTests = await Test.countDocuments(alertQuery);

      if (oldPendingTests > 0) {
        alerts.push({
          id: 'pending-tests-' + Date.now(),
          type: 'warning',
          title: 'Pending Tests',
          message: `${oldPendingTests} test(s) have been pending for more than 24 hours`,
          action: 'View pending tests',
          actionUrl: '/tests?status=pending',
          timeAgo: 'Now',
          severity: 'warning'
        });
      }

      // Check for failed tests today
      const today = new Date();
      const startOfDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
      
      let failedQuery = {
        status: 'failed',
        createdAt: { $gte: startOfDay },
        isActive: true
      };

      if (user.role === 'technician') {
        failedQuery.technician = user._id;
      }

      const failedToday = await Test.countDocuments(failedQuery);

      if (failedToday > 0) {
        alerts.push({
          id: 'failed-tests-' + Date.now(),
          type: 'error',
          title: 'Failed Tests',
          message: `${failedToday} test(s) failed today and may need attention`,
          action: 'View failed tests',
          actionUrl: '/tests?status=failed',
          timeAgo: 'Now',
          severity: 'critical'
        });
      }

      // Check for positive results today (for supervisors/admins)
      if (['supervisor', 'admin'].includes(user.role)) {
        const positivesToday = await this.getTodayDiagnoses({
          createdAt: { $gte: startOfDay },
          isActive: true
        });

        if (positivesToday.positive > 0) {
          alerts.push({
            id: 'positive-results-' + Date.now(),
            type: 'info',
            title: 'Positive Results',
            message: `${positivesToday.positive} positive result(s) detected today`,
            action: 'View results',
            actionUrl: '/results?status=positive',
            timeAgo: 'Now',
            severity: 'info'
          });
        }
      }

      return alerts;

    } catch (error) {
      console.error('❌ Get dashboard alerts error:', error);
      return [];
    }
  }

  /**
   * ✅ ADDED: Get human-readable time ago
   */
  getTimeAgo(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const now = new Date();
    const date = new Date(timestamp);
    const diffInMinutes = Math.floor((now - date) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours}h ago`;
    
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}d ago`;
    
    return date.toLocaleDateString();
  }

  // ✅ KEEP ALL YOUR EXISTING METHODS BELOW (don't change these)
  
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
   * GET /api/analytics/tat — Turnaround time stats
   */
  async getTATStats(req, res, next) {
    try {
      const { startDate, endDate } = req.query;
      const dateFilter = {};
      if (startDate) dateFilter.$gte = new Date(startDate);
      if (endDate)   dateFilter.$lte = new Date(endDate);

      const query = { status: 'completed', processedAt: { $exists: true } };
      if (Object.keys(dateFilter).length) query.createdAt = dateFilter;

      // SLA thresholds in minutes
      const SLA = { urgent: 60, high: 120, normal: 240, low: 480 };

      const completedTests = await Test.find(query)
        .select('createdAt processedAt priority')
        .lean();

      if (!completedTests.length) {
        return res.json({ success: true, data: { avgTAT: 0, byPriority: {}, slaBreaches: 0, totalCompleted: 0 } });
      }

      const byPriority = { urgent: [], high: [], normal: [], low: [] };
      let slaBreaches = 0;

      completedTests.forEach(t => {
        const tat = (new Date(t.processedAt) - new Date(t.createdAt)) / 60000; // minutes
        const prio = t.priority || 'normal';
        if (byPriority[prio]) byPriority[prio].push(tat);
        if (tat > (SLA[prio] || SLA.normal)) slaBreaches++;
      });

      const avg = arr => arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : null;

      const allTATs = completedTests.map(t => (new Date(t.processedAt) - new Date(t.createdAt)) / 60000);
      const avgTAT = avg(allTATs);

      const priorityStats = {};
      Object.entries(byPriority).forEach(([prio, tats]) => {
        priorityStats[prio] = {
          avg: avg(tats),
          count: tats.length,
          slaMinutes: SLA[prio],
          breaches: tats.filter(t => t > SLA[prio]).length
        };
      });

      res.json({
        success: true,
        data: {
          avgTAT,
          totalCompleted: completedTests.length,
          slaBreaches,
          slaBreachRate: Math.round((slaBreaches / completedTests.length) * 100),
          byPriority: priorityStats
        }
      });
    } catch (error) {
      logger.error('TAT stats error:', error);
      next(new AppError('Failed to get TAT statistics', 500));
    }
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
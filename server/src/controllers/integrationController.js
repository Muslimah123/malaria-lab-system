// 📁 server/src/controllers/integrationController.js
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const axios = require('axios');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class IntegrationController {
  /**
   * Export all test data in JSON format (for EMR integration)
   */
  async exportTestsJson(req, res, next) {
    try {
      const tests = await Test.find().populate('patient').lean();

      const enrichedTests = await Promise.all(
        tests.map(async (test) => {
          const diagnosis = await DiagnosisResult.findOne({ testId: test._id }).lean();
          return { ...test, diagnosis };
        })
      );

      res.json({ success: true, data: enrichedTests });
    } catch (error) {
      logger.error('Export tests JSON error:', error);
      next(new AppError('Failed to export test data', 500));
    }
  }

  /**
   * Export all test data in CSV format (for EMR integration)
   */
  async exportTestsCsv(req, res, next) {
    try {
      const tests = await Test.find().populate('patient').lean();
      const enrichedTests = await Promise.all(
        tests.map(async (test) => {
          const diagnosis = await DiagnosisResult.findOne({ testId: test._id }).lean();
          return { ...test, diagnosis };
        })
      );

      const csvData = enrichedTests.map(t => ({
        TestID: t._id,
        PatientName: t.patient?.name || 'N/A',
        Date: new Date(t.createdAt).toLocaleString(),
        Status: t.status,
        DiagnosisStatus: t.diagnosis?.status || 'N/A',
        MostProbableParasite: t.diagnosis?.mostProbableParasite?.type || 'N/A',  // ✅ FIXED: Using camelCase from Flask API
        ParasiteConfidence: t.diagnosis?.mostProbableParasite?.confidence || 'N/A'  // ✅ FIXED: Using camelCase from Flask API
      }));

      const { Parser } = require('json2csv');
      const parser = new Parser();
      const csv = parser.parse(csvData);

      res.set({
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="tests-export.csv"'
      });
      res.send(csv);
    } catch (error) {
      logger.error('Export tests CSV error:', error);
      next(new AppError('Failed to export test data', 500));
    }
  }

  /**
   * Sync single test result to hospital system
   */
  async syncTestResult(req, res, next) {
    try {
      const { testId } = req.params;
      const { system = 'api', priority = 'normal' } = req.body;

      const test = await Test.findById(testId).populate('patient').lean();
      if (!test) {
        return res.status(404).json({ success: false, message: 'Test not found' });
      }

      const diagnosis = await DiagnosisResult.findOne({ testId: test._id }).lean();
      if (!diagnosis) {
        return res.status(404).json({ success: false, message: 'Diagnosis not found' });
      }

      const payload = { test, diagnosis, system, priority };
      const response = await axios.post('https://example-hospital-api.com/sync', payload, { timeout: 5000 });

      res.json({
        success: true,
        message: 'Test synced successfully',
        data: response.data
      });
    } catch (error) {
      logger.error('Sync test result error:', error);
      next(new AppError('Failed to sync test result', 500));
    }
  }

  /**
   * Bulk sync multiple test results
   */
  async bulkSyncResults(req, res, next) {
    try {
      const { testIds, dateRange, system = 'api', priority = 'normal' } = req.body;

      let query = {};
      if (testIds?.length) {
        query._id = { $in: testIds };
      } else if (dateRange?.start && dateRange?.end) {
        query.createdAt = { $gte: new Date(dateRange.start), $lte: new Date(dateRange.end) };
      }

      const tests = await Test.find(query).populate('patient').lean();

      const results = [];
      for (const test of tests) {
        const diagnosis = await DiagnosisResult.findOne({ testId: test._id }).lean();
        const payload = { test, diagnosis, system, priority };

        try {
          const response = await axios.post('https://example-hospital-api.com/sync', payload, { timeout: 5000 });
          results.push({ testId: test._id, status: 'success', response: response.data });
        } catch (err) {
          logger.error(`Failed to sync test ${test._id}:`, err.message);
          results.push({ testId: test._id, status: 'failure', error: err.message });
        }
      }

      res.json({
        success: true,
        message: 'Bulk sync completed',
        results
      });
    } catch (error) {
      logger.error('Bulk sync error:', error);
      next(new AppError('Failed to bulk sync results', 500));
    }
  }

  /**
   * Get sync status (dummy implementation)
   */
  async getSyncStatus(req, res, next) {
    try {
      const { testIds, startDate, endDate, status } = req.query;

      const dummyStatus = [
        { testId: '123', status: 'synced' },
        { testId: '124', status: 'pending' }
      ];

      res.json({
        success: true,
        data: {
          statusSummary: dummyStatus,
          filters: { testIds, startDate, endDate, status }
        }
      });
    } catch (error) {
      logger.error('Get sync status error:', error);
      next(new AppError('Failed to retrieve sync status', 500));
    }
  }

  /**
   * Configure integration settings
   */
  async configureIntegration(req, res, next) {
    try {
      const { hospitalEndpoint, authMethod, credentials, syncSchedule, autoSync, retrySettings } = req.body;

      const IntegrationConfig = require('../models/IntegrationConfig');
      await IntegrationConfig.updateOne(
        {},
        { hospitalEndpoint, authMethod, credentials, syncSchedule, autoSync, retrySettings },
        { upsert: true }
      );

      res.json({ success: true, message: 'Integration settings configured successfully' });
    } catch (error) {
      logger.error('Configure integration error:', error);
      next(new AppError('Failed to configure integration', 500));
    }
  }

  /**
   * Retry failed syncs
   */
  async retryFailedSyncs(req, res, next) {
    try {
      const { testIds = [], maxRetries = 3 } = req.body;

      const results = [];
      for (const testId of testIds) {
        let attempt = 0;
        let success = false;
        let errorMsg = null;

        while (attempt < maxRetries && !success) {
          attempt++;
          try {
            const test = await Test.findById(testId).populate('patient').lean();
            const diagnosis = await DiagnosisResult.findOne({ testId: test._id }).lean();

            const payload = { test, diagnosis };
            await axios.post('https://example-hospital-api.com/sync', payload, { timeout: 5000 });

            success = true;
            results.push({ testId, status: 'success', attempts: attempt });
          } catch (err) {
            errorMsg = err.message;
          }
        }

        if (!success) {
          results.push({ testId, status: 'failure', error: errorMsg });
        }
      }

      res.json({ success: true, results });
    } catch (error) {
      logger.error('Retry failed syncs error:', error);
      next(new AppError('Failed to retry syncs', 500));
    }
  }

  /**
   * Test connection to hospital system
   */
  async testHospitalConnection(endpoint, authMethod, credentials) {
    try {
      const start = Date.now();

      const headers = {};
      if (authMethod === 'bearer' && credentials?.token) {
        headers['Authorization'] = `Bearer ${credentials.token}`;
      } else if (authMethod === 'basic' && credentials?.username && credentials?.password) {
        const basicAuth = Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
        headers['Authorization'] = `Basic ${basicAuth}`;
      }

      const response = await axios.get(endpoint, { headers, timeout: 5000 });
      const duration = Date.now() - start;

      return {
        success: true,
        responseTime: duration,
        results: response.data
      };
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('Error testing hospital connection:', error.message);
      return {
        success: false,
        responseTime: duration,
        error: error.message
      };
    }
  }

  /**
   * Get integration status
   */
  async getIntegrationStatus(req, res, next) {
    try {
      const status = {
        connected: true,
        lastSync: new Date(),
        totalSynced: 150,
        pendingSyncs: 5
      };

      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      logger.error('Get integration status error:', error);
      next(new AppError('Failed to get integration status', 500));
    }
  }
}

module.exports = new IntegrationController();

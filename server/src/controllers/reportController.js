// 📁 server/src/controllers/reportController.js
const PDFDocument = require('pdfkit');
const fs = require('fs').promises;
const path = require('path');
const Test = require('../models/Test');
const DiagnosisResult = require('../models/DiagnosisResult');
const Patient = require('../models/Patient');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errorTypes');

class ReportController {
  /**
   * Generate PDF report for a single test
   */
  async generateTestReport(req, res, next) {
    try {
      const { testId } = req.params;
      const { format = 'pdf', includeImages = false } = req.query;
      const user = req.user;

      // Find test with all related data
      const test = await Test.findOne({ testId: testId.toUpperCase() })
        .populate('patient')
        .populate('technician', 'firstName lastName username')
        .populate('reviewer', 'firstName lastName username');

      if (!test) {
        return res.status(404).json({
          success: false,
          message: 'Test not found'
        });
      }

      // Check access permissions
      const hasAccess = this.checkReportAccess(test, user);
      if (!hasAccess.allowed) {
        return res.status(403).json({
          success: false,
          message: hasAccess.reason
        });
      }

      // Get diagnosis result
      const diagnosisResult = await DiagnosisResult.findOne({ test: test._id });
      if (!diagnosisResult) {
        return res.status(404).json({
          success: false,
          message: 'Diagnosis result not found'
        });
      }

      // Generate report based on format
      let reportBuffer;
      let contentType;
      let filename;

      if (format === 'pdf') {
        reportBuffer = await this.generatePDFReport(test, diagnosisResult, includeImages);
        contentType = 'application/pdf';
        filename = `malaria_report_${testId}_${Date.now()}.pdf`;
      } else if (format === 'json') {
        const reportData = await this.generateJSONReport(test, diagnosisResult);
        reportBuffer = Buffer.from(JSON.stringify(reportData, null, 2));
        contentType = 'application/json';
        filename = `malaria_report_${testId}_${Date.now()}.json`;
      } else {
        return res.status(400).json({
          success: false,
          message: 'Unsupported format. Use pdf or json'
        });
      }

      // Log report generation
      await auditService.log({
        action: 'report_generated',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'report',
        resourceId: testId,
        resourceName: `Report for ${testId}`,
        details: {
          format,
          includeImages,
          patientId: test.patientId,
          diagnosisResult: diagnosisResult.status
        },
        requestInfo: {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          method: 'GET',
          endpoint: `/api/reports/test/${testId}`
        },
        status: 'success',
        riskLevel: 'medium' // Medical data access
      });

      // Set response headers
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', reportBuffer.length);

      res.send(reportBuffer);

    } catch (error) {
      logger.error('Generate test report error:', error);
      next(new AppError('Failed to generate report', 500));
    }
  }

  /**
   * Generate bulk reports
   */
  async generateBulkReports(req, res, next) {
    try {
      const { testIds, patientId, dateRange, format = 'pdf' } = req.body;
      const user = req.user;

      // Build query based on provided criteria
      let query = { isActive: true };
      
      if (testIds && testIds.length > 0) {
        query.testId = { $in: testIds.map(id => id.toUpperCase()) };
      }
      
      if (patientId) {
        query.patientId = patientId;
      }
      
      if (dateRange && dateRange.start && dateRange.end) {
        query.createdAt = {
          $gte: new Date(dateRange.start),
          $lte: new Date(dateRange.end)
        };
      }

      // Find tests
      const tests = await Test.find(query)
        .populate('patient')
        .populate('technician', 'firstName lastName username')
        .populate('reviewer', 'firstName lastName username')
        .sort({ createdAt: -1 })
        .limit(50); // Limit to prevent abuse

      if (tests.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'No tests found matching criteria'
        });
      }

      // Check access for all tests
      const accessibleTests = tests.filter(test => {
        const access = this.checkReportAccess(test, user);
        return access.allowed;
      });

      if (accessibleTests.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'No accessible tests found'
        });
      }

      // Generate bulk report
      const reportBuffer = await this.generateBulkPDFReport(accessibleTests);
      const filename = `malaria_bulk_report_${Date.now()}.pdf`;

      // Log bulk report generation
      await auditService.log({
        action: 'bulk_report_generated',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'report',
        resourceId: 'bulk_report',
        details: {
          testsIncluded: accessibleTests.length,
          totalTestsRequested: tests.length,
          format,
          criteria: { testIds: testIds?.length, patientId, dateRange }
        },
        status: 'success',
        riskLevel: 'high' // Bulk medical data access
      });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(reportBuffer);

    } catch (error) {
      logger.error('Generate bulk reports error:', error);
      next(new AppError('Failed to generate bulk reports', 500));
    }
  }

  /**
   * Export data in CSV format
   */
  async exportCSV(req, res, next) {
    try {
      const { startDate, endDate, includePatientData = false } = req.query;
      const user = req.user;

      // Only supervisors and admins can export data
      if (!['supervisor', 'admin'].includes(user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to export data'
        });
      }

      // Build date range query
      let dateQuery = {};
      if (startDate && endDate) {
        dateQuery = {
          createdAt: {
            $gte: new Date(startDate),
            $lte: new Date(endDate)
          }
        };
      }

      // Get diagnosis results with test data
      const results = await DiagnosisResult.find(dateQuery)
        .populate({
          path: 'test',
          populate: [
            { path: 'patient', select: includePatientData === 'true' ? '' : 'patientId' },
            { path: 'technician', select: 'firstName lastName username' }
          ]
        })
        .sort({ createdAt: -1 });

      // Generate CSV content
      const csvContent = this.generateCSVContent(results, includePatientData === 'true');
      const filename = `malaria_export_${Date.now()}.csv`;

      // Log data export
      await auditService.log({
        action: 'data_exported',
        userId: user._id,
        userInfo: { username: user.username, email: user.email, role: user.role },
        resourceType: 'export',
        resourceId: 'csv_export',
        details: {
          recordCount: results.length,
          includePatientData,
          dateRange: { startDate, endDate }
        },
        status: 'success',
        riskLevel: 'high' // Data export
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(csvContent);

    } catch (error) {
      logger.error('Export CSV error:', error);
      next(new AppError('Failed to export data', 500));
    }
  }

  /**
   * Get available reports for user
   */
  async getAvailableReports(req, res, next) {
    try {
      const { page = 1, limit = 20, patientId, status } = req.query;
      const user = req.user;
      const skip = (parseInt(page) - 1) * parseInt(limit);

      // Build query based on user role
      let query = { isActive: true };
      
      if (user.role === 'technician') {
        query.technician = user._id;
      }
      
      if (patientId) {
        query.patientId = patientId;
      }
      
      if (status) {
        query.status = status;
      }

      // Get tests with diagnosis results
      const [tests, total] = await Promise.all([
        Test.find(query)
          .populate('patient', 'patientId firstName lastName age gender')
          .populate('technician', 'firstName lastName username')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit)),
        Test.countDocuments(query)
      ]);

      // Filter tests that have diagnosis results
      const testsWithResults = [];
      for (const test of tests) {
        const hasResult = await DiagnosisResult.exists({ test: test._id });
        if (hasResult) {
          testsWithResults.push({
            ...test.toObject(),
            hasReport: true,
            reportTypes: ['pdf', 'json']
          });
        }
      }

      const totalPages = Math.ceil(total / parseInt(limit));

      res.json({
        success: true,
        data: {
          reports: testsWithResults,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: testsWithResults.length,
            pages: Math.ceil(testsWithResults.length / parseInt(limit))
          }
        }
      });

    } catch (error) {
      logger.error('Get available reports error:', error);
      next(new AppError('Failed to retrieve available reports', 500));
    }
  }

  /**
   * Generate PDF report for a single test
   */
  async generatePDFReport(test, diagnosisResult, includeImages = false) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        const chunks = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Header
        doc.fontSize(20).font('Helvetica-Bold')
           .text('MALARIA DIAGNOSIS REPORT', { align: 'center' });
        
        doc.moveDown(1);
        
        // Report metadata
        doc.fontSize(10).font('Helvetica')
           .text(`Generated: ${new Date().toLocaleString()}`)
           .text(`Report ID: ${test.testId}`)
           .moveDown(0.5);

        // Patient Information
        doc.fontSize(14).font('Helvetica-Bold')
           .text('PATIENT INFORMATION');
        
        doc.fontSize(11).font('Helvetica')
           .text(`Patient ID: ${test.patient.patientId}`)
           .text(`Name: ${test.patient.firstName} ${test.patient.lastName}`)
           .text(`Age: ${test.patient.age} years`)
           .text(`Gender: ${test.patient.gender}`)
           .moveDown(1);

        // Test Information
        doc.fontSize(14).font('Helvetica-Bold')
           .text('TEST INFORMATION');
        
        doc.fontSize(11).font('Helvetica')
           .text(`Test ID: ${test.testId}`)
           .text(`Test Date: ${test.createdAt.toLocaleDateString()}`)
           .text(`Technician: ${test.technician.firstName} ${test.technician.lastName}`)
           .text(`Status: ${test.status.toUpperCase()}`)
           .moveDown(1);

        // Diagnosis Results
        doc.fontSize(14).font('Helvetica-Bold')
           .text('DIAGNOSIS RESULTS');

        // Result status with color
        doc.fontSize(12);
        if (diagnosisResult.status === 'POS') {
          doc.fillColor('red').font('Helvetica-Bold')
             .text('RESULT: POSITIVE FOR MALARIA', { continued: false });
        } else {
          doc.fillColor('green').font('Helvetica-Bold')
             .text('RESULT: NEGATIVE FOR MALARIA', { continued: false });
        }

        doc.fillColor('black').font('Helvetica');

        if (diagnosisResult.status === 'POS') {
          if (diagnosisResult.mostProbableParasite) {
            doc.text(`Most Probable Parasite: ${this.getParasiteName(diagnosisResult.mostProbableParasite.type)}`)
               .text(`Confidence: ${(diagnosisResult.mostProbableParasite.confidence * 100).toFixed(1)}%`);
          }

          if (diagnosisResult.severity) {
            doc.text(`Severity: ${diagnosisResult.severity.level.toUpperCase()}`)
               .text(`Classification: ${diagnosisResult.severity.classification}`);
          }

          doc.text(`Parasite-WBC Ratio: ${diagnosisResult.parasiteWbcRatio.toFixed(3)}`);
        }

        doc.moveDown(1);

        // Detection Details
        if (diagnosisResult.detections && diagnosisResult.detections.length > 0) {
          doc.fontSize(14).font('Helvetica-Bold')
             .text('DETECTION DETAILS');

          diagnosisResult.detections.forEach((detection, index) => {
            doc.fontSize(12).font('Helvetica-Bold')
               .text(`Image ${index + 1}: ${detection.imageId}`);
            
            doc.fontSize(11).font('Helvetica')
               .text(`Parasites Detected: ${detection.parasiteCount}`)
               .text(`White Blood Cells: ${detection.whiteBloodCellsDetected}`)
               .text(`Parasite-WBC Ratio: ${detection.parasiteWbcRatio.toFixed(3)}`);

            if (detection.parasitesDetected && detection.parasitesDetected.length > 0) {
              doc.text('Detected Parasites:');
              detection.parasitesDetected.forEach((parasite, pIndex) => {
                doc.text(`  ${pIndex + 1}. ${this.getParasiteName(parasite.type)} (${(parasite.confidence * 100).toFixed(1)}% confidence)`);
              });
            }
            doc.moveDown(0.5);
          });
        }

        // Recommendations
        doc.fontSize(14).font('Helvetica-Bold')
           .text('RECOMMENDATIONS');

        doc.fontSize(11).font('Helvetica');
        if (diagnosisResult.status === 'POS') {
          doc.text('• Immediate medical consultation recommended')
             .text('• Begin appropriate antimalarial treatment')
             .text('• Monitor patient condition closely')
             .text('• Follow-up testing may be required');
        } else {
          doc.text('• No malaria parasites detected')
             .text('• If symptoms persist, consider other diagnostic tests')
             .text('• Maintain preventive measures in endemic areas');
        }

        doc.moveDown(1);

        // Footer
        doc.fontSize(8).font('Helvetica')
           .text('This report is generated by an automated system and should be reviewed by qualified medical personnel.', 
                 { align: 'center' });

        doc.end();

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Generate JSON report for API integration
   */
  async generateJSONReport(test, diagnosisResult) {
    return {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        reportId: test.testId,
        version: '1.0'
      },
      patient: {
        patientId: test.patient.patientId,
        demographics: {
          age: test.patient.age,
          gender: test.patient.gender
        }
      },
      test: {
        testId: test.testId,
        testDate: test.createdAt.toISOString(),
        technician: {
          id: test.technician._id,
          name: `${test.technician.firstName} ${test.technician.lastName}`
        },
        status: test.status
      },
      diagnosis: {
        result: diagnosisResult.status,
        timestamp: diagnosisResult.createdAt.toISOString(),
        mostProbableParasite: diagnosisResult.mostProbableParasite ? {
          type: diagnosisResult.mostProbableParasite.type,
          name: this.getParasiteName(diagnosisResult.mostProbableParasite.type),
          confidence: diagnosisResult.mostProbableParasite.confidence
        } : null,
        severity: diagnosisResult.severity,
        parasiteWbcRatio: diagnosisResult.parasiteWbcRatio,
        detections: diagnosisResult.detections.map(detection => ({
          imageId: detection.imageId,
          originalFilename: detection.originalFilename,
          parasiteCount: detection.parasiteCount,
          whiteBloodCellsDetected: detection.whiteBloodCellsDetected,
          parasiteWbcRatio: detection.parasiteWbcRatio,
          parasitesDetected: detection.parasitesDetected.map(parasite => ({
            type: parasite.type,
            name: this.getParasiteName(parasite.type),
            confidence: parasite.confidence,
            boundingBox: parasite.bbox
          }))
        }))
      },
      qualityMetrics: {
        confidence: diagnosisResult.mostProbableParasite?.confidence || 0,
        imageQuality: 'acceptable', // Could be enhanced with actual quality metrics
        processingTime: diagnosisResult.apiResponse?.processingTime
      }
    };
  }

  /**
   * Generate bulk PDF report
   */
  async generateBulkPDFReport(tests) {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        const chunks = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Header
        doc.fontSize(20).font('Helvetica-Bold')
           .text('MALARIA DIAGNOSIS BULK REPORT', { align: 'center' });
        
        doc.moveDown(1);
        
        // Summary
        doc.fontSize(14).font('Helvetica-Bold')
           .text('SUMMARY');
        
        const positiveTests = tests.filter(test => test.status === 'completed');
        // Get diagnosis results for summary
        const diagnosisResults = await Promise.all(
          tests.map(test => DiagnosisResult.findOne({ test: test._id }))
        );
        
        const positiveResults = diagnosisResults.filter(result => result?.status === 'POS').length;
        
        doc.fontSize(11).font('Helvetica')
           .text(`Total Tests: ${tests.length}`)
           .text(`Positive Results: ${positiveResults}`)
           .text(`Negative Results: ${diagnosisResults.length - positiveResults}`)
           .text(`Generated: ${new Date().toLocaleString()}`)
           .moveDown(1);

        // Individual test results
        for (let i = 0; i < tests.length; i++) {
          const test = tests[i];
          const diagnosisResult = diagnosisResults[i];
          
          if (i > 0) {
            doc.addPage();
          }
          
          doc.fontSize(14).font('Helvetica-Bold')
             .text(`TEST ${i + 1}: ${test.testId}`);
          
          if (diagnosisResult) {
            // Add individual test report content here
            doc.fontSize(11).font('Helvetica')
               .text(`Patient: ${test.patient.patientId}`)
               .text(`Date: ${test.createdAt.toLocaleDateString()}`)
               .text(`Result: ${diagnosisResult.status}`)
               .text(`Technician: ${test.technician.firstName} ${test.technician.lastName}`);
            
            if (diagnosisResult.status === 'POS' && diagnosisResult.mostProbableParasite) {
              doc.text(`Parasite: ${this.getParasiteName(diagnosisResult.mostProbableParasite.type)}`)
                 .text(`Confidence: ${(diagnosisResult.mostProbableParasite.confidence * 100).toFixed(1)}%`);
            }
          }
          
          doc.moveDown(1);
        }

        doc.end();

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Generate CSV content for data export
   */
  generateCSVContent(results, includePatientData = false) {
    const headers = [
      'Test ID',
      'Patient ID',
      'Test Date',
      'Result',
      'Parasite Type',
      'Confidence',
      'Severity',
      'Parasite Count',
      'WBC Count',
      'Parasite-WBC Ratio',
      'Technician'
    ];

    if (includePatientData) {
      headers.splice(2, 0, 'Patient Name', 'Age', 'Gender');
    }

    let csvContent = headers.join(',') + '\n';

    results.forEach(result => {
      if (!result.test) return;

      const row = [
        result.testId || '',
        result.test.patientId || '',
        result.test.createdAt ? result.test.createdAt.toISOString().split('T')[0] : '',
        result.status || '',
        result.mostProbableParasite ? this.getParasiteName(result.mostProbableParasite.type) : '',
        result.mostProbableParasite ? (result.mostProbableParasite.confidence * 100).toFixed(1) + '%' : '',
        result.severity?.level || '',
        result.detections?.reduce((sum, d) => sum + (d.parasiteCount || 0), 0) || '0',
        result.detections?.reduce((sum, d) => sum + (d.whiteBloodCellsDetected || 0), 0) || '0',
        result.parasiteWbcRatio?.toFixed(3) || '0',
        result.test.technician ? `${result.test.technician.firstName} ${result.test.technician.lastName}` : ''
      ];

      if (includePatientData && result.test.patient) {
        row.splice(2, 0, 
          `${result.test.patient.firstName} ${result.test.patient.lastName}`,
          result.test.patient.age?.toString() || '',
          result.test.patient.gender || ''
        );
      }

      csvContent += row.map(field => `"${field}"`).join(',') + '\n';
    });

    return csvContent;
  }

  /**
   * Check if user has access to view report
   */
  checkReportAccess(test, user) {
    // Admin and supervisors can access all reports
    if (['admin', 'supervisor'].includes(user.role)) {
      return { allowed: true };
    }

    // Technicians can only access their own tests
    if (user.role === 'technician' && test.technician.toString() === user._id.toString()) {
      return { allowed: true };
    }

    return { 
      allowed: false, 
      reason: 'You do not have permission to access this report' 
    };
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

module.exports = new ReportController();
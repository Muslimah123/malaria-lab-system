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
   * Generate a structured clinical PDF report.
   */
  async generatePDFReport(test, diagnosisResult, includeImages = false) {
    return new Promise(async (resolve, reject) => {
      try {
        // bottom:0 means PDFKit never auto-paginates — we own all page breaks via checkY.
        // bufferPages lets us add the footer to every page after content is drawn.
        const doc = new PDFDocument({
          margins: { top: 50, left: 50, right: 50, bottom: 0 },
          size: 'A4',
          bufferPages: true
        });
        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        const L = 50;
        const W = doc.page.width - 100;
        const SAFE_BOTTOM = doc.page.height - 65; // reserve 65pt at bottom for footer

        const finalStatus = diagnosisResult.manualReview?.overriddenStatus || diagnosisResult.status;
        const finalSeverity = diagnosisResult.manualReview?.overriddenSeverity || diagnosisResult.severity?.level;
        const isPositive = finalStatus === 'POSITIVE';
        const reviewed = diagnosisResult.manualReview?.isReviewed;
        const p = test.patient;
        const tech = test.technician;
        const reportDate = new Date().toISOString();

        // Explicit page break — no footer drawing here (done at the end via switchToPage)
        let y = 50;
        const newPage = () => { doc.addPage(); y = 50; };
        const checkY = (need) => { if (y + need > SAFE_BOTTOM) newPage(); };

        // Section heading: bold blue label + underline, advances y
        const sectionHead = (label) => {
          checkY(32);
          doc.fontSize(11).font('Helvetica-Bold').fillColor('#1e3a5f')
             .text(label, L, y, { lineBreak: false });
          y += 16;
          doc.moveTo(L, y).lineTo(L + W, y).lineWidth(0.5).stroke('#1e3a5f');
          y += 6;
        };

        // Key-value row, advances y by 15
        const kv = (label, value, x, labelW, totalW) => {
          checkY(15);
          doc.fontSize(9).font('Helvetica').fillColor('#666666')
             .text(label + ':', x, y, { width: labelW, lineBreak: false });
          doc.fontSize(9).font('Helvetica-Bold').fillColor('#111111')
             .text(String(value ?? 'N/A'), x + labelW, y, { width: totalW - labelW, lineBreak: false });
          y += 15;
        };

        // ── HEADER ──────────────────────────────────────────────────────
        doc.rect(L, 40, W, 52).fill('#1e3a5f');
        doc.fillColor('white').fontSize(15).font('Helvetica-Bold')
           .text('MALARIA LABORATORY DECISION SUPPORT SYSTEM', L, 51, { width: W, align: 'center', lineBreak: false });
        doc.fontSize(8).font('Helvetica')
           .text('DIAGNOSTIC REPORT  —  FOR CLINICAL DECISION SUPPORT ONLY', L, 71, { width: W, align: 'center', lineBreak: false });

        // ── DISCLAIMER ──────────────────────────────────────────────────
        y = 104;
        doc.rect(L, y, W, 24).fill('#fff3cd');
        doc.rect(L, y, W, 24).stroke('#e6ac00');
        doc.fillColor('#7d5a00').fontSize(7.5).font('Helvetica-Bold')
           .text(
             'IMPORTANT: This report is generated by an AI-assisted decision support system and is NOT a clinical diagnosis. ' +
             'Results MUST be reviewed and confirmed by a qualified medical professional before any clinical action is taken.',
             L + 6, y + 6, { width: W - 12, lineBreak: false }
           );
        y += 32;

        // ── META BAR ────────────────────────────────────────────────────
        doc.fillColor('#333333').fontSize(8).font('Helvetica')
           .text(`Report ID: ${test.testId}`, L, y, { lineBreak: false });
        doc.text(`Generated: ${new Date().toLocaleString()}`, L + 170, y, { lineBreak: false });
        doc.text(`Review Status: ${reviewed ? 'Clinically Reviewed' : 'Pending Review'}`, L + 360, y, { lineBreak: false });
        y += 12;
        doc.moveTo(L, y).lineTo(L + W, y).lineWidth(0.5).stroke('#cccccc');
        y += 10;

        // ── PATIENT & TEST INFO (two columns) ────────────────────────────
        const colW = (W - 16) / 2;
        const colR = L + colW + 16;
        const boxH = 106;
        checkY(boxH + 20);
        const boxTop = y;

        doc.rect(L, boxTop, colW, boxH).stroke('#dddddd');
        doc.fillColor('#1e3a5f').fontSize(9).font('Helvetica-Bold')
           .text('PATIENT INFORMATION', L + 8, boxTop + 7, { lineBreak: false });
        [
          ['Patient ID',   p?.patientId],
          ['Full Name',    p ? `${p.firstName} ${p.lastName}` : null],
          ['Age / Gender', p ? `${p.age ?? 'N/A'} yrs / ${p.gender ?? 'N/A'}` : null],
          ['Blood Type',   p?.bloodType],
          ['Contact',      p?.phoneNumber],
        ].forEach(([lbl, val], i) => {
          const ry = boxTop + 23 + i * 16;
          doc.fontSize(8.5).font('Helvetica').fillColor('#666666')
             .text(lbl + ':', L + 8, ry, { width: 78, lineBreak: false });
          doc.fontSize(8.5).font('Helvetica-Bold').fillColor('#111111')
             .text(String(val ?? 'N/A'), L + 86, ry, { width: colW - 90, lineBreak: false });
        });

        doc.rect(colR, boxTop, colW, boxH).stroke('#dddddd');
        doc.fillColor('#1e3a5f').fontSize(9).font('Helvetica-Bold')
           .text('TEST INFORMATION', colR + 8, boxTop + 7, { lineBreak: false });
        [
          ['Test ID',      test.testId],
          ['Date / Time',  test.createdAt?.toLocaleString()],
          ['Technician',   tech ? `${tech.firstName} ${tech.lastName}` : null],
          ['Sample Type',  test.sampleType || 'Blood Smear'],
          ['Priority',     (test.priority || 'normal').toUpperCase()],
        ].forEach(([lbl, val], i) => {
          const ry = boxTop + 23 + i * 16;
          doc.fontSize(8.5).font('Helvetica').fillColor('#666666')
             .text(lbl + ':', colR + 8, ry, { width: 78, lineBreak: false });
          doc.fontSize(8.5).font('Helvetica-Bold').fillColor('#111111')
             .text(String(val ?? 'N/A'), colR + 86, ry, { width: colW - 90, lineBreak: false });
        });
        y = boxTop + boxH + 14;

        // ── AI ANALYSIS RESULT ───────────────────────────────────────────
        sectionHead('AI ANALYSIS RESULT');

        const bannerH = 24;
        checkY(bannerH + 10);
        doc.rect(L, y, W, bannerH).fill(isPositive ? '#c0392b' : '#1a7a4a');
        doc.fillColor('white').fontSize(12).font('Helvetica-Bold')
           .text(
             isPositive ? 'POSITIVE — MALARIA PARASITES DETECTED'
                        : 'NEGATIVE — NO MALARIA PARASITES DETECTED',
             L, y + 6, { width: W, align: 'center', lineBreak: false }
           );
        y += bannerH + 10;

        if (isPositive && diagnosisResult.mostProbableParasite) {
          const mp = diagnosisResult.mostProbableParasite;
          const conf = mp.confidence <= 1 ? mp.confidence * 100 : mp.confidence;
          kv('Most Probable Parasite', `${mp.fullName || this.getParasiteName(mp.type)} (${mp.type})`, L, 160, W);
          kv('AI Confidence',          `${conf.toFixed(1)}%`,                                           L, 160, W);
          kv('Parasite / WBC Ratio',   (diagnosisResult.parasiteWbcRatio || 0).toFixed(3),              L, 160, W);
          kv('Severity Estimate',      (finalSeverity || 'N/A').toUpperCase(),                          L, 160, W);
        }
        kv('Total Parasites Detected', diagnosisResult.totalParasites ?? 0,      L, 160, W);
        kv('Total WBCs Detected',      diagnosisResult.totalWbcs ?? 0,           L, 160, W);
        kv('Images Analysed',          diagnosisResult.totalImagesAttempted ?? 0, L, 160, W);

        // ── PER-IMAGE BREAKDOWN ──────────────────────────────────────────
        if (diagnosisResult.detections?.length > 0) {
          y += 8;
          sectionHead('PER-IMAGE DETECTION BREAKDOWN');

          const cx = [0, 200, 250, 305, 368];
          const cw = [195, 45, 50, 58, 127];
          const rowH = 15;

          // table header row
          checkY(rowH * 2);
          doc.rect(L, y, W, rowH).fill('#dce6f4');
          ['Image File', 'Parasites', 'WBCs', 'P/WBC', 'Dominant Type'].forEach((h, i) => {
            doc.fillColor('#1e3a5f').fontSize(7.5).font('Helvetica-Bold')
               .text(h, L + cx[i] + 3, y + 3, { width: cw[i], lineBreak: false });
          });
          y += rowH;

          diagnosisResult.detections.forEach((det, idx) => {
            checkY(rowH + 2);
            if (idx % 2 === 0) doc.rect(L, y, W, rowH).fill('#f5f7fa');
            const dominant = det.parasitesDetected?.[0];
            const domConf = dominant
              ? (dominant.confidence <= 1 ? dominant.confidence * 100 : dominant.confidence).toFixed(0)
              : null;
            [
              (det.originalFilename || det.imageId || '').substring(0, 40),
              String(det.parasiteCount ?? 0),
              String(det.whiteBloodCellsDetected ?? 0),
              (det.parasiteWbcRatio ?? 0).toFixed(3),
              dominant ? `${this.getParasiteName(dominant.type)} (${domConf}%)` : '—'
            ].forEach((v, i) => {
              doc.fillColor('#222222').fontSize(7.5).font('Helvetica')
                 .text(v, L + cx[i] + 3, y + 3, { width: cw[i], lineBreak: false });
            });
            y += rowH;
          });
          doc.moveTo(L, y).lineTo(L + W, y).lineWidth(0.3).stroke('#dddddd');
          y += 6;
        }

        // ── CLINICAL REVIEW / SIGN-OFF ───────────────────────────────────
        y += 8;
        sectionHead('CLINICAL REVIEW & SIGN-OFF');

        if (reviewed) {
          const rev = diagnosisResult.manualReview;
          const confirmedStatus = rev.overriddenStatus || diagnosisResult.status;

          checkY(30);
          doc.rect(L, y, W, 22).fill('#d4edda');
          doc.rect(L, y, W, 22).stroke('#28a745');
          doc.fillColor('#155724').fontSize(10).font('Helvetica-Bold')
             .text(`CONFIRMED BY CLINICIAN  —  Final Result: ${confirmedStatus}`, L + 8, y + 6, { width: W - 16, lineBreak: false });
          y += 28;

          kv('Reviewed By',         rev.signedByName,                                                                  L, 140, W);
          kv('Reviewed At',         rev.reviewedAt ? new Date(rev.reviewedAt).toLocaleString() : null,                 L, 140, W);
          kv('Final Status',        confirmedStatus,                                                                    L, 140, W);
          kv('Severity',            (rev.overriddenSeverity || diagnosisResult.severity?.level || 'N/A').toUpperCase(), L, 140, W);
          kv('Reviewer Confidence', (rev.reviewerConfidence || 'N/A').toUpperCase(),                                   L, 140, W);

          // Reviewed counts (shown when clinician edited detections)
          if (rev.detectionsEdited) {
            y += 4;
            doc.fillColor('#1e3a5f').fontSize(9).font('Helvetica-Bold')
               .text('Clinician-Reviewed Counts', L, y);
            y += 13;
            kv('Parasites (reviewed)',  rev.parasiteCountReviewed ?? 'N/A',         L, 160, W);
            kv('WBCs (reviewed)',       rev.wbcCountReviewed ?? 'N/A',              L, 160, W);
            kv('P/WBC ratio (reviewed)', rev.parasiteWbcRatioReviewed != null
              ? rev.parasiteWbcRatioReviewed.toFixed(4) : 'N/A',                   L, 160, W);

            const densityLabel = rev.parasiteDensityIsPreliminaryReviewed
              ? `${(rev.parasiteDensityPerUlReviewed ?? 0).toLocaleString()} p/µL  [${rev.parasiteDensityFlagReviewed || 'preliminary'}]`
              : `${(rev.parasiteDensityPerUlReviewed ?? 0).toLocaleString()} p/µL`;
            kv('Parasitaemia (reviewed)', densityLabel, L, 160, W);

            if (rev.parasiteDensityNoteReviewed) {
              const noteH = doc.heightOfString(rev.parasiteDensityNoteReviewed, { width: W - 20, fontSize: 8 });
              checkY(noteH + 14);
              doc.rect(L, y, W, noteH + 10).fill('#fff8e1');
              doc.fillColor('#7d5a00').fontSize(8).font('Helvetica')
                 .text(rev.parasiteDensityNoteReviewed, L + 6, y + 5, { width: W - 12, lineBreak: true });
              y += noteH + 14;
            }
          }

          if (rev.reviewNotes) {
            const notesH = doc.heightOfString(rev.reviewNotes, { width: W - 20, fontSize: 9 });
            checkY(notesH + 24);
            y += 4;
            doc.fillColor('#555555').fontSize(8).font('Helvetica')
               .text('Clinical Notes:', L, y, { lineBreak: false });
            y += 13;
            doc.fillColor('#111111').fontSize(9).font('Helvetica')
               .text(rev.reviewNotes, L + 12, y, { width: W - 20, lineBreak: true });
            y += notesH + 6;
          }

          checkY(28);
          y += 4;
          doc.rect(L, y, W, 20).stroke('#aaaaaa');
          doc.fillColor('#555555').fontSize(7.5).font('Helvetica')
             .text(
               `Verification Code: ${rev.verificationCode || 'N/A'}   |   This code uniquely identifies this sign-off and can be used for audit purposes.`,
               L + 6, y + 6, { width: W - 12, lineBreak: false }
             );
          y += 24;

        } else {
          checkY(85);
          doc.fillColor('#888888').fontSize(9).font('Helvetica')
             .text(
               'This report has NOT yet been reviewed by a clinician. It must be signed off before clinical use.',
               L, y, { width: W, lineBreak: false }
             );
          y += 28;

          doc.moveTo(L, y).lineTo(L + 200, y).lineWidth(0.7).stroke('#333333');
          doc.moveTo(L + 240, y).lineTo(L + 440, y).stroke('#333333');
          y += 5;
          doc.fillColor('#333333').fontSize(8).font('Helvetica')
             .text('Clinician Signature', L, y, { lineBreak: false });
          doc.text('Date & Time', L + 240, y, { lineBreak: false });
          y += 22;
          doc.moveTo(L, y).lineTo(L + 300, y).lineWidth(0.7).stroke('#333333');
          y += 5;
          doc.fillColor('#333333').fontSize(8).font('Helvetica')
             .text('Print Name & Professional Designation', L, y, { lineBreak: false });
        }

        // ── FOOTER: stamp every buffered page (safe — bottom margin is 0) ─
        const totalPages = doc.bufferedPageRange().count;
        for (let i = 0; i < totalPages; i++) {
          doc.switchToPage(i);
          const fY = doc.page.height - 52;  // well within page.height (bottom margin = 0)
          doc.moveTo(L, fY).lineTo(L + W, fY).lineWidth(0.4).stroke('#cccccc');
          doc.fillColor('#999999').fontSize(7).font('Helvetica')
             .text(
               'AI-assisted decision support system — not a clinical diagnosis. Results must be interpreted by a qualified healthcare professional.',
               L, fY + 5, { width: W, align: 'center', lineBreak: false }
             );
          doc.text(
            `Report ID: ${test.testId}  |  ${reportDate}  |  Page ${i + 1} of ${totalPages}`,
            L, fY + 17, { width: W, align: 'center', lineBreak: false }
          );
        }

        doc.flushPages();
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
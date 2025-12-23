// 📁 server/src/services/reportService.js
const PDFDocument = require('pdfkit');
const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');

class ReportService {
  /**
   * Generates a PDF report for the given diagnosis result.
   * @param {object} diagnosisResult - The diagnosis result document.
   * @param {string} [outputPath] - Optional path for the PDF file.
   * @returns {Promise<string>} - Path to the generated PDF.
   */
  async generatePDFReport(diagnosisResult, outputPath) {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument();

      // Add page numbers on each new page
      doc.on('pageAdded', () => {
        doc.fontSize(8).text(`Page ${doc.page.number}`, 500, 750, { align: 'right' });
      });

      const fileName = `report-${diagnosisResult.testId}.pdf`;
      const reportDir = path.join(__dirname, '../../reports');
      if (!fs.existsSync(reportDir)) {
        fs.mkdirSync(reportDir);
      }
      const filePath = outputPath || path.join(reportDir, fileName);

      const writeStream = fs.createWriteStream(filePath);
      doc.pipe(writeStream);

      // Title
      doc.fontSize(18).text('Malaria Diagnosis Report', { align: 'center' }).moveDown();

      // Basic info
      doc.fontSize(12)
        .text(`Test ID: ${diagnosisResult.testId}`)
        .text(`Patient ID: ${diagnosisResult.patientId}`)
        .text(`Status: ${diagnosisResult.status}`)
        .text(`Diagnosed At: ${diagnosisResult.diagnosedAt ? new Date(diagnosisResult.diagnosedAt).toLocaleDateString() : 'N/A'}`)
        .moveDown();

      // Most probable parasite
      if (diagnosisResult.mostProbableParasite) {
        doc.text('Most Probable Parasite:', { underline: true })
          .text(`Type: ${diagnosisResult.mostProbableParasite.type || 'N/A'}`)
          .text(`Confidence: ${(diagnosisResult.mostProbableParasite.confidence * 100).toFixed(1)}%`)
          .moveDown();
      }

      // Parasite/WBC ratio
      doc.text(`Parasite-WBC Ratio: ${diagnosisResult.parasiteWbcRatio || 'N/A'}`).moveDown();

      // Detections
      if (diagnosisResult.detections && diagnosisResult.detections.length > 0) {
        doc.text('Detections:', { underline: true });
        diagnosisResult.detections.forEach((det, index) => {
          if (index > 0) doc.moveDown(0.5);
          doc.text(`Image: ${det.imageId}`)
            .text(`Parasite Count: ${det.parasiteCount}`)
            .text(`WBC Count: ${det.whiteBloodCellsDetected}`);
        });
      }

      doc.end();

      writeStream.on('finish', () => {
        console.log('PDF report generated:', filePath);
        resolve(filePath);
      });

      writeStream.on('error', (err) => {
        console.error('Error writing PDF:', err);
        reject(err);
      });
    });
  }

  /**
   * Generates a CSV report for the given diagnosis result.
   * @param {object} diagnosisResult - The diagnosis result document.
   * @returns {Promise<string>} - Path to the generated CSV file.
   */
  async generateCSVReport(diagnosisResult) {
    const fileName = `report-${diagnosisResult.testId}.csv`;
    const reportDir = path.join(__dirname, '../../reports');
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir);
    }
    const filePath = path.join(reportDir, fileName);

    const escapeCSVField = (value) => {
      if (value === null || value === undefined) return '';
      const stringValue = String(value);
      if (/[,"\n]/.test(stringValue)) {
        return `"${stringValue.replace(/"/g, '""')}"`;
      }
      return stringValue;
    };

    let csv = 'Category,Field,Value\n';

    // Basic info
    csv += `Basic Info,Test ID,${escapeCSVField(diagnosisResult.testId)}\n`;
    csv += `Basic Info,Patient ID,${escapeCSVField(diagnosisResult.patientId)}\n`;
    csv += `Basic Info,Status,${escapeCSVField(diagnosisResult.status)}\n`;
    csv += `Basic Info,Diagnosed At,${escapeCSVField(diagnosisResult.diagnosedAt ? new Date(diagnosisResult.diagnosedAt).toLocaleDateString() : 'N/A')}\n`;

    // Most probable parasite
    if (diagnosisResult.mostProbableParasite) {
      csv += `Most Probable Parasite,Type,${escapeCSVField(diagnosisResult.mostProbableParasite.type)}\n`;
      csv += `Most Probable Parasite,Confidence,${escapeCSVField((diagnosisResult.mostProbableParasite.confidence * 100).toFixed(1) + '%')}\n`;
    }

    // Parasite/WBC ratio
    csv += `Basic Info,Parasite-WBC Ratio,${escapeCSVField(diagnosisResult.parasiteWbcRatio)}\n`;

    // Detections
    if (diagnosisResult.detections && diagnosisResult.detections.length > 0) {
      csv += '\nDetections\n';
      csv += 'Image ID,Parasite Count,WBC Count\n';
      diagnosisResult.detections.forEach(det => {
        csv += `${escapeCSVField(det.imageId)},${escapeCSVField(det.parasiteCount)},${escapeCSVField(det.whiteBloodCellsDetected)}\n`;
      });
    }

    // Write to file
    return new Promise((resolve, reject) => {
      fs.writeFile(filePath, csv, 'utf-8', (err) => {
        if (err) {
          console.error('Error writing CSV:', err);
          reject(err);
        } else {
          console.log('CSV report generated:', filePath);
          resolve(filePath);
        }
      });
    });
  }

  /**
   * Backward-compatible method: Generate patient report PDF.
   * @param {object} patient
   * @param {array} testHistory
   * @param {array} diagnosisHistory
   * @param {object} options
   * @returns {Promise<Buffer>} - PDF buffer
   */
  async generatePatientReportPDF(patient, testHistory, diagnosisHistory, options = {}) {
    const diagnosisResult = {
      testId: `summary-${patient.patientId}`,
      patientId: patient.patientId,
      status: 'Summary',
      diagnosedAt: new Date(),
      mostProbableParasite: diagnosisHistory.find(d => d.status === 'POS')?.mostProbableParasite || null,
      parasiteWbcRatio: diagnosisHistory.find(d => d.parasiteWbcRatio)?.parasiteWbcRatio || null,
      detections: testHistory.map(test => ({
        imageId: test.testId,
        parasiteCount: test.parasiteCount || 'N/A',
        whiteBloodCellsDetected: test.whiteBloodCellsDetected || 'N/A'
      }))
    };

    // Generate PDF file
    const filePath = await this.generatePDFReport(diagnosisResult, null);

    // Return PDF buffer
    return fsp.readFile(filePath);
  }
}

module.exports = new ReportService();

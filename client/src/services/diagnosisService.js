// src/services/diagnosisService.js
import apiService from './api';

const diagnosisService = {
  // ✅ CORE: Basic diagnosis operations (100% backend aligned)
  getAll: (params = {}) => apiService.diagnosis.getAll(params),
  getByTestId: (testId) => apiService.diagnosis.getByTestId(testId),
  runDiagnosis: (testId) => apiService.diagnosis.runDiagnosis(testId),
  addManualReview: (testId, reviewData) => apiService.diagnosis.addManualReview(testId, reviewData),
  getImages: (testId, imageId = null) => apiService.diagnosis.getImages(testId, imageId),
  getStatistics: (params = {}) => apiService.diagnosis.getStatistics(params),
  getRequiringReview: (params = {}) => apiService.diagnosis.getRequiringReview(params),
  getPositiveCases: (params = {}) => apiService.diagnosis.getPositiveCases(params),
  exportReport: (testId, format = 'pdf') => apiService.diagnosis.exportReport(testId, format),
  sendToHospitalEMR: (testId, data = {}) => apiService.diagnosis.sendToHospitalEMR(testId, data),
  batchExport: (testIds, format = 'pdf', includeImages = false) => apiService.diagnosis.batchExport(testIds, format, includeImages),
  addQualityFeedback: (testId, feedback) => apiService.diagnosis.addQualityFeedback(testId, feedback),

  // ✅ BASIC: Image detection details (no enhanced features)
  getImageDetectionDetails: (resultId, imageId) => apiService.diagnosis.getImageDetectionDetails(resultId, imageId),

  // ✅ BASIC: Performance analytics (no enhanced features)
  getPerformanceAnalytics: (params = {}) => apiService.diagnosis.getPerformanceAnalytics(params)
};

export default diagnosisService;

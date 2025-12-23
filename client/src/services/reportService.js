// src/services/reportService.js
import apiService from './api';

const reportService = {
  generateTestReport: (testId, format = 'pdf', includeImages = false) =>
    apiService.reports.generateTestReport(testId, format, includeImages),
  generateBulkReports: (params) => apiService.reports.generateBulkReports(params),
  exportCSV: (params = {}) => apiService.reports.exportCSV(params),
  getAvailable: (params = {}) => apiService.reports.getAvailable(params),
  getStatistics: (period = 'month') => apiService.reports.getStatistics(period),
  scheduleReport: (scheduleData) => apiService.reports.scheduleReport(scheduleData),
};

export default reportService;

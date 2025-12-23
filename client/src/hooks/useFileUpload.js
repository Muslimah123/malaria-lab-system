// 📁 client/src/hooks/useFileUpload.js
// Enhanced File Upload Hook with Advanced Features

import { useState, useCallback } from 'react';
import apiService from '../services/api';

export function useFileUpload({ sessionId = null, onProgress = null } = {}) {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [processingMode, setProcessingMode] = useState('enhanced'); // 'enhanced' | 'fast'

  // Upload files to a session
  const uploadFiles = useCallback(async (files) => {
    setUploading(true);
    setError(null);
    setProgress(0);
    setResult(null);
    try {
      const response = await apiService.upload.uploadFiles(
        sessionId,
        files,
        (percent) => {
          setProgress(percent);
          if (onProgress) onProgress(percent);
        }
      );
      setResult(response);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Upload failed');
      return null;
    } finally {
      setUploading(false);
    }
  }, [sessionId, onProgress]);

  // ✅ ENHANCED: Process files with enhanced options
  const processFilesWithOptions = useCallback(async (options = {}) => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    setProcessing(true);
    setError(null);
    setProcessingMode(options.fastMode ? 'fast' : 'enhanced');
    
    try {
      const response = await apiService.upload.processFilesWithOptions(sessionId, options);
      setResult(response);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Processing failed');
      return null;
    } finally {
      setProcessing(false);
    }
  }, [sessionId]);

  // ✅ ENHANCED: Process files with automatic mode selection
  const processFiles = useCallback(async (priority = 'normal') => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    // ✅ Automatic mode selection based on priority
    const options = {
      fastMode: priority === 'high' || priority === 'urgent',
      urgentCase: priority === 'urgent',
      includeMasks: priority !== 'urgent', // Disable masks for urgent cases
      includePerformance: priority !== 'urgent', // Disable performance tracking for urgent cases
      confidenceThreshold: priority === 'urgent' ? 0.3 : 0.26
    };

    return processFilesWithOptions(options);
  }, [sessionId, processFilesWithOptions]);

  // ✅ ENHANCED: Get upload statistics with processing mode analytics
  const getEnhancedStatistics = useCallback(async (params = {}) => {
    try {
      const response = await apiService.upload.getEnhancedStatistics(params);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch statistics');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Get session analytics and insights
  const getSessionAnalytics = useCallback(async (params = {}) => {
    try {
      const response = await apiService.upload.getSessionAnalytics(params);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch analytics');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Check for existing results and attempt recovery
  const checkForExistingResults = useCallback(async () => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    try {
      const response = await apiService.upload.checkForExistingResults(sessionId);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to check results');
      return null;
    }
  }, [sessionId]);

  // ✅ ENHANCED: Get upload recommendations and optimization
  const getUploadRecommendations = useCallback(async (params = {}) => {
    try {
      const response = await apiService.upload.getUploadRecommendations(params);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch recommendations');
      return null;
    }
  }, []);

  // Validate files before upload
  const validateFiles = useCallback(async (files) => {
    setError(null);
    try {
      const response = await apiService.upload.validateFiles(files);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Validation failed');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Create upload session with enhanced metadata
  const createSession = useCallback(async (sessionData = {}) => {
    setError(null);
    try {
      const response = await apiService.upload.createSession(sessionData);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Session creation failed');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Get upload session with enhanced details
  const getSession = useCallback(async (sessionId) => {
    setError(null);
    try {
      const response = await apiService.upload.getSession(sessionId);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch session');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Cancel session with reason tracking
  const cancelSession = useCallback(async (reason = 'User cancelled') => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    try {
      const response = await apiService.upload.cancelSession(sessionId, reason);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to cancel session');
      return null;
    }
  }, [sessionId]);

  // ✅ ENHANCED: Retry upload with specific retry type
  const retryUpload = useCallback(async (retryType = 'processing', filenames = []) => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    try {
      const response = await apiService.upload.retryUpload(sessionId, retryType, filenames);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Retry failed');
      return null;
    }
  }, [sessionId]);

  // ✅ ENHANCED: Get my upload sessions with filtering
  const getMySessions = useCallback(async (params = {}) => {
    try {
      const response = await apiService.upload.getMySessions(params);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch sessions');
      return null;
    }
  }, []);

  // ✅ ENHANCED: Delete specific file from session
  const deleteFile = useCallback(async (filename) => {
    if (!sessionId) {
      setError('No session ID provided');
      return null;
    }

    try {
      const response = await apiService.upload.deleteFile(sessionId, filename);
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to delete file');
      return null;
    }
  }, [sessionId]);

  // ✅ ENHANCED: Cleanup old sessions
  const cleanupSessions = useCallback(async () => {
    try {
      const response = await apiService.upload.cleanupSessions();
      return response;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Cleanup failed');
      return null;
    }
  }, []);

  return {
    // State
    uploading,
    progress,
    error,
    result,
    processing,
    processingMode,
    
    // Core Actions
    uploadFiles,
    validateFiles,
    
    // ✅ ENHANCED: Processing Actions
    processFiles,
    processFilesWithOptions,
    
    // ✅ ENHANCED: Session Management
    createSession,
    getSession,
    cancelSession,
    retryUpload,
    getMySessions,
    deleteFile,
    cleanupSessions,
    
    // ✅ ENHANCED: Analytics & Insights
    getEnhancedStatistics,
    getSessionAnalytics,
    getUploadRecommendations,
    checkForExistingResults,
    
    // Utility
    setError: (error) => setError(error),
    clearError: () => setError(null),
    clearResult: () => setResult(null)
  };
};

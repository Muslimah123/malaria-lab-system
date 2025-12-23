// 📁 client/src/hooks/useDiagnosis.js
// Basic Diagnosis Hook

import { useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  fetchDiagnosisResult,
  runDiagnosis,
  getAllDiagnosisResults,
  getDiagnosisStatistics,
  addManualReview,
  clearError,
  clearCurrentResult
} from '../store/slices/diagnosisSlice';

export const useDiagnosis = () => {
  const dispatch = useDispatch();
  const {
    currentResult,
    isLoading,
    error,
    allResults,
    statistics
  } = useSelector((state) => state.diagnosis);

  // Core diagnosis operations
  const fetchResult = useCallback((testId) => {
    return dispatch(fetchDiagnosisResult(testId));
  }, [dispatch]);

  // Basic diagnosis without enhanced options
  const runDiagnosisAnalysis = useCallback((testId) => {
    return dispatch(runDiagnosis(testId));
  }, [dispatch]);

  // Get all diagnosis results with basic filtering
  const fetchAllResults = useCallback((params = {}) => {
    return dispatch(getAllDiagnosisResults(params));
  }, [dispatch]);

  // Get basic diagnosis statistics
  const fetchStatistics = useCallback((params = {}) => {
    return dispatch(getDiagnosisStatistics(params));
  }, [dispatch]);

  const addReview = useCallback((testId, reviewData) => {
    return dispatch(addManualReview({ testId, reviewData }));
  }, [dispatch]);

  // Utility functions
  const clearDiagnosisError = useCallback(() => {
    dispatch(clearError());
  }, [dispatch]);

  const clearResult = useCallback(() => {
    dispatch(clearCurrentResult());
  }, [dispatch]);

  return {
    // State
    currentResult,
    isLoading,
    error,
    allResults,
    statistics,
    
    // Actions
    fetchResult,
    runDiagnosisAnalysis,
    fetchAllResults,
    fetchStatistics,
    addReview,
    clearDiagnosisError,
    clearResult
  };
};

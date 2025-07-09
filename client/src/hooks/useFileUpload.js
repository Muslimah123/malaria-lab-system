// 📁 client/src/hooks/useFileUpload.js
// High-level file upload hook for your architecture
import { useState, useCallback } from 'react';
import apiService from '../services/api';

export function useFileUpload({ sessionId = null, onProgress = null } = {}) {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

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

  return {
    uploading,
    progress,
    error,
    result,
    uploadFiles,
    validateFiles
  };
}

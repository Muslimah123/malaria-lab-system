// 📁 client/src/hooks/useApi.js
// High-level API data fetching hook for your architecture
import { useState, useCallback } from 'react';
import apiService from '../services/api';

/**
 * useApi - generic hook for API calls with loading, error, and data state
 * @param {Function} apiFn - async function from apiService (e.g., apiService.patients.getAll)
 * @param {Array} params - parameters to pass to apiFn
 * @param {Object} options - { immediate: boolean }
 */
export function useApi(apiFn, params = [], options = { immediate: true }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(options.immediate);
  const [error, setError] = useState(null);

  const execute = useCallback(async (...callParams) => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiFn(...(callParams.length ? callParams : params));
      setData(response.data?.data || response.data);
      return response.data?.data || response.data;
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'API error');
      return null;
    } finally {
      setLoading(false);
    }
  }, [apiFn, params]);

  // Optionally fetch immediately
  if (options.immediate && data === null && !loading && !error) {
    execute();
  }

  return { data, loading, error, execute };
}

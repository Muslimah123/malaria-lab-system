// 📁 client/src/hooks/useAuthToken.js
// Custom hook to ensure auth token is properly set in API headers with automatic refresh

import { useEffect, useRef, useCallback } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { selectToken, selectIsAuthenticated, logout } from '../store/slices/authSlice';
import api from '../services/api';
import authService from '../services/authService';

export const useAuthToken = () => {
  const dispatch = useDispatch();
  const token = useSelector(selectToken);
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const tokenSetRef = useRef(false);
  const refreshTimerRef = useRef(null);
  const lastRefreshRef = useRef(0);

  // ✅ NEW: Check if token is expired or about to expire
  const isTokenExpiringSoon = useCallback((token) => {
    if (!token) return true;
    
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const now = Date.now() / 1000;
      const timeUntilExpiry = payload.exp - now;
      
      // Return true if token expires in less than 5 minutes
      return timeUntilExpiry < 300;
    } catch (error) {
      console.error('Error parsing token:', error);
      return true;
    }
  }, []);

  // ✅ NEW: Refresh token automatically
  const refreshToken = useCallback(async () => {
    try {
      const now = Date.now();
      // Prevent multiple refresh attempts within 30 seconds
      if (now - lastRefreshRef.current < 30000) {
        console.log('Token refresh skipped - too recent');
        return false;
      }

      console.log('🔄 Attempting automatic token refresh...');
      lastRefreshRef.current = now;
      
      const response = await authService.refreshToken();
      if (response.success) {
        console.log('✅ Token refreshed successfully');
        return true;
      }
      return false;
    } catch (error) {
      console.error('❌ Token refresh failed:', error);
      // Logout user if refresh fails
      dispatch(logout());
      return false;
    }
  }, [dispatch]);

  // ✅ NEW: Monitor token expiration and refresh automatically
  useEffect(() => {
    if (!isAuthenticated || !token) return;

    const checkTokenExpiry = () => {
      if (isTokenExpiringSoon(token)) {
        console.log('🔄 Token expiring soon, refreshing...');
        refreshToken();
      }
    };

    // Check token expiry every 2 minutes
    refreshTimerRef.current = setInterval(checkTokenExpiry, 120000);
    
    // Initial check
    checkTokenExpiry();

    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, [isAuthenticated, token, isTokenExpiringSoon, refreshToken]);

  // ✅ ENHANCED: Set token in API headers with validation
  useEffect(() => {
    if (isAuthenticated && token && !tokenSetRef.current) {
      // Validate token before setting
      if (isTokenExpiringSoon(token)) {
        console.log('🔄 Token is expired or expiring soon, refreshing before setting...');
        refreshToken().then((success) => {
          if (success) {
            // Token was refreshed, it will be set in the next effect cycle
            return;
          }
        });
        return;
      }

      // Set token in API headers
      if (api && api.defaults && api.defaults.headers) {
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        tokenSetRef.current = true;
        console.log('✅ Auth token set in API headers');
      }
    } else if (!isAuthenticated || !token) {
      // Clear token from API headers
      if (api && api.defaults && api.defaults.headers) {
        delete api.defaults.headers.common['Authorization'];
        tokenSetRef.current = false;
        console.log('🗑️ Auth token cleared from API headers');
      }
    }
  }, [isAuthenticated, token, isTokenExpiringSoon, refreshToken]);

  // ✅ NEW: Cleanup on unmount
  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, []);

  // ✅ NEW: Expose refresh function for manual use
  const manualRefresh = useCallback(async () => {
    return await refreshToken();
  }, [refreshToken]);

  // ✅ NEW: Check if token needs refresh
  const needsRefresh = useCallback(() => {
    return isTokenExpiringSoon(token);
  }, [token, isTokenExpiringSoon]);

  return { 
    token, 
    isAuthenticated, 
    tokenSetRef: tokenSetRef.current,
    refreshToken: manualRefresh,
    needsRefresh: needsRefresh()
  };
};

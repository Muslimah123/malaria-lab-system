// 📁 client/src/hooks/useSocket.js
// High-level real-time socket hook for your architecture
import { useEffect, useRef } from 'react';
import socketService from '../services/socketService';

/**
 * useSocket - subscribe to a socket event and handle cleanup
 * @param {string} event - event name to listen for
 * @param {Function} handler - callback to handle event data
 * @param {Array} deps - dependencies for the effect
 */
export function useSocket(event, handler, deps = []) {
  const savedHandler = useRef();
  savedHandler.current = handler;

  useEffect(() => {
    function eventListener(data) {
      if (savedHandler.current) {
        savedHandler.current(data);
      }
    }
    socketService.on(event, eventListener);
    return () => {
      socketService.off(event, eventListener);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [event, ...deps]);
}

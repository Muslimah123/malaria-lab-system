// 📁 client/src/components/debug/SocketDebugger.jsx
// Enhanced socket debugger component for monitoring connection health and debugging issues

import React, { useState, useEffect } from 'react';
import { useSocketConnection, useProcessingSession } from '../../hooks/useSocket';
import { useAuthToken } from '../../hooks/useAuthToken';
import socketService from '../../services/socketService';

const SocketDebugger = ({ sessionId }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [logs, setLogs] = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(2000);
  
  const { connected, connecting, error, connect, disconnect } = useSocketConnection();
  const { token, needsRefresh, refreshToken } = useAuthToken();
  const sessionStatus = useProcessingSession(sessionId);

  // Add log entry
  const addLog = (message, type = 'info') => {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, message, type };
    setLogs(prev => [...prev, logEntry]);
  };

  // Clear logs
  const clearLogs = () => setLogs([]);

  // Test connection
  const testConnection = async () => {
    try {
      addLog('Testing socket connection...', 'info');
      const isHealthy = await socketService.testConnection();
      addLog(`Connection test result: ${isHealthy ? 'Healthy' : 'Unhealthy'}`, isHealthy ? 'success' : 'error');
    } catch (error) {
      addLog(`Connection test failed: ${error.message}`, 'error');
    }
  };

  // Get connection statistics
  const getConnectionStats = () => {
    return socketService.getConnectionStats();
  };

  // Manual token refresh
  const handleTokenRefresh = async () => {
    try {
      addLog('Manually refreshing token...', 'info');
      const success = await refreshToken();
      addLog(`Token refresh: ${success ? 'Success' : 'Failed'}`, success ? 'success' : 'error');
    } catch (error) {
      addLog(`Token refresh error: ${error.message}`, 'error');
    }
  };

  // Manual socket connection
  const handleConnect = async () => {
    try {
      addLog('Manually connecting socket...', 'info');
      await connect();
      addLog('Manual connection successful', 'success');
    } catch (error) {
      addLog(`Manual connection failed: ${error.message}`, 'error');
    }
  };

  // Manual socket disconnection
  const handleDisconnect = () => {
    addLog('Manually disconnecting socket...', 'info');
    disconnect();
    addLog('Socket disconnected', 'info');
  };

  // Auto-refresh connection status
  useEffect(() => {
    if (!isOpen) return;

    const interval = setInterval(() => {
      const stats = getConnectionStats();
      addLog(`Connection stats: ${JSON.stringify(stats)}`, 'debug');
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [isOpen, refreshInterval]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && logs.length > 0) {
      const logContainer = document.getElementById('socket-logs');
      if (logContainer) {
        logContainer.scrollTop = logContainer.scrollHeight;
      }
    }
  }, [logs, autoScroll]);

  // Log connection status changes
  useEffect(() => {
    if (connected) {
      addLog('Socket connected', 'success');
    } else if (connecting) {
      addLog('Socket connecting...', 'info');
    } else {
      addLog('Socket disconnected', 'warning');
    }
  }, [connected, connecting]);

  // Log token status changes
  useEffect(() => {
    if (needsRefresh) {
      addLog('Token needs refresh', 'warning');
    }
  }, [needsRefresh]);

  // Log session status changes
  useEffect(() => {
    if (sessionStatus.status !== 'idle') {
      addLog(`Session status: ${sessionStatus.status}`, 'info');
      if (sessionStatus.viaFallback) {
        addLog('Completion detected via fallback mechanism', 'warning');
      }
    }
  }, [sessionStatus.status, sessionStatus.viaFallback]);

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 bg-blue-600 text-white p-2 rounded-full shadow-lg hover:bg-blue-700 z-50"
        title="Open Socket Debugger"
      >
        🔌
      </button>
    );
  }

  return (
    <div className="fixed bottom-4 right-4 w-96 h-96 bg-white border border-gray-300 rounded-lg shadow-xl z-50">
      {/* Header */}
      <div className="flex items-center justify-between p-3 bg-gray-100 border-b border-gray-300 rounded-t-lg">
        <h3 className="font-semibold text-gray-800">Socket Debugger</h3>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsOpen(false)}
            className="text-gray-500 hover:text-gray-700"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Connection Status */}
      <div className="p-3 border-b border-gray-300">
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : connecting ? 'bg-yellow-500' : 'bg-red-500'}`}></div>
            <span className="font-medium">
              {connected ? 'Connected' : connecting ? 'Connecting' : 'Disconnected'}
            </span>
          </div>
          <div className="text-right">
            <span className={`px-2 py-1 rounded text-xs ${needsRefresh ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
              Token: {needsRefresh ? 'Expiring' : 'Valid'}
            </span>
          </div>
        </div>

        {/* Session Status */}
        {sessionId && (
          <div className="mt-2 p-2 bg-gray-50 rounded text-xs">
            <div className="font-medium">Session: {sessionId}</div>
            <div className="text-gray-600">
              Status: {sessionStatus.status} | Progress: {sessionStatus.progress}%
              {sessionStatus.viaFallback && ' (via fallback)'}
            </div>
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="p-3 border-b border-gray-300">
        <div className="flex flex-wrap gap-2">
          <button
            onClick={handleConnect}
            disabled={connected || connecting}
            className="px-3 py-1 bg-green-600 text-white text-xs rounded hover:bg-green-700 disabled:opacity-50"
          >
            Connect
          </button>
          <button
            onClick={handleDisconnect}
            disabled={!connected}
            className="px-3 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700 disabled:opacity-50"
          >
            Disconnect
          </button>
          <button
            onClick={testConnection}
            className="px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700"
          >
            Test
          </button>
          <button
            onClick={handleTokenRefresh}
            disabled={!needsRefresh}
            className="px-3 py-1 bg-yellow-600 text-white text-xs rounded hover:bg-yellow-700 disabled:opacity-50"
          >
            Refresh Token
          </button>
          <button
            onClick={clearLogs}
            className="px-3 py-1 bg-gray-600 text-white text-xs rounded hover:bg-gray-700"
          >
            Clear Logs
          </button>
        </div>

        {/* Settings */}
        <div className="mt-2 flex items-center space-x-2 text-xs">
          <label className="flex items-center space-x-1">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="w-3 h-3"
            />
            <span>Auto-scroll</span>
          </label>
          <label className="flex items-center space-x-1">
            <span>Refresh:</span>
            <select
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(Number(e.target.value))}
              className="text-xs border rounded px-1"
            >
              <option value={1000}>1s</option>
              <option value={2000}>2s</option>
              <option value={5000}>5s</option>
            </select>
          </label>
        </div>
      </div>

      {/* Logs */}
      <div className="flex-1 overflow-hidden">
        <div
          id="socket-logs"
          className="h-full overflow-y-auto p-3 bg-gray-50 text-xs font-mono"
        >
          {logs.map((log, index) => (
            <div key={index} className={`mb-1 ${getLogColor(log.type)}`}>
              <span className="text-gray-500">[{log.timestamp.split('T')[1].split('.')[0]}]</span>
              <span className="ml-2">{log.message}</span>
            </div>
          ))}
          {logs.length === 0 && (
            <div className="text-gray-400 text-center mt-4">No logs yet</div>
          )}
        </div>
      </div>
    </div>
  );
};

// Helper function to get log colors
const getLogColor = (type) => {
  switch (type) {
    case 'success':
      return 'text-green-700';
    case 'error':
      return 'text-red-700';
    case 'warning':
      return 'text-yellow-700';
    case 'debug':
      return 'text-gray-600';
    default:
      return 'text-gray-800';
  }
};

export default SocketDebugger;
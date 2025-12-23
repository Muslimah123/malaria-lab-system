// 📁 client/src/components/common/ConnectionStatus.jsx
// Component to display socket connection health and token status

import React from 'react';
import { useSocketConnection } from '../../hooks/useSocket';
import { useAuthToken } from '../../hooks/useAuthToken';
import { Wifi, WifiOff, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

const ConnectionStatus = ({ showDetails = false }) => {
  const { connected, connecting, error } = useSocketConnection();
  const { needsRefresh } = useAuthToken();

  const getStatusIcon = () => {
    if (connecting) {
      return <Clock className="w-4 h-4 text-yellow-500 animate-pulse" />;
    }
    if (connected) {
      if (needsRefresh) {
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      }
      return <CheckCircle className="w-4 h-4 text-green-500" />;
    }
    return <WifiOff className="w-4 h-4 text-red-500" />;
  };

  const getStatusText = () => {
    if (connecting) return 'Connecting...';
    if (connected) {
      if (needsRefresh) return 'Connected (Token Expiring)';
      return 'Connected';
    }
    if (error) return 'Connection Error';
    return 'Disconnected';
  };

  const getStatusColor = () => {
    if (connecting) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
    if (connected) {
      if (needsRefresh) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      return 'text-green-600 bg-green-50 border-green-200';
    }
    if (error) return 'text-red-600 bg-red-50 border-red-200';
    return 'text-gray-600 bg-gray-50 border-gray-200';
  };

  const getConnectionQuality = () => {
    if (!connected) return null;
    
    // Simple connection quality indicator based on recent activity
    // In a real implementation, you might want to track ping times, packet loss, etc.
    return (
      <div className="flex items-center space-x-1">
        <div className="flex space-x-1">
          {[1, 2, 3].map((bar) => (
            <div
              key={bar}
              className={`w-1 h-${bar} bg-current rounded-full ${
                connected ? 'opacity-100' : 'opacity-30'
              }`}
            />
          ))}
        </div>
      </div>
    );
  };

  if (!showDetails) {
    return (
      <div className="flex items-center space-x-2">
        {getStatusIcon()}
        <span className={`text-sm font-medium ${getStatusColor()}`}>
          {getStatusText()}
        </span>
      </div>
    );
  }

  return (
    <div className="bg-white border rounded-lg p-4 shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-900">Connection Status</h3>
        <div className="flex items-center space-x-2">
          {getStatusIcon()}
          <span className={`text-sm font-medium ${getStatusColor()}`}>
            {getStatusText()}
          </span>
        </div>
      </div>

      {/* Connection Details */}
      <div className="space-y-3">
        {/* Socket Status */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Socket Connection</span>
          <div className="flex items-center space-x-2">
            {connected ? (
              <Wifi className="w-4 h-4 text-green-500" />
            ) : (
              <WifiOff className="w-4 h-4 text-red-500" />
            )}
            <span className={`text-sm ${connected ? 'text-green-600' : 'text-red-600'}`}>
              {connected ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>

        {/* Token Status */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Authentication Token</span>
          <div className="flex items-center space-x-2">
            {needsRefresh ? (
              <AlertTriangle className="w-4 h-4 text-yellow-500" />
            ) : (
              <CheckCircle className="w-4 h-4 text-green-500" />
            )}
            <span className={`text-sm ${needsRefresh ? 'text-yellow-600' : 'text-green-600'}`}>
              {needsRefresh ? 'Expiring Soon' : 'Valid'}
            </span>
          </div>
        </div>

        {/* Connection Quality */}
        {connected && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600">Connection Quality</span>
            {getConnectionQuality()}
          </div>
        )}

        {/* Error Details */}
        {error && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-red-500" />
              <span className="text-sm font-medium text-red-800">Connection Error</span>
            </div>
            <p className="text-sm text-red-700 mt-1">{error}</p>
          </div>
        )}

        {/* Recommendations */}
        {needsRefresh && (
          <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-yellow-500" />
              <span className="text-sm font-medium text-yellow-800">Action Required</span>
            </div>
            <p className="text-sm text-yellow-700 mt-1">
              Your session token is expiring soon. The system will automatically refresh it, but you may need to log in again if the refresh fails.
            </p>
          </div>
        )}

        {!connected && !connecting && (
          <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-md">
            <div className="flex items-center space-x-2">
              <WifiOff className="w-4 h-4 text-blue-500" />
              <span className="text-sm font-medium text-blue-800">Connection Lost</span>
            </div>
            <p className="text-sm text-blue-700 mt-1">
              The system is attempting to reconnect automatically. Real-time updates may be delayed until the connection is restored.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ConnectionStatus;

// src/components/dashboard/CriticalAlerts.jsx
import React from 'react';
import { 
  AlertTriangle, 
  AlertCircle, 
  XCircle,
  CheckCircle2,
  Clock,
  Shield,
  Wifi,
  WifiOff,
  Database,
  Activity,
  X
} from 'lucide-react';

const CriticalAlerts = ({ 
  alerts = [], 
  systemStatus = {},
  loading = false,
  onAlertDismiss,
  className = ""
}) => {
  if (loading) {
    return <CriticalAlertsSkeleton className={className} />;
  }

  const urgentAlerts = alerts.filter(alert => alert.severity === 'urgent' || alert.severity === 'critical');
  const hasUrgentAlerts = urgentAlerts.length > 0;

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Urgent Alerts */}
      {hasUrgentAlerts && (
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex items-center space-x-2 mb-4">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <h3 className="text-lg font-semibold text-white">Urgent Alerts</h3>
            <span className="bg-red-500 text-white text-xs px-2 py-1 rounded-full">
              {urgentAlerts.length}
            </span>
          </div>
          <div className="space-y-3">
            {urgentAlerts.map((alert) => (
              <AlertItem 
                key={alert.id} 
                alert={alert} 
                onDismiss={onAlertDismiss}
                urgent={true}
              />
            ))}
          </div>
        </div>
      )}

      {/* System Status */}
      <SystemStatusCard systemStatus={systemStatus} />
    </div>
  );
};

// Individual alert item
const AlertItem = ({ alert, onDismiss, urgent = false }) => {
  const getSeverityConfig = (severity) => {
    const configs = {
      critical: {
        icon: XCircle,
        bgColor: 'bg-red-500/10',
        borderColor: 'border-red-500/20',
        iconColor: 'text-red-400',
        textColor: 'text-red-200'
      },
      urgent: {
        icon: AlertTriangle,
        bgColor: 'bg-red-500/10',
        borderColor: 'border-red-500/20',
        iconColor: 'text-red-400',
        textColor: 'text-red-200'
      },
      warning: {
        icon: AlertCircle,
        bgColor: 'bg-yellow-500/10',
        borderColor: 'border-yellow-500/20',
        iconColor: 'text-yellow-400',
        textColor: 'text-yellow-200'
      },
      info: {
        icon: AlertCircle,
        bgColor: 'bg-blue-500/10',
        borderColor: 'border-blue-500/20',
        iconColor: 'text-blue-400',
        textColor: 'text-blue-200'
      }
    };

    return configs[severity] || configs.info;
  };

  const config = getSeverityConfig(alert.severity);
  const AlertIcon = config.icon;

  return (
    <div className={`p-4 rounded-lg border ${config.bgColor} ${config.borderColor}`}>
      <div className="flex items-start space-x-3">
        <AlertIcon className={`h-5 w-5 flex-shrink-0 mt-0.5 ${config.iconColor}`} />
        <div className="flex-1 min-w-0">
          {alert.title && (
            <p className="text-white font-medium text-sm mb-1">{alert.title}</p>
          )}
          {alert.patientName && (
            <p className="text-white font-medium text-sm">{alert.patientName}</p>
          )}
          <p className={`text-sm ${config.textColor}`}>{alert.message}</p>
          <div className="flex items-center justify-between mt-2">
            <p className={`text-xs ${config.textColor}`}>{alert.timeAgo || alert.timestamp}</p>
            {alert.actionUrl && (
              <button 
                onClick={() => window.location.href = alert.actionUrl}
                className="text-white text-xs underline hover:no-underline"
              >
                View Details
              </button>
            )}
          </div>
        </div>
        {onDismiss && (
          <button
            onClick={() => onDismiss(alert.id)}
            className={`flex-shrink-0 p-1 rounded hover:bg-white/10 ${config.iconColor}`}
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
};

// System status card
const SystemStatusCard = ({ systemStatus = {} }) => {
  const statusItems = [
    {
      name: 'API Server',
      status: systemStatus.api !== false,
      key: 'api'
    },
    {
      name: 'Diagnosis Engine',
      status: systemStatus.diagnosis !== false,
      key: 'diagnosis'
    },
    {
      name: 'Database',
      status: systemStatus.database !== false,
      key: 'database'
    },
    {
      name: 'Real-time Updates',
      status: systemStatus.realtime !== false,
      key: 'realtime'
    }
  ];

  const allSystemsOperational = statusItems.every(item => item.status);

  return (
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
      <div className="flex items-center space-x-2 mb-4">
        {allSystemsOperational ? (
          <CheckCircle2 className="h-5 w-5 text-green-400" />
        ) : (
          <AlertTriangle className="h-5 w-5 text-yellow-400" />
        )}
        <h3 className="text-lg font-semibold text-white">System Status</h3>
      </div>

      <div className="space-y-3">
        {statusItems.map((item) => (
          <SystemStatusItem 
            key={item.key} 
            name={item.name} 
            status={item.status} 
            type={item.key}
          />
        ))}
      </div>

      {!allSystemsOperational && (
        <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <p className="text-yellow-200 text-sm">
            Some services are experiencing issues. Contact IT support if problems persist.
          </p>
        </div>
      )}
    </div>
  );
};

// Individual system status item
const SystemStatusItem = ({ name, status, type }) => {
  const getStatusIcon = () => {
    if (type === 'realtime') {
      return status ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />;
    } else if (type === 'database') {
      return <Database className="w-4 h-4" />;
    } else {
      return <Activity className="w-4 h-4" />;
    }
  };

  const getStatusText = () => {
    if (type === 'api') return status ? 'Online' : 'Offline';
    if (type === 'diagnosis') return status ? 'Running' : 'Stopped';
    if (type === 'database') return status ? 'Connected' : 'Disconnected';
    if (type === 'realtime') return status ? 'Connected' : 'Disconnected';
    return status ? 'Operational' : 'Error';
  };

  return (
    <div className="flex items-center justify-between">
      <span className="text-blue-200 text-sm">{name}</span>
      <div className="flex items-center space-x-2">
        <div className={`w-2 h-2 rounded-full ${status ? 'bg-green-400' : 'bg-red-400'}`}></div>
        <div className={`${status ? 'text-green-400' : 'text-red-400'}`}>
          {getStatusIcon()}
        </div>
        <span className={`text-sm ${status ? 'text-green-400' : 'text-red-400'}`}>
          {getStatusText()}
        </span>
      </div>
    </div>
  );
};

// Loading skeleton
export const CriticalAlertsSkeleton = ({ className = "" }) => (
  <div className={`space-y-6 ${className}`}>
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
      <div className="h-6 bg-white/20 rounded w-32 mb-4"></div>
      <div className="space-y-3">
        {Array.from({ length: 2 }).map((_, index) => (
          <div key={index} className="p-4 bg-white/5 rounded-lg">
            <div className="flex items-start space-x-3">
              <div className="w-5 h-5 bg-white/20 rounded mt-0.5"></div>
              <div className="flex-1">
                <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-white/20 rounded w-full mb-2"></div>
                <div className="h-3 bg-white/20 rounded w-1/4"></div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>

    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
      <div className="h-6 bg-white/20 rounded w-32 mb-4"></div>
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="flex items-center justify-between">
            <div className="h-4 bg-white/20 rounded w-24"></div>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-white/20 rounded-full"></div>
              <div className="h-4 bg-white/20 rounded w-16"></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

// Custom hook for alerts management
export const useAlerts = () => {
  const [alerts, setAlerts] = React.useState([]);

  const addAlert = React.useCallback((alert) => {
    const newAlert = {
      id: Date.now() + Math.random(),
      timestamp: new Date().toISOString(),
      timeAgo: 'Just now',
      ...alert
    };
    setAlerts(prev => [newAlert, ...prev]);
  }, []);

  const dismissAlert = React.useCallback((alertId) => {
    setAlerts(prev => prev.filter(alert => alert.id !== alertId));
  }, []);

  const clearAlerts = React.useCallback(() => {
    setAlerts([]);
  }, []);

  return {
    alerts,
    addAlert,
    dismissAlert,
    clearAlerts
  };
};

export default CriticalAlerts;
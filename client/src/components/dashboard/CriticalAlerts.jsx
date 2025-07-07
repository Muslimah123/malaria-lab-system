import React, { useState } from 'react';
import { AlertTriangle, X, Clock, Eye, ChevronRight } from 'lucide-react';

const CriticalAlerts = ({ alerts = [], onAlertClick }) => {
  const [dismissedAlerts, setDismissedAlerts] = useState(new Set());

  // Sample alerts if none provided
  const sampleAlerts = [
    {
      id: 1,
      type: 'positive_result',
      message: 'Severe P. falciparum detected in test #MT-2024-001',
      testId: 'MT-2024-001',
      patientId: 'P12345',
      timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      priority: 'critical',
      severity: 'severe'
    },
    {
      id: 2,
      type: 'processing_delay',
      message: 'Test processing delayed - Manual review required',
      testId: 'MT-2024-002',
      patientId: 'P12346',
      timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      priority: 'high',
      severity: 'moderate'
    },
    {
      id: 3,
      type: 'quality_issue',
      message: 'Poor image quality detected - Rescan recommended',
      testId: 'MT-2024-003',
      patientId: 'P12347',
      timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
      priority: 'medium',
      severity: 'low'
    }
  ];

  const displayAlerts = alerts.length > 0 ? alerts : sampleAlerts;
  const visibleAlerts = displayAlerts.filter(alert => !dismissedAlerts.has(alert.id));

  const getAlertIcon = (type) => {
    switch (type) {
      case 'positive_result':
        return AlertTriangle;
      case 'processing_delay':
        return Clock;
      case 'quality_issue':
        return Eye;
      default:
        return AlertTriangle;
    }
  };

  const getAlertColor = (priority) => {
    switch (priority) {
      case 'critical':
        return {
          bg: 'bg-red-50',
          border: 'border-red-200',
          icon: 'text-red-600',
          text: 'text-red-800',
          badge: 'bg-red-100 text-red-800'
        };
      case 'high':
        return {
          bg: 'bg-orange-50',
          border: 'border-orange-200',
          icon: 'text-orange-600',
          text: 'text-orange-800',
          badge: 'bg-orange-100 text-orange-800'
        };
      case 'medium':
        return {
          bg: 'bg-yellow-50',
          border: 'border-yellow-200',
          icon: 'text-yellow-600',
          text: 'text-yellow-800',
          badge: 'bg-yellow-100 text-yellow-800'
        };
      default:
        return {
          bg: 'bg-gray-50',
          border: 'border-gray-200',
          icon: 'text-gray-600',
          text: 'text-gray-800',
          badge: 'bg-gray-100 text-gray-800'
        };
    }
  };

  const formatAlertTime = (timestamp) => {
    const now = new Date();
    const alertTime = new Date(timestamp);
    const diffInMinutes = Math.floor((now - alertTime) / (1000 * 60));

    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return alertTime.toLocaleDateString();
  };

  const handleDismissAlert = (alertId, event) => {
    event.stopPropagation();
    setDismissedAlerts(prev => new Set([...prev, alertId]));
  };

  const handleAlertClick = (alert) => {
    if (onAlertClick) {
      onAlertClick(alert);
    }
  };

  if (visibleAlerts.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      {visibleAlerts.map((alert) => {
        const IconComponent = getAlertIcon(alert.type);
        const colors = getAlertColor(alert.priority);

        return (
          <div
            key={alert.id}
            className={`${colors.bg} ${colors.border} border rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow`}
            onClick={() => handleAlertClick(alert)}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-3">
                <div className={`flex-shrink-0 w-6 h-6 ${colors.icon}`}>
                  <IconComponent className="w-6 h-6" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2 mb-1">
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${colors.badge}`}>
                      {alert.priority.toUpperCase()}
                    </span>
                    <span className="text-xs text-gray-500">
                      {formatAlertTime(alert.timestamp)}
                    </span>
                  </div>
                  <p className={`text-sm font-medium ${colors.text} mb-1`}>
                    {alert.message}
                  </p>
                  <div className="flex items-center space-x-4 text-xs text-gray-600">
                    <span>Test ID: {alert.testId}</span>
                    {alert.patientId && <span>Patient: {alert.patientId}</span>}
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <ChevronRight className="w-4 h-4 text-gray-400" />
                <button
                  onClick={(e) => handleDismissAlert(alert.id, e)}
                  className="text-gray-400 hover:text-gray-600 p-1"
                  title="Dismiss alert"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        );
      })}
      
      {visibleAlerts.length > 3 && (
        <div className="text-center">
          <button className="text-sm text-primary-600 hover:text-primary-700 font-medium">
            View all alerts ({visibleAlerts.length})
          </button>
        </div>
      )}
    </div>
  );
};

export default CriticalAlerts;
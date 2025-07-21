//src/components/results/SeverityBadge.jsx
import React from 'react';
import { AlertTriangle, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

const SeverityBadge = ({ severity, size = 'md', showIcon = true }) => {
  if (!severity) return null;

  const getSeverityConfig = (level) => {
    switch (level.toLowerCase()) {
      case 'severe':
        return {
          color: 'text-red-300 bg-red-500/20 border-red-500/30',
          icon: XCircle,
          label: 'Severe'
        };
      case 'moderate':
        return {
          color: 'text-orange-300 bg-orange-500/20 border-orange-500/30',
          icon: AlertTriangle,
          label: 'Moderate'
        };
      case 'mild':
        return {
          color: 'text-yellow-300 bg-yellow-500/20 border-yellow-500/30',
          icon: AlertCircle,
          label: 'Mild'
        };
      case 'negative':
        return {
          color: 'text-green-300 bg-green-500/20 border-green-500/30',
          icon: CheckCircle,
          label: 'Negative'
        };
      default:
        return {
          color: 'text-blue-300 bg-blue-500/20 border-blue-500/30',
          icon: AlertCircle,
          label: level
        };
    }
  };

  const getSizeClasses = (size) => {
    switch (size) {
      case 'sm':
        return 'px-2 py-1 text-xs';
      case 'lg':
        return 'px-4 py-2 text-base';
      default:
        return 'px-3 py-1 text-sm';
    }
  };

  const config = getSeverityConfig(severity);
  const IconComponent = config.icon;

  return (
    <span className={`inline-flex items-center rounded-full font-medium border backdrop-blur-md ${config.color} ${getSizeClasses(size)}`}>
      {showIcon && <IconComponent className="w-3 h-3 mr-1" />}
      {config.label}
    </span>
  );
};

export default SeverityBadge;
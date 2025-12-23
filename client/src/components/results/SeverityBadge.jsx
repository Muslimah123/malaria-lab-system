
//src/components/results/SeverityBadge.jsx
import React from 'react';
import { AlertTriangle, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

const SeverityBadge = ({ severity, size = 'md', showIcon = true }) => {
  if (!severity) return null;

  const getSeverityConfig = (level) => {
    switch (level.toLowerCase()) {
      case 'severe':
        return {
          color: 'text-rose-200 bg-gradient-to-r from-rose-500/20 to-rose-600/30 border-rose-500/40 shadow-rose-500/20',
          icon: XCircle,
          label: 'Severe',
          pulse: true
        };
      case 'moderate':
        return {
          color: 'text-orange-300 bg-gradient-to-r from-orange-500/20 to-orange-600/30 border-orange-500/40 shadow-orange-500/20',
          icon: AlertTriangle,
          label: 'Moderate',
          pulse: false
        };
      case 'mild':
        return {
          color: 'text-yellow-300 bg-gradient-to-r from-yellow-500/20 to-yellow-600/30 border-yellow-500/40 shadow-yellow-500/20',
          icon: AlertCircle,
          label: 'Mild',
          pulse: false
        };
      case 'negative':
        return {
          color: 'text-green-300 bg-gradient-to-r from-green-500/20 to-green-600/30 border-green-500/40 shadow-green-500/20',
          icon: CheckCircle,
          label: 'Negative',
          pulse: false
        };
      default:
        return {
          color: 'text-blue-300 bg-gradient-to-r from-blue-500/20 to-blue-600/30 border-blue-500/40 shadow-blue-500/20',
          icon: AlertCircle,
          label: level,
          pulse: false
        };
    }
  };

  const getSizeClasses = (size) => {
    switch (size) {
      case 'sm':
        return 'px-3 py-1 text-xs';
      case 'lg':
        return 'px-5 py-2 text-base';
      default:
        return 'px-4 py-2 text-sm';
    }
  };

  const getIconSize = (size) => {
    switch (size) {
      case 'sm':
        return 'w-3 h-3';
      case 'lg':
        return 'w-5 h-5';
      default:
        return 'w-4 h-4';
    }
  };

  const config = getSeverityConfig(severity);
  const IconComponent = config.icon;

  return (
    <span className={`
      inline-flex items-center rounded-xl font-bold border backdrop-blur-sm shadow-lg transition-all duration-300 hover:scale-105
      ${config.color} 
      ${getSizeClasses(size)}
      ${config.pulse ? 'animate-pulse' : ''}
    `}>
      {showIcon && (
        <div className="relative">
          <IconComponent className={`${getIconSize(size)} mr-2 drop-shadow-sm`} />
          {config.pulse && (
            <div className={`absolute inset-0 ${getIconSize(size)} mr-2 animate-ping opacity-50`}>
              <IconComponent className={getIconSize(size)} />
            </div>
          )}
        </div>
      )}
      <span className="drop-shadow-sm">{config.label}</span>
      
      {/* Subtle shine effect */}
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent rounded-xl opacity-0 hover:opacity-100 transition-opacity duration-300" />
    </span>
  );
};

export default SeverityBadge;
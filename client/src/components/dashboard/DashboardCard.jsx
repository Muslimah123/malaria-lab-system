
// src/components/dashboard/DashboardCard.jsx
import React from 'react';
import { TrendingUp, TrendingDown, X } from 'lucide-react';

const DashboardCard = ({ 
  title, 
  value, 
  change, 
  trend, 
  icon: Icon, 
  color = "bg-blue-500",
  loading = false,
  onClick = null 
}) => {
  if (loading) {
    return (
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
            <div className="h-8 bg-white/20 rounded w-1/2 mb-2"></div>
            <div className="h-4 bg-white/20 rounded w-1/3"></div>
          </div>
          <div className="w-12 h-12 bg-white/20 rounded-lg"></div>
        </div>
      </div>
    );
  }

  const isPositiveTrend = trend === 'up' || (change && !change.includes('-'));
  const TrendIcon = isPositiveTrend ? TrendingUp : TrendingDown;
  const trendColor = isPositiveTrend ? 'text-green-400' : 'text-red-400';

  const cardContent = (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-blue-200 text-sm font-medium">{title}</p>
        <p className="text-3xl font-bold text-white mt-2">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {change && (
          <div className="flex items-center mt-2">
            <TrendIcon className={`h-4 w-4 mr-1 ${trendColor}`} />
            <span className={`text-sm ${trendColor}`}>
              {change}
            </span>
            <span className="text-blue-300 text-sm ml-1">vs last period</span>
          </div>
        )}
      </div>
      {Icon && (
        <div className={`${color} p-3 rounded-lg flex-shrink-0`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      )}
    </div>
  );

  if (onClick) {
    return (
      <button
        onClick={onClick}
        className="w-full bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 hover:bg-white/15 transition-colors text-left"
      >
        {cardContent}
      </button>
    );
  }

  return (
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
      {cardContent}
    </div>
  );
};

// Skeleton loader version
export const DashboardCardSkeleton = () => (
  <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
    <div className="flex items-center justify-between">
      <div className="flex-1">
        <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
        <div className="h-8 bg-white/20 rounded w-1/2 mb-2"></div>
        <div className="h-4 bg-white/20 rounded w-1/3"></div>
      </div>
      <div className="w-12 h-12 bg-white/20 rounded-lg"></div>
    </div>
  </div>
);

// Grid container for dashboard cards
export const DashboardCardGrid = ({ children, className = "" }) => (
  <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 ${className}`}>
    {children}
  </div>
);

// Additional card variants for different use cases
export const StatCard = ({ title, value, subtitle, icon: Icon, color = "bg-blue-500" }) => (
  <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-blue-200 text-sm font-medium">{title}</p>
        <p className="text-2xl font-bold text-white mt-1">{value}</p>
        {subtitle && <p className="text-blue-300 text-xs">{subtitle}</p>}
      </div>
      {Icon && (
        <div className={`${color} p-2 rounded-lg`}>
          <Icon className="h-5 w-5 text-white" />
        </div>
      )}
    </div>
  </div>
);

export const AlertCard = ({ title, message, type = "info", icon: Icon, onClose }) => {
  const typeStyles = {
    info: "bg-blue-500/10 border-blue-500/20 text-blue-200",
    warning: "bg-yellow-500/10 border-yellow-500/20 text-yellow-200",
    error: "bg-red-500/10 border-red-500/20 text-red-200",
    success: "bg-green-500/10 border-green-500/20 text-green-200"
  };

  return (
    <div className={`border rounded-lg p-4 ${typeStyles[type]}`}>
      <div className="flex items-start space-x-3">
        {Icon && <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />}
        <div className="flex-1">
          {title && <p className="font-medium text-sm mb-1">{title}</p>}
          <p className="text-sm">{message}</p>
        </div>
        {onClose && (
          <button onClick={onClose} className="text-current hover:opacity-75">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
};

export const PerformanceCard = ({ title, metrics = [], loading = false }) => {
  if (loading) {
    return (
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 animate-pulse">
        <div className="h-5 bg-white/20 rounded w-1/2 mb-4"></div>
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex justify-between">
              <div className="h-4 bg-white/20 rounded w-1/3"></div>
              <div className="h-4 bg-white/20 rounded w-1/4"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
      <h4 className="text-white font-medium mb-3">{title}</h4>
      <div className="space-y-3">
        {metrics.map((metric, index) => (
          <div key={index} className="flex items-center justify-between">
            <span className="text-blue-200 text-sm">{metric.label}</span>
            <span className="text-white text-sm font-medium">{metric.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default DashboardCard;
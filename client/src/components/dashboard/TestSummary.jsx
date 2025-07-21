// src/components/dashboard/TestSummary.jsx
import React from 'react';
import { 
  TestTube, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  XCircle,
  Eye,
  MoreHorizontal
} from 'lucide-react';

const TestSummary = ({ 
  tests = [], 
  loading = false, 
  title = "Recent Tests",
  showViewAll = true,
  onViewAll,
  onTestClick,
  className = ""
}) => {
  if (loading) {
    return <TestSummarySkeleton title={title} className={className} />;
  }

  return (
    <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
      {/* Header */}
      <div className="p-6 border-b border-white/20">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          {showViewAll && (
            <button 
              onClick={onViewAll || (() => window.location.href = '/tests')}
              className="text-blue-300 hover:text-white text-sm font-medium transition-colors"
            >
              View All
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {tests.length > 0 ? (
          <div className="space-y-4">
            {tests.map((test) => (
              <TestSummaryItem 
                key={test.id} 
                test={test} 
                onClick={() => onTestClick?.(test)} 
              />
            ))}
          </div>
        ) : (
          <EmptyTestsState />
        )}
      </div>
    </div>
  );
};

// Individual test item component
const TestSummaryItem = ({ test, onClick }) => {
  const getStatusBadge = (status) => {
    const statusConfig = {
      completed: { 
        icon: CheckCircle, 
        className: 'bg-green-100 text-green-800 border-green-200' 
      },
      processing: { 
        icon: Clock, 
        className: 'bg-yellow-100 text-yellow-800 border-yellow-200' 
      },
      pending: { 
        icon: Clock, 
        className: 'bg-gray-100 text-gray-800 border-gray-200' 
      },
      failed: { 
        icon: XCircle, 
        className: 'bg-red-100 text-red-800 border-red-200' 
      }
    };

    const config = statusConfig[status] || statusConfig.pending;
    const StatusIcon = config.icon;

    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium border ${config.className}`}>
        <StatusIcon className="h-3 w-3" />
        <span>{status}</span>
      </span>
    );
  };

  const getResultBadge = (result, severity, parasiteType) => {
    if (result === 'positive') {
      const severityColors = {
        mild: 'bg-yellow-100 text-yellow-800 border-yellow-200',
        moderate: 'bg-orange-100 text-orange-800 border-orange-200',
        severe: 'bg-red-100 text-red-800 border-red-200'
      };
      
      return (
        <span className={`px-2 py-1 rounded-full text-xs font-medium border ${severityColors[severity] || severityColors.moderate}`}>
          {result} ({parasiteType})
        </span>
      );
    } else if (result === 'negative') {
      return (
        <span className="px-2 py-1 rounded-full text-xs font-medium border bg-green-100 text-green-800 border-green-200">
          negative
        </span>
      );
    }
    return null;
  };

  const handleClick = () => {
    if (onClick) {
      onClick();
    } else {
      window.location.href = `/tests/${test.id}`;
    }
  };

  return (
    <div 
      className={`flex items-center justify-between p-4 bg-white/5 rounded-lg transition-colors ${
        onClick ? 'hover:bg-white/10 cursor-pointer' : ''
      }`}
      onClick={onClick ? handleClick : undefined}
    >
      <div className="flex-1">
        <div className="flex items-center space-x-3 mb-2">
          <div>
            <p className="text-white font-medium">{test.patientName}</p>
            <p className="text-blue-300 text-sm">
              {test.patientId} • {test.id}
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {getStatusBadge(test.status)}
          {test.result && getResultBadge(test.result, test.severity, test.parasiteType)}
        </div>
      </div>
      
      <div className="text-right">
        <p className="text-blue-300 text-sm">{test.timeAgo || test.processedAt}</p>
        <p className="text-blue-400 text-xs">by {test.technician}</p>
        {onClick && (
          <button className="mt-1 p-1 text-blue-300 hover:text-white">
            <Eye className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
};

// Empty state component
const EmptyTestsState = () => (
  <div className="text-center py-8">
    <TestTube className="h-12 w-12 text-blue-400 mx-auto mb-4" />
    <p className="text-blue-200 mb-2">No recent tests available</p>
    <p className="text-blue-300 text-sm">Upload a sample to get started</p>
    <button 
      onClick={() => window.location.href = '/upload'}
      className="mt-4 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm transition-colors"
    >
      Upload Sample
    </button>
  </div>
);

// Loading skeleton
export const TestSummarySkeleton = ({ title = "Recent Tests", className = "" }) => (
  <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
    <div className="p-6 border-b border-white/20">
      <div className="flex items-center justify-between">
        <div className="h-6 bg-white/20 rounded w-32"></div>
        <div className="h-4 bg-white/20 rounded w-16"></div>
      </div>
    </div>
    <div className="p-6">
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, index) => (
          <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg animate-pulse">
            <div className="flex-1">
              <div className="flex items-center space-x-3 mb-2">
                <div>
                  <div className="h-4 bg-white/20 rounded w-32 mb-1"></div>
                  <div className="h-3 bg-white/20 rounded w-48"></div>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <div className="h-6 bg-white/20 rounded w-20"></div>
                <div className="h-6 bg-white/20 rounded w-24"></div>
              </div>
            </div>
            <div className="text-right">
              <div className="h-3 bg-white/20 rounded w-16 mb-1"></div>
              <div className="h-3 bg-white/20 rounded w-20"></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

// Compact version for smaller spaces
export const CompactTestSummary = ({ tests = [], loading = false, className = "" }) => {
  if (loading) {
    return (
      <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 ${className}`}>
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="flex items-center justify-between animate-pulse">
              <div className="h-4 bg-white/20 rounded w-32"></div>
              <div className="h-4 bg-white/20 rounded w-16"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 ${className}`}>
      <h4 className="text-white font-medium mb-3">Latest Tests</h4>
      <div className="space-y-3">
        {tests.slice(0, 5).map((test) => (
          <div key={test.id} className="flex items-center justify-between text-sm">
            <span className="text-blue-200 truncate flex-1">{test.patientName}</span>
            <span className={`px-2 py-1 rounded text-xs ${
              test.result === 'positive' ? 'bg-red-500/20 text-red-300' :
              test.result === 'negative' ? 'bg-green-500/20 text-green-300' :
              'bg-gray-500/20 text-gray-300'
            }`}>
              {test.result || test.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default TestSummary;
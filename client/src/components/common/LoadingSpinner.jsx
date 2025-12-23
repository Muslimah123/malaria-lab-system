//src/components/common/LoadingSpinner.jsx
import React from 'react';
import clsx from 'clsx';

const LoadingSpinner = ({ 
  size = 'md', 
  color = 'primary', 
  className = '',
  text = null,
  center = false 
}) => {
  const sizeClasses = {
    xs: 'w-3 h-3 border',
    sm: 'w-4 h-4 border-2',
    md: 'w-6 h-6 border-2',
    lg: 'w-8 h-8 border-4',
    xl: 'w-12 h-12 border-4'
  };

  const colorClasses = {
    primary: 'border-gray-300 border-t-primary-600',
    secondary: 'border-gray-300 border-t-secondary-600',
    success: 'border-gray-300 border-t-success-600',
    warning: 'border-gray-300 border-t-warning-600',
    danger: 'border-gray-300 border-t-danger-600',
    white: 'border-gray-400 border-t-white'
  };

  const spinner = (
    <div
      className={clsx(
        'inline-block rounded-full animate-spin',
        sizeClasses[size],
        colorClasses[color],
        className
      )}
      role="status"
      aria-label="Loading"
    />
  );

  if (text) {
    return (
      <div className={clsx('flex items-center space-x-2', center && 'justify-center')}>
        {spinner}
        <span className="text-sm text-gray-600">{text}</span>
      </div>
    );
  }

  if (center) {
    return (
      <div className="flex justify-center">
        {spinner}
      </div>
    );
  }

  return spinner;
};

// Specialized loading components
export const PageLoader = ({ text = 'Loading...' }) => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="text-center">
      <LoadingSpinner size="lg" />
      <p className="mt-4 text-gray-600">{text}</p>
    </div>
  </div>
);

export const CardLoader = ({ text = 'Loading...' }) => (
  <div className="card">
    <div className="card-body text-center py-12">
      <LoadingSpinner size="lg" />
      <p className="mt-4 text-gray-600">{text}</p>
    </div>
  </div>
);

export const ButtonLoader = ({ size = 'sm' }) => (
  <LoadingSpinner size={size} color="white" />
);

export const InlineLoader = ({ text = 'Loading...' }) => (
  <div className="flex items-center space-x-2 text-sm text-gray-600">
    <LoadingSpinner size="xs" />
    <span>{text}</span>
  </div>
);

// Full screen overlay loader
export const OverlayLoader = ({ text = 'Processing...', show = true }) => {
  if (!show) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-8 max-w-sm w-full mx-4 text-center">
        <LoadingSpinner size="xl" />
        <p className="mt-4 text-gray-700 font-medium">{text}</p>
      </div>
    </div>
  );
};

// Progress-based loader
export const ProgressLoader = ({ 
  progress = 0, 
  text = 'Processing...', 
  showPercentage = true 
}) => (
  <div className="text-center">
    <LoadingSpinner size="lg" />
    <div className="mt-4">
      <p className="text-gray-700 font-medium mb-2">{text}</p>
      <div className="progress-bar">
        <div 
          className="progress-fill" 
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
      </div>
      {showPercentage && (
        <p className="text-sm text-gray-600 mt-1">
          {Math.round(progress)}% complete
        </p>
      )}
    </div>
  </div>
);

// Skeleton loader for content
export const SkeletonLoader = ({ lines = 3, className = '' }) => (
  <div className={clsx('animate-pulse', className)}>
    {Array.from({ length: lines }).map((_, i) => (
      <div
        key={i}
        className={clsx(
          'bg-gray-200 rounded h-4 mb-2',
          i === lines - 1 && 'w-3/4' // Last line is shorter
        )}
      />
    ))}
  </div>
);

// Table skeleton loader
export const TableSkeletonLoader = ({ rows = 5, columns = 4 }) => (
  <div className="animate-pulse">
    <div className="grid gap-4">
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <div key={colIndex} className="bg-gray-200 rounded h-6" />
          ))}
        </div>
      ))}
    </div>
  </div>
);

// Image skeleton loader
export const ImageSkeletonLoader = ({ className = 'w-full h-48' }) => (
  <div className={clsx('bg-gray-200 rounded animate-pulse', className)} />
);

export default LoadingSpinner;
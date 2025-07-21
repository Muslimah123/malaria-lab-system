// import React from 'react';
// import { TrendingUp, TrendingDown } from 'lucide-react';
// import clsx from 'clsx';
// import LoadingSpinner from '../common/LoadingSpinner';

// const DashboardCard = ({
//   title,
//   value,
//   subtitle,
//   icon: Icon,
//   trend,
//   color = 'primary',
//   loading = false,
//   onClick,
//   priority = 'normal',
//   className = ''
// }) => {
//   const colorClasses = {
//     primary: {
//       bg: 'bg-primary-50',
//       icon: 'text-primary-600',
//       border: 'border-primary-200',
//       hover: 'hover:bg-primary-100'
//     },
//     secondary: {
//       bg: 'bg-secondary-50',
//       icon: 'text-secondary-600',
//       border: 'border-secondary-200',
//       hover: 'hover:bg-secondary-100'
//     },
//     success: {
//       bg: 'bg-success-50',
//       icon: 'text-success-600',
//       border: 'border-success-200',
//       hover: 'hover:bg-success-100'
//     },
//     warning: {
//       bg: 'bg-warning-50',
//       icon: 'text-warning-600',
//       border: 'border-warning-200',
//       hover: 'hover:bg-warning-100'
//     },
//     danger: {
//       bg: 'bg-danger-50',
//       icon: 'text-danger-600',
//       border: 'border-danger-200',
//       hover: 'hover:bg-danger-100'
//     }
//   };

//   const cardClasses = clsx(
//     'relative overflow-hidden rounded-lg bg-white p-6 shadow-medical border-2 transition-all duration-200',
//     colorClasses[color].border,
//     onClick && 'cursor-pointer',
//     onClick && colorClasses[color].hover,
//     priority === 'high' && 'ring-2 ring-danger-400 ring-opacity-50 animate-pulse-slow',
//     loading && 'opacity-75',
//     className
//   );

//   const formatValue = (val) => {
//     if (typeof val === 'number') {
//       if (val >= 1000000) {
//         return `${(val / 1000000).toFixed(1)}M`;
//       } else if (val >= 1000) {
//         return `${(val / 1000).toFixed(1)}K`;
//       }
//       return val.toLocaleString();
//     }
//     return val;
//   };

//   return (
//     <div
//       className={cardClasses}
//       onClick={onClick}
//       role={onClick ? 'button' : undefined}
//       tabIndex={onClick ? 0 : undefined}
//       onKeyDown={onClick ? (e) => {
//         if (e.key === 'Enter' || e.key === ' ') {
//           e.preventDefault();
//           onClick();
//         }
//       } : undefined}
//     >
//       {/* Background Pattern */}
//       <div className={clsx('absolute inset-0 opacity-5', colorClasses[color].bg)} />
      
//       {/* Priority Indicator */}
//       {priority === 'high' && (
//         <div className="absolute top-0 right-0 w-0 h-0 border-l-[20px] border-l-transparent border-b-[20px] border-b-danger-500">
//           <div className="absolute -top-[15px] -right-[15px] w-2 h-2 bg-white rounded-full" />
//         </div>
//       )}

//       <div className="relative">
//         {/* Header */}
//         <div className="flex items-center justify-between">
//           <div className={clsx(
//             'flex h-12 w-12 items-center justify-center rounded-lg',
//             colorClasses[color].bg
//           )}>
//             {loading ? (
//               <LoadingSpinner size="sm" color={color} />
//             ) : (
//               <Icon className={clsx('h-6 w-6', colorClasses[color].icon)} />
//             )}
//           </div>
          
//           {trend && !loading && (
//             <div className={clsx(
//               'flex items-center text-sm font-medium',
//               trend.isPositive ? 'text-success-600' : 'text-danger-600'
//             )}>
//               {trend.isPositive ? (
//                 <TrendingUp className="h-4 w-4 mr-1" />
//               ) : (
//                 <TrendingDown className="h-4 w-4 mr-1" />
//               )}
//               {trend.value}%
//             </div>
//           )}
//         </div>

//         {/* Content */}
//         <div className="mt-4">
//           <h3 className="text-sm font-medium text-gray-600 truncate">
//             {title}
//           </h3>
//           <div className="mt-2 flex items-baseline">
//             {loading ? (
//               <div className="h-8 w-20 bg-gray-200 rounded animate-pulse" />
//             ) : (
//               <span className="text-3xl font-bold text-gray-900">
//                 {formatValue(value)}
//               </span>
//             )}
//           </div>
//           {subtitle && (
//             <p className="mt-1 text-sm text-gray-500 truncate">
//               {loading ? (
//                 <div className="h-4 w-32 bg-gray-200 rounded animate-pulse" />
//               ) : (
//                 subtitle
//               )}
//             </p>
//           )}
//         </div>

//         {/* Footer Actions */}
//         {onClick && !loading && (
//           <div className="mt-4 flex items-center text-sm text-gray-600">
//             <span>View details</span>
//             <svg className="ml-1 h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
//             </svg>
//           </div>
//         )}
//       </div>
//     </div>
//   );
// };

// // Specialized card variants
// export const StatCard = ({ title, value, change, loading }) => (
//   <DashboardCard
//     title={title}
//     value={value}
//     trend={change ? { value: Math.abs(change), isPositive: change > 0 } : null}
//     loading={loading}
//   />
// );

// export const AlertCard = ({ title, count, severity = 'warning', onClick }) => (
//   <DashboardCard
//     title={title}
//     value={count}
//     color={severity}
//     priority={count > 0 ? 'high' : 'normal'}
//     onClick={onClick}
//     subtitle={count > 0 ? 'Requires attention' : 'All clear'}
//   />
// );

// export const PerformanceCard = ({ title, value, unit, target, loading }) => {
//   const percentage = target ? Math.min(100, (value / target) * 100) : 0;
//   const isGood = percentage >= 80;
  
//   return (
//     <DashboardCard
//       title={title}
//       value={`${value}${unit}`}
//       color={isGood ? 'success' : percentage >= 60 ? 'warning' : 'danger'}
//       subtitle={target ? `${percentage.toFixed(0)}% of target (${target}${unit})` : ''}
//       loading={loading}
//     />
//   );
// };

// // Skeleton loader for dashboard cards
// export const DashboardCardSkeleton = () => (
//   <div className="bg-white p-6 rounded-lg shadow-medical border border-gray-200">
//     <div className="flex items-center justify-between">
//       <div className="h-12 w-12 bg-gray-200 rounded-lg animate-pulse" />
//       <div className="h-4 w-12 bg-gray-200 rounded animate-pulse" />
//     </div>
//     <div className="mt-4 space-y-2">
//       <div className="h-4 w-24 bg-gray-200 rounded animate-pulse" />
//       <div className="h-8 w-16 bg-gray-200 rounded animate-pulse" />
//       <div className="h-3 w-32 bg-gray-200 rounded animate-pulse" />
//     </div>
//   </div>
// );

// export default DashboardCard;
// // src/components/dashboard/DashboardCard.jsx
// import React from 'react';
// import { TrendingUp, TrendingDown } from 'lucide-react';

// // Main StatCard component (matches existing export)
// const StatCard = ({ 
//   title, 
//   value, 
//   change, 
//   trend, 
//   icon: Icon, 
//   color = "bg-blue-500",
//   loading = false,
//   onClick = null 
// }) => {
//   if (loading) {
//     return (
//       <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
//         <div className="flex items-center justify-between">
//           <div className="flex-1">
//             <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
//             <div className="h-8 bg-white/20 rounded w-1/2 mb-2"></div>
//             <div className="h-4 bg-white/20 rounded w-1/3"></div>
//           </div>
//           <div className="w-12 h-12 bg-white/20 rounded-lg"></div>
//         </div>
//       </div>
//     );
//   }

//   const isPositiveTrend = trend === 'up' || (change && !change.includes('-'));
//   const TrendIcon = isPositiveTrend ? TrendingUp : TrendingDown;
//   const trendColor = isPositiveTrend ? 'text-green-400' : 'text-red-400';

//   const cardContent = (
//     <div className="flex items-center justify-between">
//       <div>
//         <p className="text-blue-200 text-sm font-medium">{title}</p>
//         <p className="text-3xl font-bold text-white mt-2">
//           {typeof value === 'number' ? value.toLocaleString() : value}
//         </p>
//         {change && (
//           <div className="flex items-center mt-2">
//             <TrendIcon className={`h-4 w-4 mr-1 ${trendColor}`} />
//             <span className={`text-sm ${trendColor}`}>
//               {change}
//             </span>
//             <span className="text-blue-300 text-sm ml-1">vs last period</span>
//           </div>
//         )}
//       </div>
//       {Icon && (
//         <div className={`${color} p-3 rounded-lg flex-shrink-0`}>
//           <Icon className="h-6 w-6 text-white" />
//         </div>
//       )}
//     </div>
//   );

//   if (onClick) {
//     return (
//       <button
//         onClick={onClick}
//         className="w-full bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 hover:bg-white/15 transition-colors text-left"
//       >
//         {cardContent}
//       </button>
//     );
//   }

//   return (
//     <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//       {cardContent}
//     </div>
//   );
// };

// // Default export (StatCard)
// const DashboardCard = StatCard;

// // Performance Card variant
// export const PerformanceCard = ({ title, metrics = [], loading = false }) => {
//   if (loading) {
//     return (
//       <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
//         <div className="h-4 bg-white/20 rounded w-1/2 mb-4"></div>
//         <div className="space-y-3">
//           {Array.from({ length: 3 }).map((_, i) => (
//             <div key={i} className="flex justify-between">
//               <div className="h-3 bg-white/20 rounded w-1/3"></div>
//               <div className="h-3 bg-white/20 rounded w-1/4"></div>
//             </div>
//           ))}
//         </div>
//       </div>
//     );
//   }

//   return (
//     <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//       <h4 className="text-white font-medium mb-4">{title}</h4>
//       <div className="space-y-3">
//         {metrics.map((metric, index) => (
//           <div key={index} className="flex items-center justify-between">
//             <span className="text-blue-200 text-sm">{metric.label}</span>
//             <span className="text-white font-medium">{metric.value}</span>
//           </div>
//         ))}
//       </div>
//     </div>
//   );
// };

// // Alert Card variant
// export const AlertCard = ({ 
//   type = 'info', 
//   title, 
//   message, 
//   actions = null,
//   onDismiss = null 
// }) => {
//   const typeStyles = {
//     info: 'bg-blue-500/10 border-blue-500/20 text-blue-200',
//     warning: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-200',
//     error: 'bg-red-500/10 border-red-500/20 text-red-200',
//     success: 'bg-green-500/10 border-green-500/20 text-green-200'
//   };

//   return (
//     <div className={`border rounded-lg p-4 ${typeStyles[type]}`}>
//       <div className="flex items-start justify-between">
//         <div className="flex-1">
//           {title && <h4 className="font-medium mb-1">{title}</h4>}
//           <p className="text-sm">{message}</p>
//           {actions && <div className="mt-3">{actions}</div>}
//         </div>
//         {onDismiss && (
//           <button
//             onClick={onDismiss}
//             className="ml-3 text-current hover:opacity-75"
//           >
//             ×
//           </button>
//         )}
//       </div>
//     </div>
//   );
// };

// // Skeleton loader version
// export const DashboardCardSkeleton = () => (
//   <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
//     <div className="flex items-center justify-between">
//       <div className="flex-1">
//         <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
//         <div className="h-8 bg-white/20 rounded w-1/2 mb-2"></div>
//         <div className="h-4 bg-white/20 rounded w-1/3"></div>
//       </div>
//       <div className="w-12 h-12 bg-white/20 rounded-lg"></div>
//     </div>
//   </div>
// );

// // Export StatCard as named export too
// export { StatCard };

// export default DashboardCard;
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
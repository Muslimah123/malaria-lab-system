// // import React, { useState, useMemo } from 'react';
// // import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
// // import { TrendingUp, BarChart3, Calendar } from 'lucide-react';

// // const StatisticsChart = ({ timeRange, onTimeRangeChange, data }) => {
// //   const [chartType, setChartType] = useState('line'); // 'line' or 'bar'

// //   // Generate sample data if none provided
// //   const generateSampleData = (range) => {
// //     const today = new Date();
// //     const dataPoints = [];
    
// //     let days = 7;
// //     if (range === 'month') days = 30;
// //     if (range === 'week') days = 7;
// //     if (range === 'today') days = 24; // hours for today
    
// //     for (let i = days - 1; i >= 0; i--) {
// //       const date = new Date(today);
      
// //       if (range === 'today') {
// //         date.setHours(date.getHours() - i);
// //         dataPoints.push({
// //           name: `${date.getHours()}:00`,
// //           tests: Math.floor(Math.random() * 15) + 1,
// //           positive: Math.floor(Math.random() * 5),
// //           negative: Math.floor(Math.random() * 10) + 1,
// //           processing: Math.floor(Math.random() * 3)
// //         });
// //       } else {
// //         date.setDate(date.getDate() - i);
// //         dataPoints.push({
// //           name: date.toLocaleDateString('en-US', { 
// //             month: 'short', 
// //             day: 'numeric' 
// //           }),
// //           tests: Math.floor(Math.random() * 50) + 10,
// //           positive: Math.floor(Math.random() * 15) + 2,
// //           negative: Math.floor(Math.random() * 30) + 5,
// //           processing: Math.floor(Math.random() * 8) + 1
// //         });
// //       }
// //     }
    
// //     return dataPoints;
// //   };

// //   const chartData = useMemo(() => {
// //     return generateSampleData(timeRange);
// //   }, [timeRange]);

// //   const timeRangeOptions = [
// //     { value: 'today', label: 'Today' },
// //     { value: 'week', label: 'This Week' },
// //     { value: 'month', label: 'This Month' }
// //   ];

// //   const CustomTooltip = ({ active, payload, label }) => {
// //     if (active && payload && payload.length) {
// //       return (
// //         <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
// //           <p className="font-medium text-gray-900">{label}</p>
// //           {payload.map((entry, index) => (
// //             <p key={index} className="text-sm" style={{ color: entry.color }}>
// //               {entry.dataKey.charAt(0).toUpperCase() + entry.dataKey.slice(1)}: {entry.value}
// //             </p>
// //           ))}
// //         </div>
// //       );
// //     }
// //     return null;
// //   };

// //   return (
// //     <div className="bg-white rounded-lg shadow-medical p-6">
// //       <div className="flex items-center justify-between mb-6">
// //         <div className="flex items-center space-x-4">
// //           <h3 className="text-lg font-medium text-gray-900">Test Statistics</h3>
          
// //           {/* Chart Type Toggle */}
// //           <div className="flex bg-gray-100 rounded-lg p-1">
// //             <button
// //               onClick={() => setChartType('line')}
// //               className={`p-2 rounded-md text-sm font-medium transition-colors ${
// //                 chartType === 'line'
// //                   ? 'bg-white text-gray-900 shadow-sm'
// //                   : 'text-gray-600 hover:text-gray-900'
// //               }`}
// //             >
// //               <TrendingUp className="w-4 h-4" />
// //             </button>
// //             <button
// //               onClick={() => setChartType('bar')}
// //               className={`p-2 rounded-md text-sm font-medium transition-colors ${
// //                 chartType === 'bar'
// //                   ? 'bg-white text-gray-900 shadow-sm'
// //                   : 'text-gray-600 hover:text-gray-900'
// //               }`}
// //             >
// //               <BarChart3 className="w-4 h-4" />
// //             </button>
// //           </div>
// //         </div>

// //         {/* Time Range Selector */}
// //         <div className="flex items-center space-x-2">
// //           <Calendar className="w-4 h-4 text-gray-400" />
// //           <select
// //             value={timeRange}
// //             onChange={(e) => onTimeRangeChange(e.target.value)}
// //             className="text-sm border border-gray-300 rounded-md px-3 py-1 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
// //           >
// //             {timeRangeOptions.map(option => (
// //               <option key={option.value} value={option.value}>
// //                 {option.label}
// //               </option>
// //             ))}
// //           </select>
// //         </div>
// //       </div>

// //       {/* Chart */}
// //       <div className="h-80">
// //         <ResponsiveContainer width="100%" height="100%">
// //           {chartType === 'line' ? (
// //             <LineChart data={chartData}>
// //               <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
// //               <XAxis 
// //                 dataKey="name" 
// //                 stroke="#6b7280"
// //                 fontSize={12}
// //                 tickLine={false}
// //                 axisLine={false}
// //               />
// //               <YAxis 
// //                 stroke="#6b7280"
// //                 fontSize={12}
// //                 tickLine={false}
// //                 axisLine={false}
// //               />
// //               <Tooltip content={<CustomTooltip />} />
// //               <Line 
// //                 type="monotone" 
// //                 dataKey="tests" 
// //                 stroke="#3b82f6" 
// //                 strokeWidth={2}
// //                 dot={{ fill: '#3b82f6', strokeWidth: 2, r: 4 }}
// //                 activeDot={{ r: 6, stroke: '#3b82f6', strokeWidth: 2 }}
// //                 name="Total Tests"
// //               />
// //               <Line 
// //                 type="monotone" 
// //                 dataKey="positive" 
// //                 stroke="#ef4444" 
// //                 strokeWidth={2}
// //                 dot={{ fill: '#ef4444', strokeWidth: 2, r: 4 }}
// //                 name="Positive"
// //               />
// //               <Line 
// //                 type="monotone" 
// //                 dataKey="negative" 
// //                 stroke="#10b981" 
// //                 strokeWidth={2}
// //                 dot={{ fill: '#10b981', strokeWidth: 2, r: 4 }}
// //                 name="Negative"
// //               />
// //             </LineChart>
// //           ) : (
// //             <BarChart data={chartData}>
// //               <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
// //               <XAxis 
// //                 dataKey="name" 
// //                 stroke="#6b7280"
// //                 fontSize={12}
// //                 tickLine={false}
// //                 axisLine={false}
// //               />
// //               <YAxis 
// //                 stroke="#6b7280"
// //                 fontSize={12}
// //                 tickLine={false}
// //                 axisLine={false}
// //               />
// //               <Tooltip content={<CustomTooltip />} />
// //               <Bar dataKey="positive" fill="#ef4444" name="Positive" />
// //               <Bar dataKey="negative" fill="#10b981" name="Negative" />
// //               <Bar dataKey="processing" fill="#f59e0b" name="Processing" />
// //             </BarChart>
// //           )}
// //         </ResponsiveContainer>
// //       </div>

// //       {/* Legend */}
// //       <div className="flex items-center justify-center space-x-6 mt-4 pt-4 border-t border-gray-200">
// //         <div className="flex items-center space-x-2">
// //           <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
// //           <span className="text-sm text-gray-600">Total Tests</span>
// //         </div>
// //         <div className="flex items-center space-x-2">
// //           <div className="w-3 h-3 bg-red-500 rounded-full"></div>
// //           <span className="text-sm text-gray-600">Positive</span>
// //         </div>
// //         <div className="flex items-center space-x-2">
// //           <div className="w-3 h-3 bg-green-500 rounded-full"></div>
// //           <span className="text-sm text-gray-600">Negative</span>
// //         </div>
// //         <div className="flex items-center space-x-2">
// //           <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
// //           <span className="text-sm text-gray-600">Processing</span>
// //         </div>
// //       </div>
// //     </div>
// //   );
// // };

// // export default StatisticsChart;
// // src/components/dashboard/StatisticsChart.jsx
// import React, { useState } from 'react';
// import { BarChart3, TrendingUp, Calendar, Filter } from 'lucide-react';

// const StatisticsChart = ({ 
//   data = [], 
//   loading = false,
//   title = "Test Statistics",
//   timeRange = "7days",
//   onTimeRangeChange,
//   className = ""
// }) => {
//   const [selectedMetric, setSelectedMetric] = useState('tests');

//   if (loading) {
//     return <StatisticsChartSkeleton title={title} className={className} />;
//   }

//   const timeRanges = [
//     { value: '7days', label: 'Last 7 Days' },
//     { value: '30days', label: 'Last 30 Days' },
//     { value: '90days', label: 'Last 90 Days' },
//     { value: '1year', label: 'Last Year' }
//   ];

//   const metrics = [
//     { key: 'tests', label: 'Total Tests', color: 'bg-blue-500' },
//     { key: 'positive', label: 'Positive Results', color: 'bg-red-500' },
//     { key: 'negative', label: 'Negative Results', color: 'bg-green-500' }
//   ];

//   // Calculate max value for scaling
//   const maxValue = Math.max(...data.map(d => Math.max(d.tests || 0, d.positive || 0, d.negative || 0)));

//   return (
//     <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
//       {/* Header */}
//       <div className="p-6 border-b border-white/20">
//         <div className="flex items-center justify-between mb-4">
//           <div className="flex items-center space-x-2">
//             <BarChart3 className="h-5 w-5 text-blue-400" />
//             <h3 className="text-lg font-semibold text-white">{title}</h3>
//           </div>
          
//           {/* Time Range Selector */}
//           <div className="flex items-center space-x-2">
//             <Calendar className="h-4 w-4 text-blue-300" />
//             <select
//               value={timeRange}
//               onChange={(e) => onTimeRangeChange?.(e.target.value)}
//               className="bg-white/10 border border-white/20 rounded px-3 py-1 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
//             >
//               {timeRanges.map(range => (
//                 <option key={range.value} value={range.value}>
//                   {range.label}
//                 </option>
//               ))}
//             </select>
//           </div>
//         </div>

//         {/* Metric Selector */}
//         <div className="flex items-center space-x-2">
//           {metrics.map(metric => (
//             <button
//               key={metric.key}
//               onClick={() => setSelectedMetric(metric.key)}
//               className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm transition-colors ${
//                 selectedMetric === metric.key
//                   ? 'bg-white/20 text-white'
//                   : 'text-blue-300 hover:text-white hover:bg-white/10'
//               }`}
//             >
//               <div className={`w-3 h-3 rounded-full ${metric.color}`}></div>
//               <span>{metric.label}</span>
//             </button>
//           ))}
//         </div>
//       </div>

//       {/* Chart */}
//       <div className="p-6">
//         {data.length > 0 ? (
//           <div className="space-y-4">
//             {/* Chart Bars */}
//             <div className="flex items-end justify-between h-48 space-x-2">
//               {data.map((item, index) => {
//                 const value = item[selectedMetric] || 0;
//                 const height = maxValue > 0 ? (value / maxValue) * 100 : 0;
//                 const metric = metrics.find(m => m.key === selectedMetric);
                
//                 return (
//                   <div key={index} className="flex-1 flex flex-col items-center">
//                     {/* Bar */}
//                     <div className="w-full relative group">
//                       <div
//                         className={`w-full ${metric?.color} opacity-70 hover:opacity-100 transition-opacity rounded-t`}
//                         style={{ height: `${height}%` }}
//                       >
//                         {/* Tooltip */}
//                         <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
//                           {value} {selectedMetric}
//                         </div>
//                       </div>
//                     </div>
                    
//                     {/* Label */}
//                     <div className="mt-2 text-xs text-blue-300 text-center">
//                       {item.date ? new Date(item.date).toLocaleDateString('en-US', { 
//                         month: 'short', 
//                         day: 'numeric' 
//                       }) : item.label}
//                     </div>
//                   </div>
//                 );
//               })}
//             </div>

//             {/* Summary Stats */}
//             <div className="grid grid-cols-3 gap-4 pt-4 border-t border-white/20">
//               {metrics.map(metric => {
//                 const total = data.reduce((sum, item) => sum + (item[metric.key] || 0), 0);
//                 const average = data.length > 0 ? Math.round(total / data.length) : 0;
                
//                 return (
//                   <div key={metric.key} className="text-center">
//                     <div className={`w-4 h-4 ${metric.color} rounded mx-auto mb-1`}></div>
//                     <p className="text-white font-medium">{total}</p>
//                     <p className="text-blue-300 text-xs">{metric.label}</p>
//                     <p className="text-blue-400 text-xs">Avg: {average}</p>
//                   </div>
//                 );
//               })}
//             </div>
//           </div>
//         ) : (
//           <EmptyChartState />
//         )}
//       </div>
//     </div>
//   );
// };

// // Empty state component
// const EmptyChartState = () => (
//   <div className="text-center py-12">
//     <BarChart3 className="h-12 w-12 text-blue-400 mx-auto mb-4" />
//     <p className="text-blue-200 mb-2">No data available</p>
//     <p className="text-blue-300 text-sm">Statistics will appear here once tests are processed</p>
//   </div>
// );

// // Loading skeleton
// export const StatisticsChartSkeleton = ({ title = "Loading Chart", className = "" }) => (
//   <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
//     <div className="p-6 border-b border-white/20">
//       <div className="flex items-center justify-between mb-4">
//         <div className="h-6 bg-white/20 rounded w-48"></div>
//         <div className="h-8 bg-white/20 rounded w-32"></div>
//       </div>
//       <div className="flex space-x-2">
//         {Array.from({ length: 3 }).map((_, i) => (
//           <div key={i} className="h-6 bg-white/20 rounded w-24"></div>
//         ))}
//       </div>
//     </div>
//     <div className="p-6">
//       <div className="flex items-end justify-between h-48 space-x-2">
//         {Array.from({ length: 7 }).map((_, i) => (
//           <div key={i} className="flex-1 flex flex-col items-center">
//             <div 
//               className="w-full bg-white/20 rounded-t animate-pulse"
//               style={{ height: `${Math.random() * 80 + 20}%` }}
//             ></div>
//             <div className="mt-2 h-3 bg-white/20 rounded w-8"></div>
//           </div>
//         ))}
//       </div>
//     </div>
//   </div>
// );

// // Pie Chart variant
// export const PieChart = ({ 
//   data = [], 
//   title = "Distribution",
//   loading = false,
//   className = ""
// }) => {
//   if (loading) {
//     return (
//       <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 ${className}`}>
//         <div className="h-6 bg-white/20 rounded w-32 mb-4"></div>
//         <div className="w-32 h-32 bg-white/20 rounded-full mx-auto animate-pulse"></div>
//       </div>
//     );
//   }

//   const total = data.reduce((sum, item) => sum + item.value, 0);
  
//   return (
//     <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 ${className}`}>
//       <h4 className="text-white font-medium mb-4">{title}</h4>
      
//       <div className="flex items-center space-x-6">
//         {/* Simple pie representation using stacked bars */}
//         <div className="flex-1">
//           <div className="space-y-2">
//             {data.map((item, index) => {
//               const percentage = total > 0 ? (item.value / total) * 100 : 0;
//               return (
//                 <div key={index} className="flex items-center justify-between">
//                   <div className="flex items-center space-x-2">
//                     <div className={`w-3 h-3 rounded ${item.color}`}></div>
//                     <span className="text-blue-200 text-sm">{item.label}</span>
//                   </div>
//                   <div className="flex items-center space-x-2">
//                     <div className="w-16 bg-white/10 rounded-full h-2">
//                       <div 
//                         className={`h-2 rounded-full ${item.color}`}
//                         style={{ width: `${percentage}%` }}
//                       ></div>
//                     </div>
//                     <span className="text-white text-sm w-8 text-right">{item.value}</span>
//                   </div>
//                 </div>
//               );
//             })}
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// // Line Chart variant (simplified)
// export const LineChart = ({ 
//   data = [], 
//   title = "Trends",
//   loading = false,
//   className = ""
// }) => {
//   if (loading) {
//     return <StatisticsChartSkeleton title={title} className={className} />;
//   }

//   const maxValue = Math.max(...data.map(d => d.value || 0));

//   return (
//     <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 ${className}`}>
//       <h4 className="text-white font-medium mb-4">{title}</h4>
      
//       <div className="relative h-32">
//         <svg className="w-full h-full" viewBox="0 0 300 100">
//           {/* Grid lines */}
//           <defs>
//             <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
//               <path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="0.5"/>
//             </pattern>
//           </defs>
//           <rect width="100%" height="100%" fill="url(#grid)" />
          
//           {/* Line */}
//           {data.length > 1 && (
//             <polyline
//               fill="none"
//               stroke="#3B82F6"
//               strokeWidth="2"
//               points={data.map((point, index) => {
//                 const x = (index / (data.length - 1)) * 280 + 10;
//                 const y = 90 - ((point.value / maxValue) * 80);
//                 return `${x},${y}`;
//               }).join(' ')}
//             />
//           )}
          
//           {/* Points */}
//           {data.map((point, index) => {
//             const x = (index / (data.length - 1)) * 280 + 10;
//             const y = 90 - ((point.value / maxValue) * 80);
//             return (
//               <circle
//                 key={index}
//                 cx={x}
//                 cy={y}
//                 r="3"
//                 fill="#3B82F6"
//                 stroke="#1E40AF"
//                 strokeWidth="1"
//               />
//             );
//           })}
//         </svg>
//       </div>
      
//       {/* Labels */}
//       <div className="flex justify-between mt-2 text-xs text-blue-300">
//         {data.map((point, index) => (
//           <span key={index}>
//             {point.label}
//           </span>
//         ))}
//       </div>
//     </div>
//   );
// };

// export default StatisticsChart;
// src/components/dashboard/StatisticsChart.jsx
import React, { useState, useEffect } from 'react';
import { 
  LineChart, 
  Line, 
  AreaChart,
  Area,
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { 
  TrendingUp, 
  BarChart3, 
  Activity,
  Calendar,
  Filter,
  Download,
  Target
} from 'lucide-react';

const StatisticsChart = ({ 
  data = [], 
  loading = false, 
  title = "Analytics",
  type = "line", // line, bar, area, pie
  className = "",
  height = 300,
  showFilters = true,
  onFilterChange = null
}) => {
  const [chartType, setChartType] = useState(type);
  const [timeRange, setTimeRange] = useState('7days');
  const [selectedMetric, setSelectedMetric] = useState('tests');

  if (loading) {
    return <StatisticsChartSkeleton title={title} className={className} height={height} />;
  }

  // Color schemes for different chart types
  const colors = {
    primary: '#3B82F6',
    success: '#10B981', 
    warning: '#F59E0B',
    danger: '#EF4444',
    purple: '#8B5CF6',
    teal: '#14B8A6'
  };

  const pieColors = [colors.primary, colors.success, colors.warning, colors.danger, colors.purple, colors.teal];

  // Chart type configurations
  const chartConfigs = {
    line: {
      icon: Activity,
      component: LineChart,
      children: (
        <Line 
          type="monotone" 
          dataKey="value" 
          stroke={colors.primary} 
          strokeWidth={2}
          dot={{ fill: colors.primary, strokeWidth: 2, r: 4 }}
          activeDot={{ r: 6, stroke: colors.primary, strokeWidth: 2 }}
        />
      )
    },
    area: {
      icon: TrendingUp,
      component: AreaChart,
      children: (
        <Area 
          type="monotone" 
          dataKey="value" 
          stroke={colors.primary} 
          fill={`${colors.primary}20`}
          strokeWidth={2}
        />
      )
    },
    bar: {
      icon: BarChart3,
      component: BarChart,
      children: (
        <Bar 
          dataKey="value" 
          fill={colors.primary}
          radius={[4, 4, 0, 0]}
        />
      )
    },
    pie: {
      icon: Target,
      component: PieChart,
      children: (
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
          outerRadius={80}
          fill="#8884d8"
          dataKey="value"
        >
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={pieColors[index % pieColors.length]} />
          ))}
        </Pie>
      )
    }
  };

  const currentConfig = chartConfigs[chartType];
  const ChartComponent = currentConfig.component;
  const ChartIcon = currentConfig.icon;

  // Custom tooltip for better data display
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white/90 backdrop-blur-sm border border-gray-200 rounded-lg p-3 shadow-lg">
          <p className="text-gray-700 font-medium">{`${label}`}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.name || 'Value'}: ${entry.value}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
      {/* Header */}
      <div className="p-6 border-b border-white/20">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="bg-blue-500 p-2 rounded-lg">
              <ChartIcon className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white">{title}</h3>
          </div>

          {showFilters && (
            <div className="flex items-center space-x-3">
              {/* Time Range Filter */}
              <select
                value={timeRange}
                onChange={(e) => {
                  setTimeRange(e.target.value);
                  onFilterChange?.({ timeRange: e.target.value, metric: selectedMetric });
                }}
                className="bg-white/10 border border-white/20 rounded px-3 py-1 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="7days">Last 7 days</option>
                <option value="30days">Last 30 days</option>
                <option value="90days">Last 90 days</option>
                <option value="1year">Last year</option>
              </select>

              {/* Chart Type Selector */}
              <div className="flex items-center space-x-1 bg-white/5 rounded-lg p-1">
                {Object.entries(chartConfigs).map(([key, config]) => {
                  const IconComponent = config.icon;
                  return (
                    <button
                      key={key}
                      onClick={() => setChartType(key)}
                      className={`p-2 rounded transition-colors ${
                        chartType === key 
                          ? 'bg-blue-500 text-white' 
                          : 'text-blue-300 hover:text-white hover:bg-white/10'
                      }`}
                      title={key.charAt(0).toUpperCase() + key.slice(1)}
                    >
                      <IconComponent className="h-4 w-4" />
                    </button>
                  );
                })}
              </div>

              {/* Export Button */}
              <button className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                <Download className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Chart Content */}
      <div className="p-6">
        {data.length > 0 ? (
          <div style={{ height: `${height}px` }}>
            <ResponsiveContainer width="100%" height="100%">
              <ChartComponent data={data}>
                {chartType !== 'pie' && (
                  <>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="name" 
                      stroke="rgba(255,255,255,0.7)"
                      fontSize={12}
                    />
                    <YAxis 
                      stroke="rgba(255,255,255,0.7)"
                      fontSize={12}
                    />
                  </>
                )}
                <Tooltip content={<CustomTooltip />} />
                {chartType === 'pie' && <Legend />}
                {currentConfig.children}
              </ChartComponent>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyChartState height={height} />
        )}
      </div>
    </div>
  );
};

// Empty state component
const EmptyChartState = ({ height }) => (
  <div 
    className="flex items-center justify-center text-center"
    style={{ height: `${height}px` }}
  >
    <div>
      <BarChart3 className="h-12 w-12 text-blue-400 mx-auto mb-4" />
      <p className="text-blue-200 mb-2">No data available</p>
      <p className="text-blue-300 text-sm">Data will appear here once tests are processed</p>
    </div>
  </div>
);

// Loading skeleton
export const StatisticsChartSkeleton = ({ title = "Loading...", className = "", height = 300 }) => (
  <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
    <div className="p-6 border-b border-white/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 bg-white/20 rounded-lg"></div>
          <div className="h-6 bg-white/20 rounded w-32"></div>
        </div>
        <div className="flex items-center space-x-3">
          <div className="h-8 bg-white/20 rounded w-24"></div>
          <div className="h-8 bg-white/20 rounded w-32"></div>
        </div>
      </div>
    </div>
    <div className="p-6">
      <div 
        className="bg-white/5 rounded animate-pulse"
        style={{ height: `${height}px` }}
      ></div>
    </div>
  </div>
);

// Multi-metric chart component
export const MultiMetricChart = ({ 
  datasets = [], 
  loading = false, 
  title = "Multi-Metric Analysis",
  className = ""
}) => {
  const [selectedMetrics, setSelectedMetrics] = useState(['tests', 'positive']);

  const colors = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'];

  if (loading) {
    return <StatisticsChartSkeleton title={title} className={className} />;
  }

  return (
    <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg ${className}`}>
      <div className="p-6 border-b border-white/20">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          
          {/* Metric Toggles */}
          <div className="flex items-center space-x-2">
            {datasets.map((dataset, index) => (
              <button
                key={dataset.key}
                onClick={() => {
                  if (selectedMetrics.includes(dataset.key)) {
                    setSelectedMetrics(prev => prev.filter(m => m !== dataset.key));
                  } else {
                    setSelectedMetrics(prev => [...prev, dataset.key]);
                  }
                }}
                className={`flex items-center space-x-2 px-3 py-1 rounded text-sm transition-colors ${
                  selectedMetrics.includes(dataset.key)
                    ? 'bg-blue-500 text-white'
                    : 'bg-white/10 text-blue-300 hover:bg-white/20'
                }`}
              >
                <div 
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: colors[index % colors.length] }}
                ></div>
                <span>{dataset.name}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="p-6">
        <div style={{ height: '300px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={datasets[0]?.data || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis 
                dataKey="name" 
                stroke="rgba(255,255,255,0.7)"
                fontSize={12}
              />
              <YAxis 
                stroke="rgba(255,255,255,0.7)"
                fontSize={12}
              />
              <Tooltip content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-white/90 backdrop-blur-sm border border-gray-200 rounded-lg p-3 shadow-lg">
                      <p className="text-gray-700 font-medium">{label}</p>
                      {payload.map((entry, index) => (
                        <p key={index} className="text-sm" style={{ color: entry.color }}>
                          {`${entry.dataKey}: ${entry.value}`}
                        </p>
                      ))}
                    </div>
                  );
                }
                return null;
              }} />
              
              {datasets.map((dataset, index) => (
                selectedMetrics.includes(dataset.key) && (
                  <Line
                    key={dataset.key}
                    type="monotone"
                    dataKey={dataset.key}
                    stroke={colors[index % colors.length]}
                    strokeWidth={2}
                    dot={{ fill: colors[index % colors.length], strokeWidth: 2, r: 4 }}
                  />
                )
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

// Specific chart components for different metrics
export const TestTrendsChart = (props) => (
  <StatisticsChart 
    {...props}
    title="Test Trends"
    type="area"
  />
);

export const ParasiteDistributionChart = (props) => (
  <StatisticsChart 
    {...props}
    title="Parasite Distribution"
    type="pie"
  />
);

export const TechnicianPerformanceChart = (props) => (
  <StatisticsChart 
    {...props}
    title="Technician Performance"
    type="bar"
  />
);

export default StatisticsChart;
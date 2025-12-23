
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
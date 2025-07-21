// src/components/dashboard/AnalyticsSection.jsx
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  BarChart3, 
  TrendingUp, 
  PieChart, 
  Activity,
  Calendar,
  Users,
  Target,
  Clock
} from 'lucide-react';

import StatisticsChart, { 
  MultiMetricChart, 
  TestTrendsChart, 
  ParasiteDistributionChart, 
  TechnicianPerformanceChart,
  StatisticsChartSkeleton 
} from './StatisticsChart';
import { selectUser } from '../../store/slices/authSlice';
import apiService from '../../services/api';

const AnalyticsSection = ({ 
  className = "",
  showCompactView = false,
  timeRange = '30days' 
}) => {
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  
  // State for analytics data
  const [analyticsData, setAnalyticsData] = useState({
    testTrends: [],
    parasiteDistribution: [],
    technicianPerformance: [],
    weeklyStats: [],
    monthlyComparison: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeChart, setActiveChart] = useState('trends');

  // Fetch analytics data
  useEffect(() => {
    fetchAnalyticsData();
  }, [timeRange]);

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch different analytics endpoints
      const [
        trendsResponse,
        distributionResponse,
        performanceResponse,
        comprehensiveResponse
      ] = await Promise.all([
        apiService.analytics.getTestTrends({ period: timeRange }),
        apiService.analytics.getParasiteTypes({ period: timeRange }),
        apiService.analytics.getTechnicianPerformance({ period: timeRange }),
        apiService.analytics.getComprehensive({ period: timeRange })
      ]);

      // Process and format the data for charts
      setAnalyticsData({
        testTrends: formatTrendsData(trendsResponse.data || []),
        parasiteDistribution: formatParasiteData(distributionResponse.data || []),
        technicianPerformance: formatPerformanceData(performanceResponse.data || []),
        weeklyStats: formatWeeklyData(comprehensiveResponse.data?.weekly || []),
        monthlyComparison: formatMonthlyData(comprehensiveResponse.data?.monthly || [])
      });

    } catch (err) {
      console.error('Analytics fetch error:', err);
      setError('Failed to load analytics data');
      
      // Use mock data if API fails
      setAnalyticsData(getMockAnalyticsData());
    } finally {
      setLoading(false);
    }
  };

  // Data formatting functions
  const formatTrendsData = (data) => {
    return data.map(item => ({
      name: formatDate(item.date),
      tests: item.totalTests || 0,
      positive: item.positiveTests || 0,
      negative: item.negativeTests || 0,
      value: item.totalTests || 0
    }));
  };

  const formatParasiteData = (data) => {
    return data.map(item => ({
      name: getParasiteName(item.type),
      value: item.count || 0,
      percentage: item.percentage || 0
    }));
  };

  const formatPerformanceData = (data) => {
    return data.map(item => ({
      name: item.technicianName || 'Unknown',
      tests: item.testsProcessed || 0,
      accuracy: item.accuracy || 0,
      avgTime: item.averageProcessingTime || 0,
      value: item.testsProcessed || 0
    }));
  };

  const formatWeeklyData = (data) => {
    return data.map(item => ({
      name: `Week ${item.week}`,
      tests: item.tests || 0,
      positive: item.positive || 0,
      efficiency: item.efficiency || 0
    }));
  };

  const formatMonthlyData = (data) => {
    return data.map(item => ({
      name: item.month,
      current: item.currentYear || 0,
      previous: item.previousYear || 0
    }));
  };

  // Helper functions
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  const getParasiteName = (type) => {
    const names = {
      'PF': 'P. falciparum',
      'PV': 'P. vivax', 
      'PM': 'P. malariae',
      'PO': 'P. ovale'
    };
    return names[type] || type;
  };

  // Mock data for fallback
  const getMockAnalyticsData = () => ({
    testTrends: [
      { name: 'Jul 1', tests: 45, positive: 8, negative: 37, value: 45 },
      { name: 'Jul 2', tests: 52, positive: 12, negative: 40, value: 52 },
      { name: 'Jul 3', tests: 38, positive: 6, negative: 32, value: 38 },
      { name: 'Jul 4', tests: 61, positive: 15, negative: 46, value: 61 },
      { name: 'Jul 5', tests: 47, positive: 9, negative: 38, value: 47 },
      { name: 'Jul 6', tests: 55, positive: 11, negative: 44, value: 55 },
      { name: 'Jul 7', tests: 49, positive: 7, negative: 42, value: 49 }
    ],
    parasiteDistribution: [
      { name: 'P. falciparum', value: 65, percentage: 65 },
      { name: 'P. vivax', value: 23, percentage: 23 },
      { name: 'P. malariae', value: 8, percentage: 8 },
      { name: 'P. ovale', value: 4, percentage: 4 }
    ],
    technicianPerformance: [
      { name: 'Maria Garcia', tests: 127, accuracy: 96, avgTime: 45, value: 127 },
      { name: 'James Wilson', tests: 89, accuracy: 94, avgTime: 52, value: 89 },
      { name: 'Sarah Chen', tests: 76, accuracy: 98, avgTime: 41, value: 76 },
      { name: 'David Park', tests: 103, accuracy: 92, avgTime: 48, value: 103 }
    ],
    weeklyStats: [
      { name: 'Week 1', tests: 234, positive: 45, efficiency: 92 },
      { name: 'Week 2', tests: 267, positive: 52, efficiency: 94 },
      { name: 'Week 3', tests: 198, positive: 38, efficiency: 89 },
      { name: 'Week 4', tests: 312, positive: 61, efficiency: 96 }
    ],
    monthlyComparison: [
      { name: 'Jan', current: 1245, previous: 1089 },
      { name: 'Feb', current: 1367, previous: 1156 },
      { name: 'Mar', current: 1456, previous: 1278 },
      { name: 'Apr', current: 1523, previous: 1345 },
      { name: 'May', current: 1612, previous: 1423 },
      { name: 'Jun', current: 1734, previous: 1567 },
      { name: 'Jul', current: 1456, previous: 1398 }
    ]
  });

  if (showCompactView) {
    return (
      <CompactAnalyticsView 
        data={analyticsData}
        loading={loading}
        className={className}
      />
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Chart Selector */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Analytics Overview</h3>
          <div className="flex items-center space-x-2">
            {[
              { key: 'trends', label: 'Test Trends', icon: TrendingUp },
              { key: 'distribution', label: 'Parasite Types', icon: Target },
              { key: 'performance', label: 'Performance', icon: Users },
              { key: 'comparison', label: 'Comparison', icon: BarChart3 }
            ].map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setActiveChart(key)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                  activeChart === key
                    ? 'bg-blue-500 text-white'
                    : 'text-blue-300 hover:text-white hover:bg-white/10'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Active Chart */}
      <div className="grid grid-cols-1 gap-6">
        {activeChart === 'trends' && (
          <MultiMetricChart
            datasets={[
              {
                key: 'tests',
                name: 'Total Tests',
                data: analyticsData.testTrends
              },
              {
                key: 'positive',
                name: 'Positive Tests',
                data: analyticsData.testTrends
              },
              {
                key: 'negative',
                name: 'Negative Tests', 
                data: analyticsData.testTrends
              }
            ]}
            loading={loading}
            title="Test Trends Over Time"
          />
        )}

        {activeChart === 'distribution' && (
          <StatisticsChart
            data={analyticsData.parasiteDistribution}
            loading={loading}
            title="Parasite Type Distribution"
            type="pie"
            height={400}
          />
        )}

        {activeChart === 'performance' && (
          <StatisticsChart
            data={analyticsData.technicianPerformance}
            loading={loading}
            title="Technician Performance"
            type="bar"
            height={350}
          />
        )}

        {activeChart === 'comparison' && (
          <StatisticsChart
            data={analyticsData.monthlyComparison}
            loading={loading}
            title="Monthly Comparison (Current vs Previous Year)"
            type="bar"
            height={350}
          />
        )}
      </div>

      {/* Quick Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <QuickStatCard
          title="Weekly Average"
          value={Math.round(analyticsData.weeklyStats.reduce((sum, week) => sum + week.tests, 0) / analyticsData.weeklyStats.length) || 0}
          subtitle="tests per week"
          icon={Calendar}
          loading={loading}
        />
        
        <QuickStatCard
          title="Detection Rate"
          value={`${Math.round((analyticsData.testTrends.reduce((sum, day) => sum + day.positive, 0) / analyticsData.testTrends.reduce((sum, day) => sum + day.tests, 0)) * 100) || 0}%`}
          subtitle="positive detection rate"
          icon={Target}
          loading={loading}
        />
        
        <QuickStatCard
          title="Avg Processing Time"
          value={`${Math.round(analyticsData.technicianPerformance.reduce((sum, tech) => sum + tech.avgTime, 0) / analyticsData.technicianPerformance.length) || 0}min`}
          subtitle="per test"
          icon={Clock}
          loading={loading}
        />
      </div>
    </div>
  );
};

// Quick stat card component
const QuickStatCard = ({ title, value, subtitle, icon: Icon, loading }) => {
  if (loading) {
    return (
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 animate-pulse">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="h-4 bg-white/20 rounded w-3/4 mb-2"></div>
            <div className="h-6 bg-white/20 rounded w-1/2 mb-1"></div>
            <div className="h-3 bg-white/20 rounded w-2/3"></div>
          </div>
          <div className="w-10 h-10 bg-white/20 rounded-lg"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-blue-200 text-sm font-medium">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          <p className="text-blue-300 text-xs">{subtitle}</p>
        </div>
        <div className="bg-blue-500 p-2 rounded-lg">
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  );
};

// Compact view for smaller spaces
const CompactAnalyticsView = ({ data, loading, className }) => {
  if (loading) {
    return (
      <div className={`space-y-4 ${className}`}>
        {Array.from({ length: 2 }).map((_, index) => (
          <StatisticsChartSkeleton key={index} height={200} />
        ))}
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      <TestTrendsChart
        data={data.testTrends}
        loading={loading}
        height={200}
        showFilters={false}
      />
      <ParasiteDistributionChart
        data={data.parasiteDistribution}
        loading={loading}
        height={200}
        showFilters={false}
      />
    </div>
  );
};

export default AnalyticsSection;
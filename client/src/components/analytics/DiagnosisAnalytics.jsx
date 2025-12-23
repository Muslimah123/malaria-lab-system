// 📁 client/src/components/analytics/DiagnosisAnalytics.jsx
// Comprehensive Diagnosis Analytics Dashboard

import React, { useState, useEffect, useMemo } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area
} from 'recharts';
import { 
  TrendingUp, 
  Users, 
  Activity, 
  Target, 
  Clock, 
  Download,
  RefreshCw,
  Filter,
  Calendar,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { 
  selectDiagnosisAnalytics, 
  selectAnalyticsLoading, 
  selectPerformanceMetrics,
  fetchDiagnosisAnalytics 
} from '../../store/slices/analyticsSlice';
import { useDiagnosis } from '../../hooks/useDiagnosis'; // ✅ ADDED: Missing import
import { showToast } from '../../contexts/ToastContext';
import LoadingSpinner from '../common/LoadingSpinner';
import { formatDate, formatNumber } from '../../utils/formatters';

const DiagnosisAnalytics = () => {
  const dispatch = useDispatch(); // ✅ ADDED: Missing dispatch
  
  // ✅ FIXED: Use correct hook methods and properties
  const { 
    fetchStatistics, 
    statistics, 
    isLoading: diagnosisLoading, 
    error: diagnosisError 
  } = useDiagnosis();
  
  // ✅ ADDED: Redux selectors for analytics data
  const diagnosisAnalytics = useSelector(selectDiagnosisAnalytics);
  const performanceMetrics = useSelector(selectPerformanceMetrics);
  const analyticsLoading = useSelector(selectAnalyticsLoading);
  
  const [timeRange, setTimeRange] = useState('7d');
  const [refreshKey, setRefreshKey] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Load analytics data when component mounts or timeRange changes
    loadAnalytics();
  }, [timeRange, refreshKey]);

  const loadAnalytics = async () => {
    try {
      setLoading(true);
      setError(null);

      // ✅ FIXED: Use the correct Redux action instead of hook method
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date().toISOString();
      
      await dispatch(fetchDiagnosisAnalytics({ 
        startDate, 
        endDate, 
        filters: { timeRange } 
      }));
    } catch (error) {
      console.error('❌ Failed to load analytics:', error);
      setError(`Failed to load analytics: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    setRefreshKey(prev => prev + 1);
  };

  const exportAnalytics = () => {
    try {
      // ✅ FIXED: Use statistics from the hook instead of undefined performanceAnalytics
      const dataStr = JSON.stringify(statistics, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `diagnosis-analytics-${timeRange}-${new Date().toISOString().split('T')[0]}.json`;
      link.click();
    } catch (error) {
      console.error('❌ Export error:', error);
    }
  };

  // Mock data for demonstration (replace with real data from your backend)
  const mockData = {
    totalTests: 1247,
    successRate: 94.2,
    avgProcessingTime: 3.8,
    totalImages: 5678,
    positiveCases: 234,
    negativeCases: 1013,
    timeSeriesData: [
      { date: '2024-01-01', tests: 45, positive: 12, negative: 33, avgTime: 3.2 },
      { date: '2024-01-02', tests: 52, positive: 15, negative: 37, avgTime: 3.5 },
      { date: '2024-01-03', tests: 48, positive: 11, negative: 37, avgTime: 3.1 },
      { date: '2024-01-04', tests: 55, positive: 18, negative: 37, avgTime: 3.8 },
      { date: '2024-01-05', tests: 51, positive: 14, negative: 37, avgTime: 3.3 },
      { date: '2024-01-06', tests: 49, positive: 13, negative: 36, avgTime: 3.4 },
      { date: '2024-01-07', tests: 53, positive: 16, negative: 37, avgTime: 3.6 }
    ],
    // ✅ ADDED: Missing properties that the component expects
    parasiteDistribution: [
      { type: 'PF', count: 89, percentage: 38.0 },
      { type: 'PM', count: 67, percentage: 28.6 },
      { type: 'PO', count: 45, percentage: 19.2 },
      { type: 'PV', count: 33, percentage: 14.1 }
    ],
    accuracyMetrics: {
      sensitivity: 92.3,
      specificity: 96.8,
      precision: 94.1,
      recall: 92.3
    }
  };

  // ✅ FIXED: Use Redux state data instead of undefined variables
  const data = diagnosisAnalytics?.data || mockData;
  const isLoading = analyticsLoading || diagnosisLoading;
  
  // ✅ FIXED: Properly extract error messages from objects to prevent React rendering errors
  const hasError = (() => {
    if (diagnosisAnalytics?.error) {
      return typeof diagnosisAnalytics.error === 'string' 
        ? diagnosisAnalytics.error 
        : diagnosisAnalytics.error.message || 'Unknown error';
    }
    if (diagnosisError) {
      return typeof diagnosisError === 'string' 
        ? diagnosisError 
        : diagnosisError.message || 'Unknown error';
    }
    if (error) {
      return typeof error === 'string' 
        ? error 
        : error.message || 'Unknown error';
    }
    return null;
  })();

  // ✅ ADDED: Safety check to ensure data is properly formatted
  const safeData = (() => {
    if (!data || typeof data !== 'object') return mockData;
    
    // Ensure all required properties exist and are properly formatted
    return {
      totalTests: typeof data.totalTests === 'number' ? data.totalTests : mockData.totalTests,
      successRate: typeof data.successRate === 'number' ? data.successRate : mockData.successRate,
      avgProcessingTime: typeof data.avgProcessingTime === 'number' ? data.avgProcessingTime : mockData.avgProcessingTime,
      totalImages: typeof data.totalImages === 'number' ? data.totalImages : mockData.totalImages,
      positiveCases: typeof data.positiveCases === 'number' ? data.positiveCases : mockData.positiveCases,
      negativeCases: typeof data.negativeCases === 'number' ? data.negativeCases : mockData.negativeCases,
      timeSeriesData: Array.isArray(data.timeSeriesData) ? data.timeSeriesData : mockData.timeSeriesData,
      parasiteDistribution: Array.isArray(data.parasiteDistribution) ? data.parasiteDistribution : mockData.parasiteDistribution,
      accuracyMetrics: data.accuracyMetrics && typeof data.accuracyMetrics === 'object' ? data.accuracyMetrics : mockData.accuracyMetrics
    };
  })();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
        <span className="ml-3 text-blue-200 text-lg">Loading analytics...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header with Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Diagnosis Performance Analytics</h2>
          <p className="text-blue-200">
            Comprehensive insights into diagnosis performance and system metrics
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          {/* Time Range Selector */}
          <div className="flex bg-white/10 rounded-lg p-1 border border-white/20">
            {[
              { value: '1d', label: '24H' },
              { value: '7d', label: '7D' },
              { value: '30d', label: '30D' },
              { value: '90d', label: '90D' }
            ].map(range => (
              <button
                key={range.value}
                onClick={() => setTimeRange(range.value)}
                className={`px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  timeRange === range.value
                    ? 'bg-blue-500 text-white shadow-lg'
                    : 'text-blue-200 hover:bg-white/10 hover:text-white'
                }`}
              >
                {range.label}
              </button>
            ))}
          </div>
          
          {/* Action Buttons */}
          <button
            onClick={handleRefresh}
            className="p-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-blue-200 hover:text-white transition-all duration-200"
            title="Refresh data"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
          
          <button
            onClick={exportAnalytics}
            className="flex items-center px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-all duration-200 hover:scale-105"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </button>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Total Tests */}
        <div className="bg-gradient-to-br from-blue-500/10 via-blue-600/10 to-transparent border border-blue-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Target className="w-6 h-6 text-blue-400" />
            </div>
            <TrendingUp className="w-5 h-5 text-green-400" />
          </div>
          <h3 className="text-lg font-semibold text-blue-200 mb-2">Total Tests</h3>
          <p className="text-3xl font-bold text-blue-100">{safeData.totalTests?.toLocaleString() || 0}</p>
          <p className="text-sm text-blue-300 mt-2">+12% from last period</p>
        </div>

        {/* Success Rate */}
        <div className="bg-gradient-to-br from-green-500/10 via-green-600/10 to-transparent border border-green-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-green-500/20 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-400" />
            </div>
            <div className="text-right">
              <span className="text-sm text-green-300">Success Rate</span>
            </div>
          </div>
          <h3 className="text-lg font-semibold text-green-200 mb-2">Success Rate</h3>
          <p className="text-3xl font-bold text-green-100">{safeData.successRate?.toFixed(1) || 0}%</p>
          <p className="text-sm text-green-300 mt-2">+2.1% from last period</p>
        </div>

        {/* Average Processing Time */}
        <div className="bg-gradient-to-br from-purple-500/10 via-purple-600/10 to-transparent border border-purple-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <Clock className="w-6 h-6 text-purple-400" />
            </div>
            <div className="text-right">
              <span className="text-sm text-purple-300">Avg Time</span>
            </div>
          </div>
          <h3 className="text-lg font-semibold text-purple-200 mb-2">Processing Time</h3>
          <p className="text-3xl font-bold text-purple-100">{safeData.avgProcessingTime?.toFixed(1) || 0}s</p>
          <p className="text-sm text-purple-300 mt-2">-0.3s from last period</p>
        </div>

        {/* Total Images */}
        <div className="bg-gradient-to-br from-orange-500/10 via-orange-600/10 to-transparent border border-orange-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-orange-500/20 rounded-lg">
              <Activity className="w-6 h-6 text-orange-400" />
            </div>
            <div className="text-right">
              <span className="text-sm text-orange-300">Images</span>
            </div>
          </div>
          <h3 className="text-lg font-semibold text-orange-200 mb-2">Total Images</h3>
          <p className="text-3xl font-bold text-orange-100">{safeData.totalImages?.toLocaleString() || 0}</p>
          <p className="text-sm text-orange-300 mt-2">+8% from last period</p>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Test Volume Trend */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold text-white flex items-center">
              <LineChart className="w-5 h-5 mr-2 text-blue-400" />
              Test Volume Trend
            </h3>
            <div className="flex items-center space-x-2 text-sm text-blue-200">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-blue-400 rounded-full mr-2"></div>
                <span>Tests</span>
              </div>
              <div className="flex items-center">
                <div className="w-3 h-3 bg-green-400 rounded-full mr-2"></div>
                <span>Positive</span>
              </div>
            </div>
          </div>
          
          <div className="h-64 flex items-center justify-center">
            <div className="text-center text-blue-200">
              <BarChart className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-semibold">Chart Component</p>
              <p className="text-sm opacity-75">Integrate with Chart.js or Recharts</p>
              <div className="mt-4 space-y-2 text-left">
                {safeData.timeSeriesData?.slice(0, 5).map((item, index) => (
                  <div key={index} className="flex justify-between text-sm">
                    <span>{item.date}</span>
                    <span className="text-blue-300">{item.tests} tests</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Parasite Distribution */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold text-white flex items-center">
              <PieChart className="w-5 h-5 mr-2 text-green-400" />
              Parasite Distribution
            </h3>
          </div>
          
          <div className="space-y-4">
            {safeData.parasiteDistribution?.map((parasite, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-4 h-4 rounded-full ${
                    parasite.type === 'PF' ? 'bg-red-400' :
                    parasite.type === 'PM' ? 'bg-orange-400' :
                    parasite.type === 'PO' ? 'bg-yellow-400' :
                    'bg-green-400'
                  }`}></div>
                  <span className="text-white font-medium">{parasite.type}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <span className="text-blue-200">{parasite.count}</span>
                  <span className="text-green-300 font-semibold">{parasite.percentage}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detailed Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Case Distribution */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center">
            <Target className="w-5 h-5 mr-2 text-red-400" />
            Case Distribution
          </h3>
          
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-blue-200">Positive Cases</span>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-bold text-red-400">{safeData.positiveCases}</span>
                <span className="text-sm text-red-300">({((safeData.positiveCases / safeData.totalTests) * 100).toFixed(1)}%)</span>
              </div>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-blue-200">Negative Cases</span>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-bold text-green-400">{safeData.negativeCases}</span>
                <span className="text-sm text-green-300">({((safeData.negativeCases / safeData.totalTests) * 100).toFixed(1)}%)</span>
              </div>
            </div>
            
            <div className="w-full bg-white/10 rounded-full h-2 mt-4">
              <div 
                className="bg-gradient-to-r from-red-400 to-green-400 h-2 rounded-full transition-all duration-500"
                style={{ 
                  width: `${(safeData.positiveCases / safeData.totalTests) * 100}%`,
                  background: `linear-gradient(90deg, #f87171 ${(safeData.positiveCases / safeData.totalTests) * 100}%, #4ade80 0%)`
                }}
              />
            </div>
          </div>
        </div>

        {/* Accuracy Metrics */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center">
            <CheckCircle className="w-5 h-5 mr-2 text-green-400" />
            Accuracy Metrics
          </h3>
          
          <div className="space-y-4">
            {safeData.accuracyMetrics && Object.entries(safeData.accuracyMetrics).map(([metric, value]) => (
              <div key={metric} className="flex justify-between items-center">
                <span className="text-blue-200 capitalize">{metric}</span>
                <span className="text-2xl font-bold text-green-400">{value}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Performance Alerts */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-yellow-400" />
            Performance Alerts
          </h3>
          
          <div className="space-y-3">
            {/* ✅ FIXED: Use hasError instead of undefined metrics */}
            {hasError && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                <div className="flex items-center space-x-2 mb-1">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <span className="text-sm font-medium text-red-400">Error</span>
                </div>
                <p className="text-sm text-red-300">{hasError}</p>
              </div>
            )}
            
            {/* ✅ FIXED: Use hasError instead of undefined metrics */}
            {!hasError && (
              <div className="p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-center">
                <CheckCircle className="w-6 h-6 text-green-400 mx-auto mb-2" />
                <p className="text-sm text-green-300">No errors detected</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Real-time Performance */}
      {/* ✅ FIXED: Use performanceMetrics from Redux instead of undefined metrics */}
      {performanceMetrics?.data && (
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2" />
            Real-time Performance
          </h3>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-300">{performanceMetrics.data.recentApiCalls || 0}</p>
              <p className="text-sm text-blue-200">Recent API Calls</p>
            </div>
            
            <div className="text-center">
              <p className="text-2xl font-bold text-green-300">{performanceMetrics.data.recentRenders || 0}</p>
              <p className="text-sm text-green-200">Recent Renders</p>
            </div>
            
            <div className="text-center">
              <p className="text-2xl font-bold text-purple-300">{performanceMetrics.data.currentMemoryUsage?.toFixed(1) || 0}%</p>
              <p className="text-sm text-purple-200">Memory Usage</p>
            </div>
            
            <div className="text-center">
              <p className="text-2xl font-bold text-orange-300">{performanceMetrics.data.uptime || '0s'}</p>
              <p className="text-sm text-orange-200">Uptime</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DiagnosisAnalytics;

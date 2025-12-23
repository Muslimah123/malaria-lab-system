// 📁 client/src/components/admin/PerformanceDashboard.jsx
// Comprehensive System Performance Dashboard

import React, { useState, useEffect, useMemo } from 'react';
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
  CheckCircle,
  Cpu,
  Memory,
  HardDrive,
  Wifi,
  Zap,
  Play,
  Pause,
  RotateCcw
} from 'lucide-react';
import { showToast } from '../../contexts/ToastContext';
import { formatDate, formatNumber } from '../../utils/formatters';

const PerformanceDashboard = () => {
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [metrics, setMetrics] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(5000);
  const [selectedTimeframe, setSelectedTimeframe] = useState('1h');

  useEffect(() => {
    // Load initial metrics
    loadMetrics();
    
    // Set up auto-refresh
    const interval = setInterval(() => {
      if (isMonitoring) {
        loadMetrics();
      }
    }, refreshInterval);
    
    return () => clearInterval(interval);
  }, [isMonitoring, refreshInterval]);

  const loadMetrics = async () => {
    try {
      // ✅ REVERTED: Back to mock data instead of API calls
      const mockMetrics = {
        systemHealth: 'Operational',
        uptime: '99.9%',
        activeUsers: Math.floor(Math.random() * 20) + 5,
        performanceScore: 'A+',
        cpuUsage: Math.floor(Math.random() * 30) + 20,
        memoryUsage: Math.floor(Math.random() * 40) + 30,
        diskUsage: Math.floor(Math.random() * 20) + 10,
        networkLatency: Math.floor(Math.random() * 50) + 10,
        apiResponseTime: Math.floor(Math.random() * 200) + 50,
        errorRate: Math.floor(Math.random() * 2),
        throughput: Math.floor(Math.random() * 1000) + 500,
        
        // ✅ COMPLETE: All required session properties
        session: {
          durationFormatted: '2h 15m',
          startTime: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          totalInteractions: Math.floor(Math.random() * 50) + 10,
          duration: 2 * 60 * 60 * 1000 // Duration in milliseconds
        },
        
        // ✅ COMPLETE: All required user properties
        user: {
          totalInteractions: Math.floor(Math.random() * 100) + 20,
          recentInteractions: [
            {
              action: 'Page View',
              timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
              details: { page: '/dashboard' }
            },
            {
              action: 'Button Click',
              timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
              details: { button: 'refresh' }
            }
          ]
        },
        
        // ✅ COMPLETE: All required api properties
        api: {
          successRate: Math.floor(Math.random() * 20) + 80,
          totalCalls: Math.floor(Math.random() * 1000) + 500,
          averageResponseTime: Math.floor(Math.random() * 500) + 100,
          fastestCall: Math.floor(Math.random() * 50) + 20,
          successfulCalls: Math.floor(Math.random() * 800) + 400,
          failedCalls: Math.floor(Math.random() * 200) + 50,
          slowestCall: Math.floor(Math.random() * 1000) + 500
        },
        
        // ✅ COMPLETE: All required rendering properties
        rendering: {
          averageRenderTime: Math.floor(Math.random() * 10) + 8,
          totalRenders: Math.floor(Math.random() * 500) + 200
        },
        
        // ✅ COMPLETE: All required memory properties
        memory: {
          usagePercent: Math.floor(Math.random() * 30) + 50,
          currentUsage: Math.floor(Math.random() * 500 * 1024 * 1024) + 200 * 1024 * 1024,
          averageUsage: Math.floor(Math.random() * 20) + 45,
          currentTotal: Math.floor(Math.random() * 1000 * 1024 * 1024) + 500 * 1024 * 1024,
          currentLimit: Math.floor(Math.random() * 2000 * 1024 * 1024) + 1000 * 1024 * 1024
        },
        
        // ✅ COMPLETE: All required errors properties
        errors: {
          totalErrors: Math.floor(Math.random() * 10) + 2,
          errorTypes: {
            'API Error': Math.floor(Math.random() * 5) + 1,
            'Validation Error': Math.floor(Math.random() * 3) + 1,
            'Network Error': Math.floor(Math.random() * 2) + 1
          },
          recentErrors: [
            {
              type: 'API Error',
              timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
              details: { message: 'Request timeout' },
              url: '/api/analytics',
              userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          ]
        }
      };
      
      setMetrics(mockMetrics);
    } catch (error) {
      console.error('❌ Failed to load metrics:', error);
    }
  };

  const handleStartMonitoring = () => {
    setIsMonitoring(true);
  };

  const handleStopMonitoring = () => {
    setIsMonitoring(false);
  };

  const handleResetMetrics = () => {
    setMetrics(null);
    loadMetrics();
  };

  const exportMetrics = () => {
    try {
      const exportData = {
        metrics: metrics,
        exportTime: new Date().toISOString(),
        exportSource: 'Performance Dashboard',
        monitoringStatus: isMonitoring,
        refreshInterval: refreshInterval,
        timeframe: selectedTimeframe
      };
      
      const dataStr = JSON.stringify(exportData, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `performance-metrics-${new Date().toISOString().split('T')[0]}.json`;
      link.click();
    } catch (error) {
      console.error('❌ Export error:', error);
    }
  };

  const getStatusColor = (value, threshold = 80) => {
    if (value >= threshold) return 'text-red-400';
    if (value >= threshold * 0.7) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getStatusIcon = (value, threshold = 80) => {
    if (value >= threshold) return <AlertTriangle className="w-4 h-4 text-red-400" />;
    if (value >= threshold * 0.7) return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
    return <CheckCircle className="w-4 h-4 text-green-400" />;
  };

  if (!metrics) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
        <span className="ml-3 text-blue-200 text-lg">Performance metrics not available.</span>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header with Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">System Performance Dashboard</h2>
          <p className="text-blue-200">
            Real-time monitoring of system performance, API calls, and resource usage
          </p>
          
          {/* ✅ ADDED: Data source indicator */}
          <div className="flex items-center space-x-4 mt-2 text-sm">
            <div className={`flex items-center space-x-2 px-3 py-1 rounded-full ${
              'mock' 
                ? 'bg-green-500/20 text-green-300 border border-green-500/30' 
                : 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
            }`}>
              <div className={`w-2 h-2 rounded-full ${
                'mock' ? 'bg-green-400' : 'bg-yellow-400'
              }`}></div>
              <span>
                Mock Data
              </span>
            </div>
            
            {/* Removed last update display as it's not available in mock data */}
          </div>
        </div>
        
        <div className="flex items-center space-x-3">
          {/* Monitoring Controls */}
          <div className="flex bg-white/10 rounded-lg p-1 border border-white/20">
            <button
              onClick={handleStartMonitoring}
              disabled={isMonitoring}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                isMonitoring
                  ? 'bg-green-500 text-white'
                  : 'text-green-200 hover:bg-white/10 hover:text-white'
              }`}
            >
              <Play className="w-4 h-4 inline mr-1" />
              Start
            </button>
            <button
              onClick={handleStopMonitoring}
              disabled={!isMonitoring}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                !isMonitoring
                  ? 'bg-red-500 text-white'
                  : 'text-red-200 hover:bg-white/10 hover:text-white'
              }`}
            >
              <Pause className="w-4 h-4 inline mr-1" />
              Stop
            </button>
          </div>
          
          {/* Refresh Interval */}
          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            className="px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-blue-200 text-sm"
          >
            <option value={1000}>1s</option>
            <option value={5000}>5s</option>
            <option value={10000}>10s</option>
            <option value={30000}>30s</option>
          </select>
          
          {/* Action Buttons */}
          <button
            onClick={loadMetrics}
            className="p-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-blue-200 hover:text-white transition-all duration-200"
            title="Refresh metrics"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
          
          <button
            onClick={handleResetMetrics}
            className="p-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-red-200 hover:text-white transition-all duration-200"
            title="Reset metrics"
          >
            <RotateCcw className="w-5 h-5" />
          </button>
          
          <button
            onClick={exportMetrics}
            className="flex items-center px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-all duration-200 hover:scale-105"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </button>
        </div>
      </div>

      {/* Session Information */}
      <div className="bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-transparent border border-blue-500/20 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-bold text-blue-300 flex items-center">
            <Clock className="w-5 h-5 mr-2" />
            Session Information
          </h3>
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isMonitoring ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`}></div>
            <span className="text-sm text-blue-200">
              {isMonitoring ? 'Monitoring Active' : 'Monitoring Paused'}
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-100">{metrics.session.durationFormatted}</p>
            <p className="text-sm text-blue-200">Session Duration</p>
          </div>
          
          <div className="text-center">
            <p className="text-2xl font-bold text-green-100">
              {metrics.session.startTime ? new Date(metrics.session.startTime).toLocaleTimeString() : 'N/A'}
            </p>
            <p className="text-sm text-green-200">Session Start</p>
          </div>
          
          <div className="text-center">
            <p className="text-2xl font-bold text-purple-100">
              {metrics.user.totalInteractions}
            </p>
            <p className="text-sm text-purple-200">User Interactions</p>
          </div>
        </div>
      </div>

      {/* Performance Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* API Performance */}
        <div className="bg-gradient-to-br from-blue-500/10 via-blue-600/10 to-transparent border border-blue-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Activity className="w-6 h-6 text-blue-400" />
            </div>
            {getStatusIcon(metrics.api.successRate, 90)}
          </div>
          <h3 className="text-lg font-semibold text-blue-200 mb-2">API Success Rate</h3>
          <p className={`text-3xl font-bold ${getStatusColor(metrics.api.successRate, 90)}`}>
            {metrics.api.successRate.toFixed(1)}%
          </p>
          <p className="text-sm text-blue-300 mt-2">
            {metrics.api.totalCalls} total calls
          </p>
        </div>

        {/* API Response Time */}
        <div className="bg-gradient-to-br from-green-500/10 via-green-600/10 to-transparent border border-green-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-green-500/20 rounded-lg">
              <Clock className="w-6 h-6 text-green-400" />
            </div>
            {getStatusIcon(metrics.api.averageResponseTime, 5000)}
          </div>
          <h3 className="text-lg font-semibold text-green-200 mb-2">Avg Response Time</h3>
          <p className={`text-3xl font-bold ${getStatusColor(metrics.api.averageResponseTime, 5000)}`}>
            {metrics.api.averageResponseTime.toFixed(1)}ms
          </p>
          <p className="text-sm text-green-300 mt-2">
            Fastest: {metrics.api.fastestCall.toFixed(1)}ms
          </p>
        </div>

        {/* Render Performance */}
        <div className="bg-gradient-to-br from-purple-500/10 via-purple-600/10 to-transparent border border-purple-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <TrendingUp className="w-6 h-6 text-purple-400" />
            </div>
            {getStatusIcon(metrics.rendering.averageRenderTime, 16)}
          </div>
          <h3 className="text-lg font-semibold text-purple-200 mb-2">Avg Render Time</h3>
          <p className={`text-3xl font-bold ${getStatusColor(metrics.rendering.averageRenderTime, 16)}`}>
            {metrics.rendering.averageRenderTime.toFixed(1)}ms
          </p>
          <p className="text-sm text-purple-300 mt-2">
            {metrics.rendering.totalRenders} total renders
          </p>
        </div>

        {/* Memory Usage */}
        <div className="bg-gradient-to-br from-orange-500/10 via-orange-600/10 to-transparent border border-orange-500/20 rounded-xl p-6 hover:scale-105 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-orange-500/20 rounded-lg">
              <HardDrive className="w-6 h-6 text-orange-400" />
            </div>
            {getStatusIcon(metrics.memory.usagePercent, 80)}
          </div>
          <h3 className="text-lg font-semibold text-orange-200 mb-2">Memory Usage</h3>
          <p className={`text-3xl font-bold ${getStatusColor(metrics.memory.usagePercent, 80)}`}>
            {metrics.memory.usagePercent.toFixed(1)}%
          </p>
          <p className="text-sm text-orange-300 mt-2">
            {(metrics.memory.currentUsage / 1024 / 1024).toFixed(1)} MB
          </p>
        </div>
      </div>

      {/* Detailed Performance Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* API Call Distribution */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-6 flex items-center">
            <LineChart className="w-5 h-5 mr-2 text-blue-400" />
            API Call Performance
          </h3>
          
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-blue-200">Total Calls</span>
              <span className="text-white font-bold">{metrics.api.totalCalls}</span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-green-200">Successful</span>
              <span className="text-green-400 font-bold">{metrics.api.successfulCalls}</span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-red-200">Failed</span>
              <span className="text-red-400 font-bold">{metrics.api.failedCalls}</span>
            </div>
            
            <div className="w-full bg-white/10 rounded-full h-2">
              <div 
                className="bg-gradient-to-r from-green-400 to-blue-400 h-2 rounded-full transition-all duration-500"
                style={{ width: `${(metrics.api.successfulCalls / metrics.api.totalCalls) * 100}%` }}
              />
            </div>
            
            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <p className="text-2xl font-bold text-blue-300">{metrics.api.slowestCall.toFixed(1)}ms</p>
                <p className="text-sm text-blue-200">Slowest Call</p>
              </div>
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <p className="text-2xl font-bold text-green-300">{metrics.api.fastestCall.toFixed(1)}ms</p>
                <p className="text-sm text-green-200">Fastest Call</p>
              </div>
            </div>
          </div>
        </div>

        {/* Memory Usage Trend */}
        <div className="bg-white/5 border border-white/20 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-6 flex items-center">
            <HardDrive className="w-5 h-5 mr-2 text-orange-400" />
            Memory Usage Trend
          </h3>
          
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-orange-200">Current Usage</span>
              <span className="text-orange-400 font-bold">{metrics.memory.usagePercent.toFixed(1)}%</span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-blue-200">Average Usage</span>
              <span className="text-blue-400 font-bold">{metrics.memory.averageUsage.toFixed(1)}%</span>
            </div>
            
            <div className="w-full bg-white/10 rounded-full h-2">
              <div 
                className="bg-gradient-to-r from-orange-400 to-red-400 h-2 rounded-full transition-all duration-500"
                style={{ width: `${metrics.memory.usagePercent}%` }}
              />
            </div>
            
            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <p className="text-lg font-bold text-blue-300">
                  {(metrics.memory.currentTotal / 1024 / 1024).toFixed(1)} MB
                </p>
                <p className="text-sm text-blue-200">Total Allocated</p>
              </div>
              <div className="text-center p-3 bg-white/5 rounded-lg">
                <p className="text-lg font-bold text-green-300">
                  {(metrics.memory.currentLimit / 1024 / 1024).toFixed(1)} MB
                </p>
                <p className="text-sm text-green-200">Memory Limit</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Error Monitoring */}
      <div className="bg-white/5 border border-white/20 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-6 flex items-center">
          <AlertTriangle className="w-5 h-5 mr-2 text-yellow-400" />
          Error Monitoring
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="text-center p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
            <p className="text-3xl font-bold text-red-400">{metrics.errors.totalErrors}</p>
            <p className="text-sm text-red-200">Total Errors</p>
          </div>
          
          <div className="text-center p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
            <p className="text-3xl font-bold text-yellow-400">
              {Object.keys(metrics.errors.errorTypes).length}
            </p>
            <p className="text-sm text-yellow-200">Error Types</p>
          </div>
          
          <div className="text-center p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <p className="text-3xl font-bold text-blue-400">
              {metrics.errors.recentErrors.length}
            </p>
            <p className="text-sm text-blue-200">Recent Errors</p>
          </div>
        </div>
        
        {/* Error Types Breakdown */}
        <div className="mb-6">
          <h4 className="text-md font-semibold text-white mb-4">Error Types Distribution</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(metrics.errors.errorTypes).map(([type, count]) => (
              <div key={type} className="p-3 bg-white/5 border border-white/10 rounded-lg text-center">
                <p className="text-lg font-bold text-red-400">{count}</p>
                <p className="text-sm text-blue-200">{type}</p>
              </div>
            ))}
          </div>
        </div>
        
        {/* Recent Errors */}
        <div>
          <h4 className="text-md font-semibold text-white mb-4">Recent Errors</h4>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {metrics.errors.recentErrors.map((error, index) => (
              <div key={index} className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-red-300">{error.type}</span>
                  <span className="text-xs text-red-400">
                    {new Date(error.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-red-200 mb-2">
                  {error.details?.message || error.details?.error || 'No details available'}
                </p>
                <div className="text-xs text-red-300 space-y-1">
                  <p>URL: {error.url}</p>
                  <p>User Agent: {error.userAgent?.substring(0, 50)}...</p>
                </div>
              </div>
            ))}
            
            {metrics.errors.recentErrors.length === 0 && (
              <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-center">
                <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                <p className="text-green-300">No recent errors detected</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* User Interactions */}
      <div className="bg-white/5 border border-white/20 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-6 flex items-center">
          <Activity className="w-5 h-5 mr-2 text-purple-400" />
          User Interaction Analytics
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-md font-semibold text-white mb-4">Recent Interactions</h4>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {metrics.user.recentInteractions.map((interaction, index) => (
                <div key={index} className="p-3 bg-white/5 border border-white/10 rounded-lg">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-purple-300">{interaction.action}</span>
                    <span className="text-xs text-blue-300">
                      {new Date(interaction.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  {Object.keys(interaction.details).length > 0 && (
                    <p className="text-xs text-blue-200">
                      {JSON.stringify(interaction.details)}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
          
          <div>
            <h4 className="text-md font-semibold text-white mb-4">Interaction Summary</h4>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-blue-200">Total Interactions</span>
                <span className="text-white font-bold">{metrics.user.totalInteractions}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-green-200">Session Duration</span>
                <span className="text-green-400 font-bold">{metrics.session.durationFormatted}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <span className="text-purple-200">Avg Interaction Rate</span>
                <span className="text-purple-400 font-bold">
                  {metrics.user.totalInteractions > 0 
                    ? (metrics.user.totalInteractions / (metrics.session.duration / 1000 / 60)).toFixed(2)
                    : 0
                  } per minute
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PerformanceDashboard;

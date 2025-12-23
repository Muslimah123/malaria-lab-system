// 📁 client/src/pages/AnalyticsPage.jsx
// Simplified Analytics Dashboard

import React, { useState, useEffect } from 'react';
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
  Cell
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
  CheckCircle,
  Settings
} from 'lucide-react';
import DiagnosisAnalytics from '../components/analytics/DiagnosisAnalytics';
import PerformanceDashboard from '../components/admin/PerformanceDashboard';
import Header from '../components/common/Header';
import Sidebar from '../components/common/Sidebar';

const AnalyticsPage = () => {
  const [activeTab, setActiveTab] = useState('diagnosis');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30000); // 30 seconds
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    // Set up auto-refresh
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        setLastRefresh(new Date());
        // Trigger refresh of components
        window.dispatchEvent(new CustomEvent('analytics-refresh'));
      }, refreshInterval);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh, refreshInterval]);

  const handleRefresh = () => {
    setLastRefresh(new Date());
    window.dispatchEvent(new CustomEvent('analytics-refresh'));
  };

  const exportAllData = () => {
    // Export analytics data
    const allData = {
      diagnosisAnalytics: 'Available in Diagnosis Analytics section',
      exportTime: new Date().toISOString(),
      exportSource: 'Analytics Page'
    };
    
    const dataStr = JSON.stringify(allData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `analytics-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
  };

  const tabs = [
    {
      id: 'diagnosis',
      label: 'Diagnosis Analytics',
      icon: <Target className="w-5 h-5" />,
      description: 'Comprehensive diagnosis performance insights'
    },
    {
      id: 'performance',
      label: 'System Performance',
      icon: <Activity className="w-5 h-5" />,
      description: 'Real-time system monitoring and metrics'
    },
    {
      id: 'overview',
      label: 'Overview Dashboard',
      icon: <BarChart className="w-5 h-5" />,
      description: 'High-level system overview and alerts'
    }
  ];

  const renderOverviewDashboard = () => (
    <div className="space-y-8">
      {/* System Health Overview */}
      <div className="bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-transparent border border-blue-500/20 rounded-xl p-6">
        <h3 className="text-lg font-bold text-blue-300 mb-6 flex items-center">
          <CheckCircle className="w-5 h-5 mr-2" />
          System Health Overview
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* System Status */}
          <div className="text-center p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
            <div className="w-4 h-4 bg-green-400 rounded-full mx-auto mb-2 animate-pulse"></div>
            <p className="text-lg font-bold text-green-400">Operational</p>
            <p className="text-sm text-green-200">All systems normal</p>
          </div>
          
          {/* Uptime */}
          <div className="text-center p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <Clock className="w-8 h-8 text-blue-400 mx-auto mb-2" />
            <p className="text-lg font-bold text-blue-400">99.9%</p>
            <p className="text-sm text-blue-200">System Uptime</p>
          </div>
          
          {/* Active Users */}
          <div className="text-center p-4 bg-purple-500/10 border border-purple-500/20 rounded-lg">
            <Activity className="w-8 h-8 text-purple-400 mx-auto mb-2" />
            <p className="text-lg font-bold text-purple-400">12</p>
            <p className="text-sm text-purple-200">Active Users</p>
          </div>
          
          {/* Performance Score */}
          <div className="text-center p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg">
            <TrendingUp className="w-8 h-8 text-orange-400 mx-auto mb-2" />
            <p className="text-lg font-bold text-orange-400">A+</p>
            <p className="text-sm text-orange-200">Performance</p>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white/5 border border-white/20 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-6 flex items-center">
          <Settings className="w-5 h-5 mr-2" />
          Quick Actions
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={() => setActiveTab('diagnosis')}
            className="p-4 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg text-left transition-all duration-200 hover:scale-105"
          >
            <Target className="w-6 h-6 text-blue-400 mb-2" />
            <h4 className="font-semibold text-blue-200">View Diagnosis Analytics</h4>
            <p className="text-sm text-blue-300">Detailed diagnosis performance insights</p>
          </button>
          
          <button
            onClick={() => setActiveTab('performance')}
            className="p-4 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-lg text-left transition-all duration-200 hover:scale-105"
          >
            <Activity className="w-6 h-6 text-green-400 mb-2" />
            <h4 className="font-semibold text-green-200">Monitor System Performance</h4>
            <p className="text-sm text-green-300">Real-time system metrics and alerts</p>
          </button>
          
          <button
            onClick={exportAllData}
            className="p-4 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 rounded-lg text-left transition-all duration-200 hover:scale-105"
          >
            <Download className="w-6 h-6 text-purple-400 mb-2" />
            <h4 className="font-semibold text-purple-200">Export All Data</h4>
            <p className="text-sm text-purple-300">Download comprehensive analytics report</p>
          </button>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white/5 border border-white/20 rounded-xl p-6">
        <h3 className="text-lg font-bold text-white mb-6 flex items-center">
          <Activity className="w-5 h-5 mr-2" />
          Recent System Activity
        </h3>
        
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-white/5 border border-white/10 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
              <span className="text-blue-200">System health check completed</span>
            </div>
            <span className="text-sm text-blue-300">2 minutes ago</span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-white/5 border border-white/10 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
              <span className="text-blue-200">New diagnosis test completed</span>
            </div>
            <span className="text-sm text-blue-300">5 minutes ago</span>
          </div>
          
          <div className="flex items-center justify-between p-3 bg-white/5 border border-white/10 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
              <span className="text-blue-200">Performance metrics updated</span>
            </div>
            <span className="text-sm text-blue-300">8 minutes ago</span>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 flex">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        onClose={() => setSidebarOpen(false)} 
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-64">
        {/* Header */}
        <Header
          title="Analytics Dashboard"
          subtitle="Comprehensive insights into diagnosis performance and system metrics"
          onMenuClick={() => setSidebarOpen(true)}
          showSearch={false}
          showNotifications={true}
        />

        {/* Main Content Area */}
        <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 overflow-y-auto pt-24">
          <div className="max-w-7xl mx-auto space-y-8">
            {/* Page Header */}
            <div className="text-center">
              <h1 className="text-4xl font-bold text-white mb-4">Analytics Dashboard</h1>
              <p className="text-blue-200 text-lg mb-6">
                Comprehensive insights into diagnosis performance and system metrics
              </p>
              
              {/* Last Refresh Info */}
              <div className="flex items-center justify-center space-x-4 text-sm text-blue-300">
                <span>Last updated: {lastRefresh.toLocaleTimeString()}</span>
                {autoRefresh && (
                  <span className="flex items-center">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
                    Auto-refresh active
                  </span>
                )}
              </div>
            </div>

            {/* Controls Bar */}
            <div className="bg-white/5 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
              <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
                {/* Tab Navigation */}
                <div className="flex space-x-1 bg-white/10 rounded-lg p-1 border border-white/20">
                  {tabs.map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 flex items-center space-x-2 ${
                        activeTab === tab.id
                          ? 'bg-blue-500 text-white shadow-lg'
                          : 'text-blue-200 hover:bg-white/10 hover:text-white'
                      }`}
                    >
                      {tab.icon}
                      <span>{tab.label}</span>
                    </button>
                  ))}
                </div>
                
                {/* Control Buttons */}
                <div className="flex items-center space-x-3">
                  {/* Auto-refresh Toggle */}
                  <button
                    onClick={() => setAutoRefresh(!autoRefresh)}
                    className={`flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                      autoRefresh
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        : 'bg-white/10 text-blue-200 border border-white/20 hover:bg-white/20'
                    }`}
                  >
                    <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
                    Auto-refresh
                  </button>
                  
                  {/* Refresh Interval */}
                  <select
                    value={refreshInterval}
                    onChange={(e) => setRefreshInterval(Number(e.target.value))}
                    className="px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-blue-200 text-sm"
                  >
                    <option value={10000}>10s</option>
                    <option value={30000}>30s</option>
                    <option value={60000}>1m</option>
                    <option value={300000}>5m</option>
                  </select>
                  
                  {/* Manual Refresh */}
                  <button
                    onClick={handleRefresh}
                    className="p-3 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-blue-200 hover:text-white transition-all duration-200"
                    title="Manual refresh"
                  >
                    <RefreshCw className="w-5 h-5" />
                  </button>
                  
                  {/* Export All */}
                  <button
                    onClick={exportAllData}
                    className="flex items-center px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg transition-all duration-200 hover:scale-105"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Export All
                  </button>
                </div>
              </div>
            </div>

            {/* Tab Content */}
            <div className="bg-white/5 backdrop-blur-xl border border-white/20 rounded-2xl p-8">
              {activeTab === 'diagnosis' && (
                <div>
                  <div className="mb-6">
                    <h2 className="text-2xl font-bold text-white mb-2">Diagnosis Analytics</h2>
                    <p className="text-blue-200">{tabs.find(t => t.id === 'diagnosis')?.description}</p>
                  </div>
                  <DiagnosisAnalytics />
                </div>
              )}
              
              {activeTab === 'performance' && (
                <div>
                  <div className="mb-6">
                    <h2 className="text-2xl font-bold text-white mb-2">System Performance</h2>
                    <p className="text-blue-200">{tabs.find(t => t.id === 'performance')?.description}</p>
                  </div>
                  <PerformanceDashboard />
                </div>
              )}
              
              {activeTab === 'overview' && (
                <div>
                  <div className="mb-6">
                    <h2 className="text-2xl font-bold text-white mb-2">Overview Dashboard</h2>
                    <p className="text-blue-200">{tabs.find(t => t.id === 'overview')?.description}</p>
                  </div>
                  {renderOverviewDashboard()}
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default AnalyticsPage;

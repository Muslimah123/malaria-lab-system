// src/components/dashboard/DashboardOverview.jsx
import React from 'react';
import { 
  Microscope, 
  Users, 
  Clock, 
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity
} from 'lucide-react';

const DashboardOverview = ({ data, loading }) => {
  // ✅ DEBUG: Log data for troubleshooting
  console.log('🔍 DashboardOverview data:', data);
  console.log('🔍 DashboardOverview loading:', loading);

  if (loading || !data) {
    console.log('🔍 DashboardOverview: Showing loading state');
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 animate-pulse">
            <div className="flex items-center justify-between mb-4">
              <div className="h-8 w-8 bg-white/20 rounded-lg"></div>
              <div className="h-4 w-16 bg-white/20 rounded"></div>
            </div>
            <div className="h-6 w-20 bg-white/20 rounded mb-2"></div>
            <div className="h-4 w-24 bg-white/20 rounded"></div>
          </div>
        ))}
      </div>
    );
  }

  const overviewItems = [
    {
      title: "Today's Tests",
      value: data.todayTests || 0,
      change: data.todayChange || "+0%",
      trend: "up",
      icon: Microscope,
      color: "bg-blue-500",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-500/20"
    },
    {
      title: "Positive Results",
      value: data.positiveToday || 0,
      change: data.positiveChange || "+0%",
      trend: data.positiveChange?.includes('-') ? "down" : "up",
      icon: AlertTriangle,
      color: "bg-red-500",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/20"
    },
    {
      title: "Pending Review",
      value: data.pendingReview || 0,
      change: data.pendingChange || "+0%",
      trend: "up",
      icon: Clock,
      color: "bg-yellow-500",
      bgColor: "bg-yellow-500/10",
      borderColor: "border-yellow-500/20"
    },
    {
      title: "Active Patients",
      value: data.activePatients || 0,
      change: data.patientsChange || "+0%",
      trend: "up",
      icon: Users,
      color: "bg-green-500",
      bgColor: "bg-green-500/10",
      borderColor: "border-green-500/20"
    }
  ];

  const getTrendIcon = (trend) => {
    if (trend === "up") {
      return <TrendingUp className="h-4 w-4 text-green-400" />;
    }
    return <TrendingUp className="h-4 w-4 text-red-400 transform rotate-180" />;
  };

  const getStatusColor = (trend) => {
    return trend === "up" ? "text-green-400" : "text-red-400";
  };

  return (
    <div className="mb-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Dashboard Overview</h2>
          <p className="text-blue-200">Key metrics and system status</p>
        </div>
        <div className="flex items-center space-x-2 text-blue-300 text-sm">
          <Activity className="h-4 w-4" />
          <span>Last updated: {data.lastUpdated ? 
            new Date(data.lastUpdated).toLocaleTimeString() : 
            'Never'
          }</span>
        </div>
      </div>

      {/* Overview Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {overviewItems.map((item, index) => (
          <div 
            key={index}
            className={`${item.bgColor} ${item.borderColor} backdrop-blur-md border rounded-lg p-6 hover:scale-105 transition-all duration-300 cursor-pointer group`}
            onClick={() => {
              const routes = [
                '/tests?filter=today',
                '/results?filter=positive', 
                '/tests?status=pending',
                '/patients'
              ];
              window.location.href = routes[index];
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className={`${item.color} p-3 rounded-lg group-hover:scale-110 transition-transform duration-300`}>
                <item.icon className="h-6 w-6 text-white" />
              </div>
              <div className="flex items-center space-x-1">
                {getTrendIcon(item.trend)}
                <span className={`text-xs font-medium ${getStatusColor(item.trend)}`}>
                  {item.change}
                </span>
              </div>
            </div>
            
            <div className="mb-2">
              <div className="text-3xl font-bold text-white mb-1">
                {item.value.toLocaleString()}
              </div>
              <div className="text-blue-200 text-sm font-medium">
                {item.title}
              </div>
            </div>

            {/* Progress bar */}
            <div className="w-full bg-white/20 rounded-full h-2">
              <div 
                className={`${item.color} h-2 rounded-full transition-all duration-500`}
                style={{ width: `${Math.min((item.value / Math.max(data.todayTests || 1, 1)) * 100, 100)}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Status Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
        {/* System Status */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-4">
            <div className="bg-green-500 p-2 rounded-lg">
              <CheckCircle className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white">System Status</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-blue-200 text-sm">Database</span>
              <span className="text-green-400 text-sm flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                Online
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-blue-200 text-sm">ML Service</span>
              <span className="text-green-400 text-sm flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                Active
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-blue-200 text-sm">File Storage</span>
              <span className="text-green-400 text-sm flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                Available
              </span>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-4">
            <div className="bg-blue-500 p-2 rounded-lg">
              <Activity className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white">Recent Activity</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Tests Today</span>
              <span className="text-white font-medium">{data.todayTests || 0}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Positive Rate</span>
              <span className="text-white font-medium">
                {data.todayTests && data.positiveToday ? 
                  `${((data.positiveToday / data.todayTests) * 100).toFixed(1)}%` : 
                  '0%'
                }
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Avg. Processing</span>
              <span className="text-white font-medium">2.3 min</span>
            </div>
          </div>
        </div>

        {/* Alerts Summary */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-4">
            <div className="bg-red-500 p-2 rounded-lg">
              <AlertTriangle className="h-5 w-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white">Alerts</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Critical</span>
              <span className="text-red-400 font-medium">
                {data.urgentAlerts?.filter(alert => alert.severity === 'critical').length || 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Warnings</span>
              <span className="text-yellow-400 font-medium">
                {data.urgentAlerts?.filter(alert => alert.severity === 'warning').length || 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-blue-200">Info</span>
              <span className="text-blue-400 font-medium">
                {data.urgentAlerts?.filter(alert => alert.severity === 'info').length || 0}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;


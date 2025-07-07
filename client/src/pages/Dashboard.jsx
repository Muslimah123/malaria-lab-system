import React, { useEffect, useState, useMemo } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { 
  Activity, 
  Users, 
  TestTube, 
  AlertTriangle, 
  TrendingUp, 
  Clock,
  Upload,
  FileText,
  Settings,
  RefreshCw
} from 'lucide-react';

import { selectUser, selectUserRole } from '../store/slices/authSlice';
import { showErrorToast } from '../store/slices/notificationsSlice';
import apiService from '../services/api';
import socketService from '../services/socketService';

import DashboardCard from '../components/dashboard/DashboardCard';
import QuickActions from '../components/dashboard/QuickActions';
import TestSummary from '../components/dashboard/TestSummary';
import RecentActivity from '../components/dashboard/RecentActivity';
import StatisticsChart from '../components/dashboard/StatisticsChart';
import CriticalAlerts from '../components/dashboard/CriticalAlerts';
import LoadingSpinner from '../components/common/LoadingSpinner';

import { ROUTES, USER_ROLES, TEST_STATUSES } from '../utils/constants';

const Dashboard = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const user = useSelector(selectUser);
  const userRole = useSelector(selectUserRole);

  // Dashboard state
  const [dashboardData, setDashboardData] = useState({
    stats: null,
    recentTests: [],
    criticalAlerts: [],
    todayActivity: [],
    isLoading: true,
    error: null,
    lastUpdated: null
  });

  const [refreshing, setRefreshing] = useState(false);
  const [timeRange, setTimeRange] = useState('today'); // today, week, month

  // Real-time data updates
  useEffect(() => {
    fetchDashboardData();
    
    // Set up periodic refresh
    const refreshInterval = setInterval(() => {
      if (document.visibilityState === 'visible') {
        fetchDashboardData(true); // Silent refresh
      }
    }, 30000); // Refresh every 30 seconds

    // Listen for real-time updates
    setupSocketListeners();

    return () => {
      clearInterval(refreshInterval);
      cleanupSocketListeners();
    };
  }, [timeRange]);

  const fetchDashboardData = async (silent = false) => {
    try {
      if (!silent) {
        setDashboardData(prev => ({ ...prev, isLoading: true, error: null }));
      } else {
        setRefreshing(true);
      }

      // Parallel API calls for better performance
      const [statsResponse, recentTestsResponse, alertsResponse] = await Promise.all([
        apiService.dashboard.getStats(),
        apiService.tests.getAll({ 
          limit: 10, 
          sortBy: 'createdAt', 
          sortOrder: 'desc',
          ...(userRole === USER_ROLES.TECHNICIAN && { technicianId: user._id })
        }),
        apiService.dashboard.getAlerts?.() || Promise.resolve({ data: { alerts: [] } })
      ]);

      const stats = statsResponse.data.data || statsResponse.data;
      const recentTests = recentTestsResponse.data.data?.tests || [];
      const criticalAlerts = alertsResponse.data.data?.alerts || [];

      // Calculate additional metrics
      const enhancedStats = enhanceStats(stats, recentTests);

      setDashboardData({
        stats: enhancedStats,
        recentTests,
        criticalAlerts,
        isLoading: false,
        error: null,
        lastUpdated: new Date().toISOString()
      });

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      
      setDashboardData(prev => ({
        ...prev,
        isLoading: false,
        error: apiService.handleApiError(error)
      }));

      if (!silent) {
        dispatch(showErrorToast('Failed to load dashboard data'));
      }
    } finally {
      setRefreshing(false);
    }
  };

  const enhanceStats = (stats, recentTests) => {
    // Calculate trends and additional metrics
    const today = new Date().toDateString();
    const todayTests = recentTests.filter(test => 
      new Date(test.createdAt).toDateString() === today
    );

    const processingTests = recentTests.filter(test => 
      test.status === TEST_STATUSES.PROCESSING
    );

    const urgentTests = recentTests.filter(test => 
      test.priority === 'urgent' && test.status === TEST_STATUSES.PENDING
    );

    return {
      ...stats,
      todayTests: todayTests.length,
      processingTests: processingTests.length,
      urgentTests: urgentTests.length,
      averageProcessingTime: calculateAverageProcessingTime(recentTests),
      positivityRate: stats.totalTests > 0 ? 
        ((stats.positiveTests / stats.totalTests) * 100).toFixed(1) : 0
    };
  };

  const calculateAverageProcessingTime = (tests) => {
    const completedTests = tests.filter(test => 
      test.status === TEST_STATUSES.COMPLETED && test.processingTime
    );

    if (completedTests.length === 0) return 0;

    const totalTime = completedTests.reduce((sum, test) => sum + test.processingTime, 0);
    return Math.round(totalTime / completedTests.length / 1000 / 60); // Convert to minutes
  };

  const setupSocketListeners = () => {
    socketService.on('testCreated', handleTestUpdate);
    socketService.on('testUpdated', handleTestUpdate);
    socketService.on('diagnosisCompleted', handleDiagnosisCompleted);
    socketService.on('positiveResult', handlePositiveResult);
  };

  const cleanupSocketListeners = () => {
    socketService.off('testCreated', handleTestUpdate);
    socketService.off('testUpdated', handleTestUpdate);
    socketService.off('diagnosisCompleted', handleDiagnosisCompleted);
    socketService.off('positiveResult', handlePositiveResult);
  };

  const handleTestUpdate = (data) => {
    // Refresh dashboard data when tests are updated
    fetchDashboardData(true);
  };

  const handleDiagnosisCompleted = (data) => {
    // Update stats and recent tests
    fetchDashboardData(true);
  };

  const handlePositiveResult = (data) => {
    // Add to critical alerts if it's a severe case
    if (data.severity === 'severe') {
      setDashboardData(prev => ({
        ...prev,
        criticalAlerts: [{
          id: Date.now(),
          type: 'positive_result',
          message: `Severe malaria detected in test ${data.testId}`,
          testId: data.testId,
          patientId: data.patientId,
          timestamp: new Date().toISOString(),
          priority: 'critical'
        }, ...prev.criticalAlerts.slice(0, 4)] // Keep only 5 alerts
      }));
    }
  };

  const handleRefresh = () => {
    fetchDashboardData(false);
  };

  const handleQuickAction = (action) => {
    switch (action) {
      case 'upload':
        navigate(ROUTES.UPLOAD);
        break;
      case 'results':
        navigate(ROUTES.RESULTS);
        break;
      case 'history':
        navigate(ROUTES.HISTORY);
        break;
      case 'settings':
        navigate(ROUTES.SETTINGS);
        break;
      default:
        break;
    }
  };

  // Memoized computed values
  const dashboardCards = useMemo(() => {
    if (!dashboardData.stats) return [];

    const baseCards = [
      {
        title: 'Today\'s Tests',
        value: dashboardData.stats.todayTests || 0,
        subtitle: 'Tests processed today',
        icon: TestTube,
        trend: { value: 12, isPositive: true },
        color: 'primary',
        onClick: () => navigate(ROUTES.HISTORY)
      },
      {
        title: 'Positive Results',
        value: dashboardData.stats.positiveTests || 0,
        subtitle: `${dashboardData.stats.positivityRate}% positivity rate`,
        icon: AlertTriangle,
        trend: { value: 5, isPositive: false },
        color: 'danger',
        onClick: () => navigate(`${ROUTES.RESULTS}?status=positive`)
      },
      {
        title: 'Processing Queue',
        value: dashboardData.stats.processingTests || 0,
        subtitle: 'Tests in progress',
        icon: Clock,
        color: 'warning',
        onClick: () => navigate(`${ROUTES.HISTORY}?status=processing`)
      },
      {
        title: 'Avg. Processing',
        value: `${dashboardData.stats.averageProcessingTime || 0}m`,
        subtitle: 'Average completion time',
        icon: TrendingUp,
        trend: { value: 8, isPositive: true },
        color: 'success'
      }
    ];

    // Add role-specific cards
    if (userRole === USER_ROLES.SUPERVISOR || userRole === USER_ROLES.ADMIN) {
      baseCards.push({
        title: 'Total Patients',
        value: dashboardData.stats.totalPatients || 0,
        subtitle: 'Registered patients',
        icon: Users,
        color: 'secondary',
        onClick: () => navigate(ROUTES.PATIENTS)
      });
    }

    if (dashboardData.stats.urgentTests > 0) {
      baseCards.unshift({
        title: 'Urgent Tests',
        value: dashboardData.stats.urgentTests,
        subtitle: 'Require immediate attention',
        icon: AlertTriangle,
        color: 'danger',
        priority: 'high',
        onClick: () => navigate(`${ROUTES.HISTORY}?priority=urgent`)
      });
    }

    return baseCards;
  }, [dashboardData.stats, userRole, navigate]);

  if (dashboardData.isLoading && !dashboardData.stats) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <LoadingSpinner size="xl" />
          <p className="mt-4 text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Welcome back, {user?.firstName || user?.username}
          </h1>
          <p className="mt-1 text-sm text-gray-600">
            {new Date().toLocaleDateString('en-US', { 
              weekday: 'long', 
              year: 'numeric', 
              month: 'long', 
              day: 'numeric' 
            })}
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-4">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="btn btn-outline btn-sm"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {dashboardData.lastUpdated && (
            <span className="text-xs text-gray-500">
              Last updated: {new Date(dashboardData.lastUpdated).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Error State */}
      {dashboardData.error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 text-red-400 mr-2" />
            <span className="text-red-800">{dashboardData.error}</span>
            <button
              onClick={handleRefresh}
              className="ml-auto text-red-600 hover:text-red-800"
            >
              Try Again
            </button>
          </div>
        </div>
      )}

      {/* Critical Alerts */}
      {dashboardData.criticalAlerts.length > 0 && (
        <CriticalAlerts 
          alerts={dashboardData.criticalAlerts}
          onAlertClick={(alert) => navigate(`/results/${alert.testId}`)}
        />
      )}

      {/* Quick Stats Cards */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {dashboardCards.map((card, index) => (
          <DashboardCard
            key={index}
            {...card}
            loading={refreshing}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Quick Actions */}
        <div className="lg:col-span-1">
          <QuickActions
            userRole={userRole}
            onAction={handleQuickAction}
            stats={dashboardData.stats}
          />
        </div>

        {/* Statistics Chart */}
        <div className="lg:col-span-2">
          <StatisticsChart
            timeRange={timeRange}
            onTimeRangeChange={setTimeRange}
            data={dashboardData.stats}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Tests Summary */}
        <TestSummary
          tests={dashboardData.recentTests}
          loading={refreshing}
          onViewAll={() => navigate(ROUTES.HISTORY)}
          onTestClick={(test) => navigate(`/results/${test.testId}`)}
        />

        {/* Recent Activity */}
        <RecentActivity
          activities={dashboardData.todayActivity}
          loading={refreshing}
          userRole={userRole}
        />
      </div>
    </div>
  );
};

export default Dashboard;
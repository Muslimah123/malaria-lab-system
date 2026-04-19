// // src/pages/Dashboard.jsx
// import React, { useState, useEffect } from 'react';
// import { useSelector, useDispatch } from 'react-redux';
// import { 
//   Microscope,
//   Clock,
//   TrendingUp,
//   Users,
//   AlertTriangle
// } from 'lucide-react';

// // Store imports
// import { selectUser, selectIsAuthenticated } from '../store/slices/authSlice';
// import { useAuthToken } from '../hooks/useAuthToken';
// import { selectNotifications } from '../store/slices/notificationsSlice';
// import { 
//   selectDashboardData, 
//   selectDashboardLoading, 
//   selectDashboardError,
//   selectDashboardStats,
//   selectRecentTests,
//   selectUrgentAlerts,
//   selectSystemStatus,
//   fetchDashboardData,
//   fetchAnalyticsData,
//   updateRealtimeData,
//   dismissAlert,
//   clearDashboardError
// } from '../store/slices/dashboardSlice';

// // Component imports
// import Header from '../components/common/Header';
// import Sidebar from '../components/common/Sidebar';
// import DashboardOverview from '../components/dashboard/DashboardOverview';
// import QuickActions, { QuickActionsSkeleton } from '../components/dashboard/QuickActions';
// import TestSummary, { TestSummarySkeleton } from '../components/dashboard/TestSummary';
// import CriticalAlerts, { CriticalAlertsSkeleton } from '../components/dashboard/CriticalAlerts';
// import AnalyticsSection from '../components/dashboard/AnalyticsSection';
// import LoadingSpinner from '../components/common/LoadingSpinner';
// import Toast from '../components/common/Toast';

// // Services and hooks
// import socketService from '../services/socketService';
// import { showErrorToast, showSuccessToast } from '../store/slices/notificationsSlice';

// const Dashboard = () => {
//   const dispatch = useDispatch();
  
//   // Redux state
//   const user = useSelector(selectUser);
//   const isAuthenticated = useSelector(selectIsAuthenticated);
  
//   // Ensure auth token is properly set
//   const { tokenSetRef } = useAuthToken();
//   const notifications = useSelector(selectNotifications);
//   const dashboardData = useSelector(selectDashboardData);
//   const loading = useSelector(selectDashboardLoading);
//   const error = useSelector(selectDashboardError);
//   const stats = useSelector(selectDashboardStats);
//   const recentTests = useSelector(selectRecentTests);
//   const urgentAlerts = useSelector(selectUrgentAlerts);
//   const systemStatus = useSelector(selectSystemStatus);

//   // ✅ DEBUG: Log dashboard data for troubleshooting
//   useEffect(() => {
//     console.log('🔍 Dashboard Debug:', {
//       isAuthenticated,
//       tokenSetRef: !!tokenSetRef,
//       dashboardData: !!dashboardData,
//       loading,
//       error,
//       dataKeys: dashboardData ? Object.keys(dashboardData) : 'No data',
//       stats: stats,
//       recentTests: recentTests,
//       urgentAlerts: urgentAlerts
//     });
//   }, [isAuthenticated, tokenSetRef, dashboardData, loading, error, stats, recentTests, urgentAlerts]);

//   // Local state
//   const [sidebarOpen, setSidebarOpen] = useState(false);
//   const [socketConnected, setSocketConnected] = useState(false);
//   const [realtimeUpdates, setRealtimeUpdates] = useState(true);

//   // Initialize dashboard
//   useEffect(() => {
//     if (isAuthenticated && tokenSetRef) {
//       console.log('🔄 Initializing dashboard...');
//       console.log('🔍 Auth state:', { isAuthenticated, tokenSetRef });
//       dispatch(fetchDashboardData());
//       dispatch(fetchAnalyticsData({ timeRange: '30days' }));
//       initializeSocket();
//     } else {
//       console.log('❌ Dashboard not initialized:', { isAuthenticated, tokenSetRef });
//     }
//   }, [isAuthenticated, tokenSetRef, dispatch]);

//   // Add retry mechanism for failed dashboard loads
//   useEffect(() => {
//     if (error && !dashboardData) {
//       console.log('🔄 Retrying dashboard data fetch due to error...');
//       const retryTimer = setTimeout(() => {
//         dispatch(fetchDashboardData());
//       }, 2000);
//       return () => clearTimeout(retryTimer);
//     }
//   }, [error, dashboardData, dispatch]);

//   // ✅ FIXED: Add periodic refresh to keep dashboard data current
//   useEffect(() => {
//     if (isAuthenticated && tokenSetRef) {
//       console.log('🔄 Setting up periodic dashboard refresh...');
//       const refreshInterval = setInterval(() => {
//         console.log('🔄 Periodic dashboard refresh...');
//         dispatch(fetchDashboardData());
//       }, 30000); // Refresh every 30 seconds
      
//       return () => {
//         console.log('🔄 Clearing periodic dashboard refresh...');
//         clearInterval(refreshInterval);
//       };
//     }
//   }, [isAuthenticated, tokenSetRef, dispatch]);

//   // Initialize socket connection
//   const initializeSocket = () => {
//     const token = localStorage.getItem('authToken');
    
//     if (token) {
//       socketService.safeConnect(token);
      
//       socketService.socket?.on('connect', () => {
//         setSocketConnected(true);
//         console.log('Socket connected');
//       });

//       socketService.socket?.on('disconnect', () => {
//         setSocketConnected(false);
//         console.log('Socket disconnected');
//       });

//       // Subscribe to real-time updates
//       socketService.subscribeToTestUpdates((testUpdate) => {
//         if (realtimeUpdates) {
//           handleTestUpdate(testUpdate);
//         }
//       });

//       socketService.subscribeToNotifications(user?.id, (notification) => {
//         dispatch(showSuccessToast(notification.message));
//       });
//     }
//   };

//   // Handle real-time test updates
//   const handleTestUpdate = (testUpdate) => {
//     console.log('🔄 Test update received:', testUpdate);
    
//     if (testUpdate.status === 'completed') {
//       // Update Redux state with real-time data
//       dispatch(updateRealtimeData({
//         type: 'test_completed',
//         data: testUpdate
//       }));
      
//       // ✅ FIXED: Refresh dashboard data when a test is completed
//       console.log('🔄 Test completed, refreshing dashboard data...');
//       dispatch(fetchDashboardData());
      
//       if (testUpdate.result === 'positive' && testUpdate.severity === 'severe') {
//         dispatch(showErrorToast(
//           `Critical: Severe malaria detected in ${testUpdate.patientName}`,
//           { 
//             actionUrl: `/results/${testUpdate.testId}`,
//             duration: 10000 
//           }
//         ));
        
//         // Add urgent alert
//         dispatch(updateRealtimeData({
//           type: 'urgent_alert',
//           data: {
//             type: 'critical_result',
//             message: `Severe malaria detected in ${testUpdate.patientName}`,
//             severity: 'critical',
//             patientName: testUpdate.patientName
//           }
//         }));
//       }
//     }
//   };

//   // Handle refresh
//   const handleRefresh = () => {
//     dispatch(fetchDashboardData());
//     dispatch(fetchAnalyticsData({ timeRange: '30days' }));
//   };

//   // Handle errors
//   useEffect(() => {
//     if (error) {
//       dispatch(showErrorToast(error));
//       dispatch(clearDashboardError());
//     }
//   }, [error, dispatch]);

//   // Show initial loading state
//   if (loading && !dashboardData) {
//     return (
//       <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
//         <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-8 flex items-center space-x-4">
//           <LoadingSpinner size="lg" color="white" />
//           <span className="text-white text-lg">Loading dashboard...</span>
//         </div>
//       </div>
//     );
//   }

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex">
//       {/* Sidebar */}
//       <Sidebar 
//         isOpen={sidebarOpen} 
//         onClose={() => setSidebarOpen(false)} 
//       />

//       {/* Main Content */}
//       <div className="flex-1 flex flex-col min-w-0">
//         {/* Header */}
//         <Header
//           title="Dashboard"
//           subtitle={`Welcome back, ${user?.firstName || user?.name || 'User'}`}
//           onMenuClick={() => setSidebarOpen(true)}
//           onRefresh={handleRefresh}
//           socketConnected={socketConnected}
//           showSearch={true}
//           showNotifications={true}
//         />

//         {/* Main Content Area */}
//         <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 overflow-y-auto">
//           {/* Dashboard Overview - Only render once */}
//           {dashboardData && (
//             <DashboardOverview data={dashboardData} loading={loading} />
//           )}

//           {/* Main Content Grid */}
//           <div className="grid grid-cols-1 xl:grid-cols-3 gap-8 mb-8">
//             {/* Left Column - Recent Tests */}
//             <div className="xl:col-span-2">
//               <TestSummary
//                 tests={recentTests}
//                 loading={loading}
//                 title="Recent Tests"
//                 showViewAll={true}
//                 onViewAll={() => window.location.href = '/tests'}
//                 onTestClick={(test) => window.location.href = `/tests/${test.id}`}
//               />
//             </div>

//             {/* Right Column - Sidebar Content */}
//             <div className="space-y-6">
//               {/* Quick Actions */}
//               {loading ? (
//                 <QuickActionsSkeleton />
//               ) : (
//                 <QuickActions />
//               )}

//               {/* Critical Alerts & System Status */}
//               {loading ? (
//                 <CriticalAlertsSkeleton />
//               ) : (
//                 <CriticalAlerts
//                   alerts={urgentAlerts}
//                   systemStatus={{
//                     ...systemStatus,
//                     realtime: socketConnected
//                   }}
//                   onAlertDismiss={(alertId) => {
//                     dispatch(dismissAlert(alertId));
//                   }}
//                 />
//               )}
//             </div>
//           </div>

//           {/* Analytics Section */}
//           <div className="mb-8">
//             <AnalyticsSection 
//               timeRange="30days"
//               showCompactView={user?.role === 'technician'} // Show compact view for technicians
//             />
//           </div>

//           {/* Footer Info */}
//           <div className="mt-8 text-center">
//             <p className="text-blue-300 text-sm">
//               Last updated: {dashboardData?.lastUpdated ? 
//                 new Date(dashboardData.lastUpdated).toLocaleString() : 
//                 'Never'
//               }
//             </p>
//             <p className="text-blue-400 text-xs mt-1">
//               {socketConnected ? '🟢 Real-time updates active' : '🔴 Real-time updates offline'}
//             </p>
//           </div>
//         </main>
//       </div>

//       {/* Toast Notifications */}
//       <Toast />
//     </div>
//   );
// };

// export default Dashboard;
// src/pages/Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  Microscope,
  Clock,
  TrendingUp,
  Users,
  AlertTriangle
} from 'lucide-react';

// Store imports
import { selectUser, selectIsAuthenticated } from '../store/slices/authSlice';
import { selectNotifications } from '../store/slices/notificationsSlice';
import { 
  selectDashboardData, 
  selectDashboardLoading, 
  selectDashboardError,
  selectDashboardStats,
  selectRecentTests,
  selectUrgentAlerts,
  selectSystemStatus,
  fetchDashboardData,
  fetchAnalyticsData,
  updateRealtimeData,
  dismissAlert,
  clearDashboardError
} from '../store/slices/dashboardSlice';

// Component imports
import Header from '../components/common/Header';
import Sidebar from '../components/common/Sidebar';
import DashboardCard, { DashboardCardGrid, DashboardCardSkeleton } from '../components/dashboard/DashboardCard';
import QuickActions, { QuickActionsSkeleton } from '../components/dashboard/QuickActions';
import TestSummary, { TestSummarySkeleton } from '../components/dashboard/TestSummary';
import CriticalAlerts, { CriticalAlertsSkeleton } from '../components/dashboard/CriticalAlerts';
import AnalyticsSection from '../components/dashboard/AnalyticsSection';
import TATWidget from '../components/dashboard/TATWidget';
import LoadingSpinner from '../components/common/LoadingSpinner';
import Toast from '../components/common/Toast';

// Services and hooks
import socketService from '../services/socketService';
import { showErrorToast, showSuccessToast } from '../store/slices/notificationsSlice';

const Dashboard = () => {
  const dispatch = useDispatch();
  
  // Redux state
  const user = useSelector(selectUser);
  const isAuthenticated = useSelector(selectIsAuthenticated);
  const notifications = useSelector(selectNotifications);
  const dashboardData = useSelector(selectDashboardData);
  const loading = useSelector(selectDashboardLoading);
  const error = useSelector(selectDashboardError);
  const stats = useSelector(selectDashboardStats);
  const recentTests = useSelector(selectRecentTests);
  const urgentAlerts = useSelector(selectUrgentAlerts);
  const systemStatus = useSelector(selectSystemStatus);

  // Local state
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [socketConnected, setSocketConnected] = useState(false);
  const [realtimeUpdates, setRealtimeUpdates] = useState(true);

  // Initialize dashboard
  useEffect(() => {
    if (isAuthenticated) {
      dispatch(fetchDashboardData());
      dispatch(fetchAnalyticsData({ timeRange: '30days' }));
      initializeSocket();
    }
  }, [isAuthenticated, dispatch]);

  // Initialize socket connection
  const initializeSocket = () => {
    const token = localStorage.getItem('authToken');
    
    if (token) {
      socketService.connect(token);
      
      socketService.socket?.on('connect', () => {
        setSocketConnected(true);
        console.log('Socket connected');
      });

      socketService.socket?.on('disconnect', () => {
        setSocketConnected(false);
        console.log('Socket disconnected');
      });

      // Subscribe to real-time updates
      socketService.subscribeToTestUpdates((testUpdate) => {
        if (realtimeUpdates) {
          handleTestUpdate(testUpdate);
        }
      });

      socketService.subscribeToNotifications(user?.id, (notification) => {
        dispatch(showSuccessToast(notification.message));
      });
    }
  };

  // Handle real-time test updates
  const handleTestUpdate = (testUpdate) => {
    if (testUpdate.status === 'completed') {
      // Update Redux state with real-time data
      dispatch(updateRealtimeData({
        type: 'test_completed',
        data: testUpdate
      }));
      
      if (testUpdate.result === 'positive' && testUpdate.severity === 'severe') {
        dispatch(showErrorToast(
          `Critical: Severe malaria detected in ${testUpdate.patientName}`,
          { 
            actionUrl: `/results/${testUpdate.testId}`,
            duration: 10000 
          }
        ));
        
        // Add urgent alert
        dispatch(updateRealtimeData({
          type: 'urgent_alert',
          data: {
            type: 'critical_result',
            message: `Severe malaria detected in ${testUpdate.patientName}`,
            severity: 'critical',
            patientName: testUpdate.patientName
          }
        }));
      }
    }
  };

  // Handle refresh
  const handleRefresh = () => {
    dispatch(fetchDashboardData());
    dispatch(fetchAnalyticsData({ timeRange: '30days' }));
  };

  // Handle errors
  useEffect(() => {
    if (error) {
      dispatch(showErrorToast(error));
      dispatch(clearDashboardError());
    }
  }, [error, dispatch]);

  // Show initial loading state
  if (loading && !dashboardData) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-8 flex items-center space-x-4">
          <LoadingSpinner size="lg" color="white" />
          <span className="text-white text-lg">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        onClose={() => setSidebarOpen(false)} 
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-64">
        {/* Header */}
        <Header
          title="Dashboard"
          subtitle={`Welcome back, ${user?.firstName || user?.name || 'User'}`}
          onMenuClick={() => setSidebarOpen(true)}
          onRefresh={handleRefresh}
          socketConnected={socketConnected}
          showSearch={true}
          showNotifications={true}
        />

        {/* Main Content Area */}
        <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 overflow-y-auto pt-24">
          {/* Stats Grid */}
          <DashboardCardGrid className="mb-8">
            {loading ? (
              // Show skeleton cards while loading
              Array.from({ length: 4 }).map((_, index) => (
                <DashboardCardSkeleton key={index} />
              ))
            ) : (
              stats.map((stat, index) => (
                <DashboardCard
                  key={index}
                  title={stat.title}
                  value={stat.value}
                  change={stat.change}
                  trend={stat.trend}
                  icon={index === 0 ? Microscope : index === 1 ? AlertTriangle : index === 2 ? Clock : Users}
                  color={stat.color}
                  onClick={() => {
                    const routes = [
                      '/tests?filter=today',
                      '/results?filter=positive', 
                      '/tests?status=pending',
                      '/patients'
                    ];
                    window.location.href = routes[index];
                  }}
                />
              ))
            )}
          </DashboardCardGrid>

          {/* Main Content Grid */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-8 mb-8">
            {/* Left Column - Recent Tests */}
            <div className="xl:col-span-2">
              <TestSummary
                tests={recentTests}
                loading={loading}
                title="Recent Tests"
                showViewAll={true}
                onViewAll={() => window.location.href = '/tests'}
                onTestClick={(test) => window.location.href = `/tests/${test.id}`}
              />
            </div>

            {/* Right Column - Sidebar Content */}
            <div className="space-y-6">
              {/* Quick Actions */}
              {loading ? (
                <QuickActionsSkeleton />
              ) : (
                <QuickActions />
              )}

              {/* Critical Alerts & System Status */}
              {loading ? (
                <CriticalAlertsSkeleton />
              ) : (
                <CriticalAlerts
                  alerts={urgentAlerts}
                  systemStatus={{
                    ...systemStatus,
                    realtime: socketConnected
                  }}
                  onAlertDismiss={(alertId) => {
                    dispatch(dismissAlert(alertId));
                  }}
                />
              )}

              {/* TAT / SLA Widget */}
              <TATWidget />
            </div>
          </div>

          {/* Analytics Section */}
          <div className="mb-8">
            <AnalyticsSection 
              timeRange="30days"
              showCompactView={user?.role === 'technician'} // Show compact view for technicians
            />
          </div>

          {/* Footer Info */}
          <div className="mt-8 text-center">
            <p className="text-blue-300 text-sm">
              Last updated: {dashboardData?.lastUpdated ? 
                new Date(dashboardData.lastUpdated).toLocaleString() : 
                'Never'
              }
            </p>
            <p className="text-blue-400 text-xs mt-1">
              {socketConnected ? '🟢 Real-time updates active' : '🔴 Real-time updates offline'}
            </p>
          </div>
        </main>
      </div>

      {/* Toast Notifications */}
      <Toast />
    </div>
  );
};

export default Dashboard;
import React from 'react';
import { Clock, User, TestTube, Activity, Eye } from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';

const RecentActivity = ({ activities = [], loading = false, userRole }) => {
  const getActivityIcon = (type) => {
    switch (type) {
      case 'test_created':
        return TestTube;
      case 'test_completed':
        return Activity;
      case 'user_login':
        return User;
      case 'result_viewed':
        return Eye;
      default:
        return Clock;
    }
  };

  const getActivityColor = (type) => {
    switch (type) {
      case 'test_created':
        return 'text-blue-600 bg-blue-100';
      case 'test_completed':
        return 'text-green-600 bg-green-100';
      case 'user_login':
        return 'text-purple-600 bg-purple-100';
      case 'result_viewed':
        return 'text-gray-600 bg-gray-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const formatActivityTime = (timestamp) => {
    const now = new Date();
    const activityTime = new Date(timestamp);
    const diffInMinutes = Math.floor((now - activityTime) / (1000 * 60));

    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return activityTime.toLocaleDateString();
  };

  // Sample activities if none provided
  const sampleActivities = [
    {
      id: 1,
      type: 'test_created',
      message: 'New blood smear test created for Patient #12345',
      user: 'Dr. Johnson',
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString()
    },
    {
      id: 2,
      type: 'test_completed',
      message: 'Malaria analysis completed - Positive result detected',
      user: 'Lab Tech Sarah',
      timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString()
    },
    {
      id: 3,
      type: 'result_viewed',
      message: 'Test results reviewed by supervisor',
      user: 'Dr. Smith',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    }
  ];

  const displayActivities = activities.length > 0 ? activities : sampleActivities;

  return (
    <div className="bg-white rounded-lg shadow-medical p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900">Recent Activity</h3>
        <span className="text-sm text-gray-500">Today</span>
      </div>

      {loading ? (
        <div className="flex justify-center py-8">
          <LoadingSpinner size="md" />
        </div>
      ) : (
        <div className="space-y-4">
          {displayActivities.length === 0 ? (
            <div className="text-center py-8">
              <Activity className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No recent activity</p>
            </div>
          ) : (
            displayActivities.map((activity) => {
              const IconComponent = getActivityIcon(activity.type);
              const colorClasses = getActivityColor(activity.type);

              return (
                <div key={activity.id} className="flex items-start space-x-3">
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${colorClasses}`}>
                    <IconComponent className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-900">{activity.message}</p>
                    <div className="flex items-center mt-1 space-x-2">
                      <span className="text-xs text-gray-500">{activity.user}</span>
                      <span className="text-xs text-gray-400">•</span>
                      <span className="text-xs text-gray-500">
                        {formatActivityTime(activity.timestamp)}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {displayActivities.length > 0 && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <button className="text-sm text-primary-600 hover:text-primary-700 font-medium">
            View all activity
          </button>
        </div>
      )}
    </div>
  );
};

export default RecentActivity;
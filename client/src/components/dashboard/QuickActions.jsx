import React from 'react';
import { Upload, FileText, History, Settings, TestTube, Users } from 'lucide-react';

const QuickActions = ({ userRole, onAction, stats }) => {
  const getActionsForRole = (role) => {
    const baseActions = [
      {
        id: 'upload',
        label: 'Upload Samples',
        description: 'Upload blood smear images',
        icon: Upload,
        color: 'bg-blue-500 hover:bg-blue-600',
        permission: ['admin', 'supervisor', 'technician']
      },
      {
        id: 'results',
        label: 'View Results',
        description: 'Check test results',
        icon: FileText,
        color: 'bg-green-500 hover:bg-green-600',
        permission: ['admin', 'supervisor', 'technician']
      },
      {
        id: 'history',
        label: 'Test History',
        description: 'Browse all tests',
        icon: History,
        color: 'bg-purple-500 hover:bg-purple-600',
        permission: ['admin', 'supervisor', 'technician']
      },
      {
        id: 'patients',
        label: 'Manage Patients',
        description: 'Patient records',
        icon: Users,
        color: 'bg-indigo-500 hover:bg-indigo-600',
        permission: ['admin', 'supervisor']
      },
      {
        id: 'settings',
        label: 'Settings',
        description: 'System settings',
        icon: Settings,
        color: 'bg-gray-500 hover:bg-gray-600',
        permission: ['admin', 'supervisor']
      }
    ];

    return baseActions.filter(action => 
      action.permission.includes(role) || action.permission.includes('all')
    );
  };

  const actions = getActionsForRole(userRole);

  const getActionBadge = (actionId) => {
    if (!stats) return null;
    
    switch (actionId) {
      case 'upload':
        return stats.processingTests > 0 ? stats.processingTests : null;
      case 'results':
        return stats.positiveTests > 0 ? stats.positiveTests : null;
      case 'history':
        return stats.todayTests > 0 ? stats.todayTests : null;
      default:
        return null;
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-medical p-6">
      <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
      
      <div className="space-y-3">
        {actions.map((action) => {
          const badge = getActionBadge(action.id);
          
          return (
            <button
              key={action.id}
              onClick={() => onAction(action.id)}
              className={`
                w-full flex items-center p-4 rounded-lg text-white transition-colors
                ${action.color}
                hover:shadow-lg transform hover:scale-105 transition-transform
              `}
            >
              <div className="flex-shrink-0">
                <action.icon className="w-6 h-6" />
              </div>
              <div className="ml-4 flex-1 text-left">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium">{action.label}</h4>
                  {badge && (
                    <span className="bg-white bg-opacity-20 text-white text-xs font-medium px-2 py-1 rounded-full">
                      {badge}
                    </span>
                  )}
                </div>
                <p className="text-sm opacity-90 mt-1">{action.description}</p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Quick Stats */}
      {stats && (
        <div className="mt-6 pt-6 border-t border-gray-200">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Today's Summary</h4>
          <div className="grid grid-cols-2 gap-4 text-center">
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-lg font-semibold text-gray-900">{stats.todayTests || 0}</p>
              <p className="text-xs text-gray-600">Tests</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-lg font-semibold text-gray-900">{stats.processingTests || 0}</p>
              <p className="text-xs text-gray-600">Processing</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default QuickActions;
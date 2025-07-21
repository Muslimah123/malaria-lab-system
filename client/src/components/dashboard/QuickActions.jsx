// import React from 'react';
// import { Upload, FileText, History, Settings, TestTube, Users } from 'lucide-react';

// const QuickActions = ({ userRole, onAction, stats }) => {
//   const getActionsForRole = (role) => {
//     const baseActions = [
//       {
//         id: 'upload',
//         label: 'Upload Samples',
//         description: 'Upload blood smear images',
//         icon: Upload,
//         color: 'bg-blue-500 hover:bg-blue-600',
//         permission: ['admin', 'supervisor', 'technician']
//       },
//       {
//         id: 'results',
//         label: 'View Results',
//         description: 'Check test results',
//         icon: FileText,
//         color: 'bg-green-500 hover:bg-green-600',
//         permission: ['admin', 'supervisor', 'technician']
//       },
//       {
//         id: 'history',
//         label: 'Test History',
//         description: 'Browse all tests',
//         icon: History,
//         color: 'bg-purple-500 hover:bg-purple-600',
//         permission: ['admin', 'supervisor', 'technician']
//       },
//       {
//         id: 'patients',
//         label: 'Manage Patients',
//         description: 'Patient records',
//         icon: Users,
//         color: 'bg-indigo-500 hover:bg-indigo-600',
//         permission: ['admin', 'supervisor']
//       },
//       {
//         id: 'settings',
//         label: 'Settings',
//         description: 'System settings',
//         icon: Settings,
//         color: 'bg-gray-500 hover:bg-gray-600',
//         permission: ['admin', 'supervisor']
//       }
//     ];

//     return baseActions.filter(action => 
//       action.permission.includes(role) || action.permission.includes('all')
//     );
//   };

//   const actions = getActionsForRole(userRole);

//   const getActionBadge = (actionId) => {
//     if (!stats) return null;
    
//     switch (actionId) {
//       case 'upload':
//         return stats.processingTests > 0 ? stats.processingTests : null;
//       case 'results':
//         return stats.positiveTests > 0 ? stats.positiveTests : null;
//       case 'history':
//         return stats.todayTests > 0 ? stats.todayTests : null;
//       default:
//         return null;
//     }
//   };

//   return (
//     <div className="bg-white rounded-lg shadow-medical p-6">
//       <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
      
//       <div className="space-y-3">
//         {actions.map((action) => {
//           const badge = getActionBadge(action.id);
          
//           return (
//             <button
//               key={action.id}
//               onClick={() => onAction(action.id)}
//               className={`
//                 w-full flex items-center p-4 rounded-lg text-white transition-colors
//                 ${action.color}
//                 hover:shadow-lg transform hover:scale-105 transition-transform
//               `}
//             >
//               <div className="flex-shrink-0">
//                 <action.icon className="w-6 h-6" />
//               </div>
//               <div className="ml-4 flex-1 text-left">
//                 <div className="flex items-center justify-between">
//                   <h4 className="font-medium">{action.label}</h4>
//                   {badge && (
//                     <span className="bg-white bg-opacity-20 text-white text-xs font-medium px-2 py-1 rounded-full">
//                       {badge}
//                     </span>
//                   )}
//                 </div>
//                 <p className="text-sm opacity-90 mt-1">{action.description}</p>
//               </div>
//             </button>
//           );
//         })}
//       </div>

//       {/* Quick Stats */}
//       {stats && (
//         <div className="mt-6 pt-6 border-t border-gray-200">
//           <h4 className="text-sm font-medium text-gray-900 mb-3">Today's Summary</h4>
//           <div className="grid grid-cols-2 gap-4 text-center">
//             <div className="bg-gray-50 rounded-lg p-3">
//               <p className="text-lg font-semibold text-gray-900">{stats.todayTests || 0}</p>
//               <p className="text-xs text-gray-600">Tests</p>
//             </div>
//             <div className="bg-gray-50 rounded-lg p-3">
//               <p className="text-lg font-semibold text-gray-900">{stats.processingTests || 0}</p>
//               <p className="text-xs text-gray-600">Processing</p>
//             </div>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// };

// export default QuickActions;
// src/components/dashboard/QuickActions.jsx
import React from 'react';
import { useSelector } from 'react-redux';
import { 
  Upload, 
  Plus, 
  Eye, 
  Download, 
  Users, 
  TestTube,
  FileText,
  Settings
} from 'lucide-react';
import { selectUser } from '../../store/slices/authSlice';

const QuickActions = ({ className = "" }) => {
  const user = useSelector(selectUser);

  // Define actions based on user role
  const getQuickActions = () => {
    const baseActions = [
      { 
        title: 'Upload Sample', 
        icon: Upload, 
        color: 'bg-blue-500', 
        href: '/upload',
        description: 'Upload blood sample images'
      },
      { 
        title: 'New Patient', 
        icon: Plus, 
        color: 'bg-green-500', 
        href: '/patients/new',
        description: 'Create patient record'
      },
      { 
        title: 'View Results', 
        icon: Eye, 
        color: 'bg-purple-500', 
        href: '/results',
        description: 'Check diagnosis results'
      }
    ];

    const roleSpecificActions = {
      admin: [
        { 
          title: 'User Management', 
          icon: Users, 
          color: 'bg-indigo-500', 
          href: '/users',
          description: 'Manage system users'
        },
        { 
          title: 'System Settings', 
          icon: Settings, 
          color: 'bg-gray-500', 
          href: '/settings',
          description: 'Configure system'
        },
        { 
          title: 'Generate Report', 
          icon: Download, 
          color: 'bg-orange-500', 
          href: '/reports',
          description: 'Export data reports'
        }
      ],
      supervisor: [
        { 
          title: 'Test Records', 
          icon: TestTube, 
          color: 'bg-teal-500', 
          href: '/tests',
          description: 'Review all tests'
        },
        { 
          title: 'Generate Report', 
          icon: Download, 
          color: 'bg-orange-500', 
          href: '/reports',
          description: 'Export data reports'
        }
      ],
      technician: [
        { 
          title: 'My Tests', 
          icon: TestTube, 
          color: 'bg-teal-500', 
          href: '/my-tests',
          description: 'View assigned tests'
        }
      ]
    };

    const userRoleActions = roleSpecificActions[user?.role] || [];
    
    // Combine base actions with role-specific actions, limit to 6 total
    return [...baseActions, ...userRoleActions].slice(0, 6);
  };

  const quickActions = getQuickActions();

  return (
    <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 ${className}`}>
      <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
      <div className="grid grid-cols-2 gap-3">
        {quickActions.map((action, index) => (
          <QuickActionButton
            key={index}
            action={action}
          />
        ))}
      </div>
    </div>
  );
};

// Individual quick action button component
const QuickActionButton = ({ action }) => {
  const { title, icon: Icon, color, href, description } = action;

  return (
    <a
      href={href}
      className="flex flex-col items-center justify-center p-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg transition-colors group"
      title={description}
    >
      <div className={`${color} p-2 rounded-lg mb-2 group-hover:scale-110 transition-transform`}>
        <Icon className="h-5 w-5 text-white" />
      </div>
      <span className="text-white text-sm font-medium text-center leading-tight">
        {title}
      </span>
    </a>
  );
};

// Loading skeleton for quick actions
export const QuickActionsSkeleton = ({ className = "" }) => (
  <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 ${className}`}>
    <div className="h-6 bg-white/20 rounded w-1/3 mb-4"></div>
    <div className="grid grid-cols-2 gap-3">
      {Array.from({ length: 4 }).map((_, index) => (
        <div key={index} className="flex flex-col items-center justify-center p-4 bg-white/5 rounded-lg animate-pulse">
          <div className="w-9 h-9 bg-white/20 rounded-lg mb-2"></div>
          <div className="h-4 bg-white/20 rounded w-16"></div>
        </div>
      ))}
    </div>
  </div>
);

// Custom hook for quick actions
export const useQuickActions = () => {
  const user = useSelector(selectUser);
  
  return React.useMemo(() => {
    const baseActions = [
      { title: 'Upload Sample', icon: Upload, color: 'bg-blue-500', href: '/upload' },
      { title: 'New Patient', icon: Plus, color: 'bg-green-500', href: '/patients/new' },
      { title: 'View Results', icon: Eye, color: 'bg-purple-500', href: '/results' }
    ];

    const roleSpecificActions = {
      admin: [
        { title: 'User Management', icon: Users, color: 'bg-indigo-500', href: '/users' },
        { title: 'System Settings', icon: Settings, color: 'bg-gray-500', href: '/settings' },
        { title: 'Generate Report', icon: Download, color: 'bg-orange-500', href: '/reports' }
      ],
      supervisor: [
        { title: 'Test Records', icon: TestTube, color: 'bg-teal-500', href: '/tests' },
        { title: 'Generate Report', icon: Download, color: 'bg-orange-500', href: '/reports' }
      ],
      technician: [
        { title: 'My Tests', icon: TestTube, color: 'bg-teal-500', href: '/my-tests' }
      ]
    };

    return [...baseActions, ...(roleSpecificActions[user?.role] || [])].slice(0, 6);
  }, [user?.role]);
};

export default QuickActions;
// src/components/common/Sidebar.jsx
import React from 'react';
import { useSelector } from 'react-redux';
import { useLocation } from 'react-router-dom'; // Add this import
import { 
  Home,
  Upload,
  Eye,
  TestTube,
  Users,
  UserCheck,
  PieChart,
  Shield,
  FileText,
  Settings,
  ClipboardList,
  Microscope,
  X
} from 'lucide-react';
import { selectUser } from '../../store/slices/authSlice';

const Sidebar = ({ isOpen, onClose }) => {
  const user = useSelector(selectUser);
  const location = useLocation(); // Use React Router's location

  // Navigation items based on user role
  const getNavigationItems = () => {
    const baseItems = [
      { name: 'Dashboard', icon: Home, path: '/dashboard' },
      { name: 'Worklist', icon: ClipboardList, path: '/worklist' },
      { name: 'Upload Sample', icon: Upload, path: '/upload' },
      { name: 'Test Results', icon: Eye, path: '/results' },
    ];

    const roleSpecificItems = {
      admin: [
        { name: 'Test Records', icon: TestTube, path: '/tests' },
        { name: 'Patient Management', icon: Users, path: '/patients' },
        { name: 'User Management', icon: UserCheck, path: '/users' },
        { name: 'Analytics', icon: PieChart, path: '/analytics' },
        { name: 'Audit Logs', icon: Shield, path: '/audit' },
        { name: 'Reports', icon: FileText, path: '/reports' },
        { name: 'Settings', icon: Settings, path: '/settings' },
      ],
      supervisor: [
        { name: 'Test Records', icon: TestTube, path: '/tests' },
        { name: 'Patient Management', icon: Users, path: '/patients' },
        { name: 'Analytics', icon: PieChart, path: '/analytics' },
        { name: 'Reports', icon: FileText, path: '/reports' },
        { name: 'Quality Control', icon: Shield, path: '/quality' },
      ],
      technician: [
        { name: 'Patient Management', icon: Users, path: '/patients' },
      ]
    };

    return [...baseItems, ...(roleSpecificItems[user?.role] || [])];
  };

  const navigationItems = getNavigationItems();

  // ✅ IMPROVED: Enhanced active path detection
  const isCurrentPath = (path) => {
    const pathname = location.pathname;
    
    // Exact match for most routes
    if (pathname === path) return true;
    
    // Special handling for nested routes
    switch (path) {
      case '/results':
        // Highlight for both /results and /results/:testId
        return pathname === '/results' || pathname.startsWith('/results/');
      
      case '/tests':
        // Highlight for both /tests and /tests/:testId  
        return pathname === '/tests' || pathname.startsWith('/tests/');
        
      case '/patients':
        // Highlight for both /patients and /patients/:patientId
        return pathname === '/patients' || pathname.startsWith('/patients/');
        
      case '/users':
        // Highlight for both /users and /users/:userId
        return pathname === '/users' || pathname.startsWith('/users/');
        
      case '/my-tests':
        // Highlight for both /my-tests and /my-tests/:testId
        return pathname === '/my-tests' || pathname.startsWith('/my-tests/');
        
      case '/reports':
        // Highlight for both /reports and /reports/:reportId
        return pathname === '/reports' || pathname.startsWith('/reports/');
        
      case '/analytics':
        // Highlight for both /analytics and /analytics/:type
        return pathname === '/analytics' || pathname.startsWith('/analytics/');
        
      case '/settings':
        // Highlight for both /settings and /settings/:section
        return pathname === '/settings' || pathname.startsWith('/settings/');
        
      default:
        return false;
    }
  };

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white/10 backdrop-blur-md border-r border-white/20 transform transition-transform duration-300 ease-in-out lg:translate-x-0 ${
        isOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/20">
          <div className="flex items-center space-x-3">
            <div className="bg-blue-500 p-2 rounded-lg">
              <Microscope className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">Malaria Lab</h1>
              <p className="text-blue-200 text-xs">Diagnosis System</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="lg:hidden text-blue-200 hover:text-white p-1 rounded transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="mt-6 px-3 flex-1 overflow-y-auto">
          <div className="space-y-1">
            {navigationItems.map((item) => {
              const isActive = isCurrentPath(item.path);
              return (
                <a
                  key={item.name}
                  href={item.path}
                  className={`group flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-500 text-white shadow-lg'
                      : 'text-blue-200 hover:text-white hover:bg-white/10'
                  }`}
                  onClick={onClose} // Close sidebar on mobile when item is clicked
                >
                  <item.icon className={`mr-3 h-5 w-5 flex-shrink-0 ${
                    isActive ? 'text-white' : 'text-blue-300 group-hover:text-white'
                  }`} />
                  {item.name}
                </a>
              );
            })}
          </div>
        </nav>

        {/* User info at bottom */}
        <div className="absolute bottom-0 w-full p-4 border-t border-white/20">
          <div className="flex items-center space-x-3 mb-2">
            <div className="bg-blue-500 w-8 h-8 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-medium">
                {user?.firstName?.[0]}{user?.lastName?.[0] || user?.name?.split(' ').map(n => n[0]).join('') || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium truncate">
                {user?.firstName} {user?.lastName || user?.name}
              </p>
              <p className="text-blue-300 text-xs truncate capitalize">{user?.role}</p>
            </div>
          </div>
          
          {/* Role Badge */}
          <div className="mt-2">
            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
              user?.role === 'admin' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' :
              user?.role === 'supervisor' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' :
              'bg-green-500/20 text-green-300 border border-green-500/30'
            }`}>
              {user?.role === 'admin' ? '👑 Administrator' :
               user?.role === 'supervisor' ? '👔 Supervisor' :
               '🔬 Technician'}
            </span>
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
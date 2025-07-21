// src/components/common/Sidebar.jsx
import React from 'react';
import { useSelector } from 'react-redux';
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

  // Navigation items based on user role
  const getNavigationItems = () => {
    const baseItems = [
      { name: 'Dashboard', icon: Home, path: '/dashboard' },
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
        { name: 'My Tests', icon: ClipboardList, path: '/my-tests' },
        { name: 'Patient Management', icon: Users, path: '/patients' },
      ]
    };

    return [...baseItems, ...(roleSpecificItems[user?.role] || [])];
  };

  const navigationItems = getNavigationItems();

  const isCurrentPath = (path) => {
    return window.location.pathname === path;
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
      <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white/10 backdrop-blur-md border-r border-white/20 transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 ${
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
        <nav className="mt-6 px-3 flex-1">
          <div className="space-y-1">
            {navigationItems.map((item) => {
              const isActive = isCurrentPath(item.path);
              return (
                <a
                  key={item.name}
                  href={item.path}
                  className={`group flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-500 text-white'
                      : 'text-blue-200 hover:text-white hover:bg-white/10'
                  }`}
                  onClick={onClose} // Close sidebar on mobile when item is clicked
                >
                  <item.icon className="mr-3 h-5 w-5 flex-shrink-0" />
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
              user?.role === 'admin' ? 'bg-purple-100 text-purple-800' :
              user?.role === 'supervisor' ? 'bg-blue-100 text-blue-800' :
              'bg-green-100 text-green-800'
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
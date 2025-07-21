// src/components/common/Header.jsx
import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  Search, 
  Bell, 
  Menu, 
  RefreshCw, 
  Wifi, 
  WifiOff,
  LogOut,
  User,
  Settings
} from 'lucide-react';
import { selectUser } from '../../store/slices/authSlice';
import { selectNotifications } from '../../store/slices/notificationsSlice';
import { logout } from '../../store/slices/authSlice';
import apiService from '../../services/api';

const Header = ({ 
  title = "Dashboard", 
  subtitle = null, 
  onMenuClick, 
  onRefresh,
  socketConnected = false,
  showSearch = true,
  showNotifications = true 
}) => {
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  const notifications = useSelector(selectNotifications);
  
  const [showNotificationDropdown, setShowNotificationDropdown] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const handleLogout = async () => {
    try {
      await dispatch(logout()).unwrap();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const handleSearch = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (searchTerm.trim()) {
      // Implement global search functionality
      window.location.href = `/search?q=${encodeURIComponent(searchTerm.trim())}`;
    }
  };

  const unreadNotifications = notifications.filter(n => !n.read);

  return (
    <header className="bg-white/10 backdrop-blur-md border-b border-white/20">
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between py-4">
          {/* Left Section */}
          <div className="flex items-center space-x-4">
            {/* Mobile Menu Button */}
            <button
              onClick={onMenuClick}
              className="lg:hidden text-blue-200 hover:text-white p-2 rounded-lg hover:bg-white/10 transition-colors"
            >
              <Menu className="h-6 w-6" />
            </button>
            
            {/* Title */}
            <div>
              <h1 className="text-xl font-semibold text-white">{title}</h1>
              {subtitle && (
                <p className="text-blue-200 text-sm">{subtitle}</p>
              )}
            </div>
          </div>

          {/* Right Section */}
          <div className="flex items-center space-x-4">
            {/* Socket Status Indicator */}
            <div className="flex items-center space-x-2">
              {socketConnected ? (
                <Wifi className="h-4 w-4 text-green-400" title="Real-time connected" />
              ) : (
                <WifiOff className="h-4 w-4 text-red-400" title="Real-time disconnected" />
              )}
            </div>

            {/* Search */}
            {showSearch && (
              <div className="relative hidden sm:block">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
                <input
                  type="text"
                  placeholder="Search patients, tests..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch(e)}
                  className="bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent w-64"
                />
              </div>
            )}

            {/* Notifications */}
            {showNotifications && (
              <div className="relative">
                <button 
                  onClick={() => setShowNotificationDropdown(!showNotificationDropdown)}
                  className="relative p-2 text-blue-200 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                >
                  <Bell className="h-5 w-5" />
                  {unreadNotifications.length > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                      {unreadNotifications.length}
                    </span>
                  )}
                </button>

                {/* Notifications Dropdown */}
                {showNotificationDropdown && (
                  <>
                    <div 
                      className="fixed inset-0 z-40" 
                      onClick={() => setShowNotificationDropdown(false)}
                    />
                    <div className="absolute right-0 mt-2 w-80 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg shadow-lg z-50">
                      <div className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="text-white font-medium">Notifications</h3>
                          {unreadNotifications.length > 0 && (
                            <span className="text-blue-300 text-sm">
                              {unreadNotifications.length} new
                            </span>
                          )}
                        </div>
                        <div className="space-y-3 max-h-64 overflow-y-auto">
                          {notifications.length > 0 ? (
                            notifications.slice(0, 5).map((notification) => (
                              <div 
                                key={notification.id} 
                                className={`flex items-start space-x-3 p-3 rounded-lg transition-colors ${
                                  notification.read ? 'bg-white/5' : 'bg-blue-500/10'
                                }`}
                              >
                                <div className={`flex-shrink-0 w-2 h-2 rounded-full mt-2 ${
                                  notification.type === 'urgent' ? 'bg-red-400' : 
                                  notification.type === 'warning' ? 'bg-yellow-400' : 'bg-blue-400'
                                }`} />
                                <div className="flex-1">
                                  <p className="text-white text-sm">{notification.message}</p>
                                  <p className="text-blue-300 text-xs mt-1">{notification.timeAgo}</p>
                                </div>
                              </div>
                            ))
                          ) : (
                            <p className="text-blue-300 text-sm text-center py-4">
                              No notifications
                            </p>
                          )}
                        </div>
                        {notifications.length > 5 && (
                          <div className="mt-3 pt-3 border-t border-white/20">
                            <button className="text-blue-300 hover:text-white text-sm w-full text-center">
                              View all notifications
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Refresh Button */}
            {onRefresh && (
              <button
                onClick={onRefresh}
                className="p-2 text-blue-200 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                title="Refresh data"
              >
                <RefreshCw className="h-5 w-5" />
              </button>
            )}

            {/* User Menu */}
            <div className="relative">
              <button
                onClick={() => setShowUserDropdown(!showUserDropdown)}
                className="flex items-center space-x-3 text-left hover:bg-white/10 rounded-lg p-2 transition-colors"
              >
                <div className="bg-blue-500 w-8 h-8 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-medium">
                    {user?.firstName?.[0]}{user?.lastName?.[0] || user?.name?.split(' ').map(n => n[0]).join('') || 'U'}
                  </span>
                </div>
                <div className="hidden sm:block text-right">
                  <p className="text-white text-sm font-medium">
                    {user?.firstName} {user?.lastName || user?.name}
                  </p>
                  <p className="text-blue-300 text-xs capitalize">{user?.role}</p>
                </div>
              </button>

              {/* User Dropdown */}
              {showUserDropdown && (
                <>
                  <div 
                    className="fixed inset-0 z-40" 
                    onClick={() => setShowUserDropdown(false)}
                  />
                  <div className="absolute right-0 mt-2 w-48 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg shadow-lg z-50">
                    <div className="p-2">
                      <div className="px-3 py-2 border-b border-white/20">
                        <p className="text-white text-sm font-medium">
                          {user?.firstName} {user?.lastName || user?.name}
                        </p>
                        <p className="text-blue-300 text-xs">{user?.email}</p>
                        <p className="text-blue-400 text-xs capitalize">{user?.role}</p>
                      </div>
                      <div className="py-1">
                        <button
                          onClick={() => window.location.href = '/profile'}
                          className="w-full flex items-center space-x-2 px-3 py-2 text-sm text-blue-200 hover:text-white hover:bg-white/10 rounded transition-colors"
                        >
                          <User className="h-4 w-4" />
                          <span>Profile</span>
                        </button>
                        <button
                          onClick={() => window.location.href = '/settings'}
                          className="w-full flex items-center space-x-2 px-3 py-2 text-sm text-blue-200 hover:text-white hover:bg-white/10 rounded transition-colors"
                        >
                          <Settings className="h-4 w-4" />
                          <span>Settings</span>
                        </button>
                        <div className="border-t border-white/20 my-1" />
                        <button
                          onClick={handleLogout}
                          className="w-full flex items-center space-x-2 px-3 py-2 text-sm text-red-300 hover:text-red-200 hover:bg-red-500/10 rounded transition-colors"
                        >
                          <LogOut className="h-4 w-4" />
                          <span>Sign out</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
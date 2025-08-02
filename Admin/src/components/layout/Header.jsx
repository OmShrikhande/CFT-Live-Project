import React, { useState } from 'react';
import { 
  Menu, 
  Bell, 
  Shield, 
  User, 
  Settings, 
  LogOut, 
  ChevronDown,
  Lock,
  Activity
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { format } from 'date-fns';

const Header = ({ onMenuClick }) => {
  const { user, logout } = useAuth();
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  return (
    <header className="bg-white shadow-sm border-b border-secondary-200 sticky top-0 z-30">
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Left side */}
          <div className="flex items-center">
            {/* Mobile menu button */}
            <button
              type="button"
              className="lg:hidden p-2 rounded-md text-secondary-600 hover:text-secondary-900 hover:bg-secondary-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500"
              onClick={onMenuClick}
            >
              <Menu className="h-6 w-6" />
            </button>
            
            {/* Security Status */}
            <div className="hidden sm:flex items-center ml-4 lg:ml-0">
              <div className="flex items-center px-3 py-1 bg-success-100 text-success-800 rounded-full text-sm font-medium">
                <Shield className="h-4 w-4 mr-1" />
                Secure Session
              </div>
            </div>
          </div>

          {/* Right side */}
          <div className="flex items-center space-x-4">
            {/* Current Time */}
            <div className="hidden md:block text-sm text-secondary-600">
              {format(new Date(), 'PPp')}
            </div>
            
            {/* Notifications */}
            <div className="relative">
              <button
                type="button"
                className="p-2 rounded-full text-secondary-600 hover:text-secondary-900 hover:bg-secondary-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 relative"
                onClick={() => setNotificationsOpen(!notificationsOpen)}
              >
                <Bell className="h-6 w-6" />
                {/* Notification badge */}
                <span className="absolute top-0 right-0 block h-2 w-2 rounded-full bg-danger-400 ring-2 ring-white"></span>
              </button>
              
              {/* Notifications dropdown */}
              {notificationsOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
                  <div className="p-4 border-b border-secondary-200">
                    <h3 className="text-sm font-medium text-secondary-900">
                      Security Notifications
                    </h3>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    <div className="p-4 hover:bg-secondary-50">
                      <div className="flex items-start">
                        <div className="flex-shrink-0">
                          <Activity className="h-5 w-5 text-primary-600" />
                        </div>
                        <div className="ml-3 flex-1">
                          <p className="text-sm text-secondary-900">
                            New transfer request pending approval
                          </p>
                          <p className="text-xs text-secondary-500 mt-1">
                            2 minutes ago
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="p-4 hover:bg-secondary-50">
                      <div className="flex items-start">
                        <div className="flex-shrink-0">
                          <Shield className="h-5 w-5 text-success-600" />
                        </div>
                        <div className="ml-3 flex-1">
                          <p className="text-sm text-secondary-900">
                            Security scan completed successfully
                          </p>
                          <p className="text-xs text-secondary-500 mt-1">
                            1 hour ago
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="p-3 border-t border-secondary-200">
                    <button className="text-sm text-primary-600 hover:text-primary-800 font-medium">
                      View all notifications
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Profile dropdown */}
            <div className="relative">
              <button
                type="button"
                className="flex items-center max-w-xs bg-white rounded-full text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
              >
                <div className="flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-secondary-50">
                  <div className="h-8 w-8 bg-primary-600 rounded-full flex items-center justify-center">
                    <User className="h-5 w-5 text-white" />
                  </div>
                  <div className="hidden md:block text-left">
                    <p className="text-sm font-medium text-secondary-900">
                      {user?.firstName} {user?.lastName}
                    </p>
                    <p className="text-xs text-secondary-600 capitalize">
                      {user?.role?.replace('_', ' ')}
                    </p>
                  </div>
                  <ChevronDown className="h-4 w-4 text-secondary-600" />
                </div>
              </button>

              {/* Profile dropdown menu */}
              {profileDropdownOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
                  <div className="p-4 border-b border-secondary-200">
                    <div className="flex items-center">
                      <div className="h-10 w-10 bg-primary-600 rounded-full flex items-center justify-center">
                        <User className="h-6 w-6 text-white" />
                      </div>
                      <div className="ml-3">
                        <p className="text-sm font-medium text-secondary-900">
                          {user?.firstName} {user?.lastName}
                        </p>
                        <p className="text-xs text-secondary-600">
                          {user?.email}
                        </p>
                        <p className="text-xs text-primary-600 capitalize font-medium">
                          {user?.role?.replace('_', ' ')}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="py-1">
                    <button className="flex items-center w-full px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-100">
                      <User className="h-4 w-4 mr-3" />
                      Profile Settings
                    </button>
                    <button className="flex items-center w-full px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-100">
                      <Lock className="h-4 w-4 mr-3" />
                      Change Password
                    </button>
                    <button className="flex items-center w-full px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-100">
                      <Settings className="h-4 w-4 mr-3" />
                      Account Settings
                    </button>
                  </div>
                  
                  <div className="border-t border-secondary-200">
                    <button
                      onClick={handleLogout}
                      className="flex items-center w-full px-4 py-2 text-sm text-danger-700 hover:bg-danger-50"
                    >
                      <LogOut className="h-4 w-4 mr-3" />
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {/* Security Banner */}
      <div className="bg-primary-600 text-white text-xs py-1 px-4 text-center">
        <div className="flex items-center justify-center space-x-4">
          <span>🔒 Secure Government Portal</span>
          <span>•</span>
          <span>Organization: {user?.organization?.name}</span>
          <span>•</span>
          <span>Session Active</span>
        </div>
      </div>
      
      {/* Click outside handlers */}
      {(profileDropdownOpen || notificationsOpen) && (
        <div 
          className="fixed inset-0 z-40"
          onClick={() => {
            setProfileDropdownOpen(false);
            setNotificationsOpen(false);
          }}
        />
      )}
    </header>
  );
};

export default Header;
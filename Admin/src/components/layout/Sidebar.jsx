import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  Users, 
  Activity, 
  FileText, 
  Settings, 
  AlertTriangle,
  BarChart3,
  Lock,
  Eye,
  X
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const Sidebar = ({ open, setOpen }) => {
  const { user, hasPermission } = useAuth();

  const navigation = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: LayoutDashboard,
      current: true,
    },
    {
      name: 'User Management',
      href: '/users',
      icon: Users,
      permission: 'canManageUsers',
    },
    {
      name: 'Transfer Requests',
      href: '/transfers',
      icon: Activity,
      permission: 'canManageTransfers',
    },
    {
      name: 'Reports',
      href: '/reports',
      icon: BarChart3,
      permission: 'canViewReports',
    },
    {
      name: 'Security Logs',
      href: '/security',
      icon: Eye,
      permission: 'canViewSecurityLogs',
    },
    {
      name: 'Audit Trail',
      href: '/audit',
      icon: FileText,
      permission: 'canViewAuditLogs',
    },
  ];

  const adminNavigation = [
    {
      name: 'System Settings',
      href: '/settings',
      icon: Settings,
      role: 'super_admin',
    },
    {
      name: 'Security Center',
      href: '/security-center',
      icon: Lock,
      role: 'super_admin',
    },
  ];

  const filteredNavigation = navigation.filter(item => 
    !item.permission || hasPermission(item.permission)
  );

  const filteredAdminNavigation = adminNavigation.filter(item => 
    !item.role || user?.role === item.role
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex min-h-0 flex-1 flex-col bg-secondary-900">
          {/* Logo */}
          <div className="flex h-16 flex-shrink-0 items-center px-4 bg-secondary-800">
            <div className="flex items-center">
              <div className="h-8 w-8 bg-primary-600 rounded-lg flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div className="ml-3">
                <h1 className="text-white font-semibold text-lg">
                  Gov Portal
                </h1>
                <p className="text-secondary-300 text-xs">
                  Admin Panel
                </p>
              </div>
            </div>
          </div>
          
          {/* Navigation */}
          <div className="flex flex-1 flex-col overflow-y-auto">
            <nav className="flex-1 space-y-1 px-2 py-4">
              {/* Main Navigation */}
              <div className="space-y-1">
                {filteredNavigation.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    className={({ isActive }) =>
                      `group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                        isActive
                          ? 'bg-primary-700 text-white'
                          : 'text-secondary-300 hover:bg-secondary-700 hover:text-white'
                      }`
                    }
                  >
                    <item.icon
                      className="mr-3 h-5 w-5 flex-shrink-0"
                      aria-hidden="true"
                    />
                    {item.name}
                  </NavLink>
                ))}
              </div>

              {/* Admin Navigation */}
              {filteredAdminNavigation.length > 0 && (
                <div className="pt-6">
                  <div className="px-2 pb-2">
                    <h3 className="text-xs font-semibold text-secondary-400 uppercase tracking-wider">
                      Administration
                    </h3>
                  </div>
                  <div className="space-y-1">
                    {filteredAdminNavigation.map((item) => (
                      <NavLink
                        key={item.name}
                        to={item.href}
                        className={({ isActive }) =>
                          `group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                            isActive
                              ? 'bg-primary-700 text-white'
                              : 'text-secondary-300 hover:bg-secondary-700 hover:text-white'
                          }`
                        }
                      >
                        <item.icon
                          className="mr-3 h-5 w-5 flex-shrink-0"
                          aria-hidden="true"
                        />
                        {item.name}
                      </NavLink>
                    ))}
                  </div>
                </div>
              )}
            </nav>

            {/* Security Status */}
            <div className="flex-shrink-0 p-4 border-t border-secondary-700">
              <div className="bg-success-900/50 rounded-lg p-3">
                <div className="flex items-center">
                  <Shield className="h-5 w-5 text-success-400" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-success-400">
                      Security Status
                    </p>
                    <p className="text-xs text-success-300">
                      All systems operational
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* User Info */}
            <div className="flex-shrink-0 p-4 border-t border-secondary-700">
              <div className="flex items-center">
                <div className="h-8 w-8 bg-primary-600 rounded-full flex items-center justify-center">
                  <span className="text-sm font-medium text-white">
                    {user?.firstName?.[0]}{user?.lastName?.[0]}
                  </span>
                </div>
                <div className="ml-3 flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    {user?.firstName} {user?.lastName}
                  </p>
                  <p className="text-xs text-secondary-300 truncate capitalize">
                    {user?.role?.replace('_', ' ')}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile Sidebar */}
      <div className={`lg:hidden fixed inset-0 z-50 ${open ? 'block' : 'hidden'}`}>
        <div className="fixed inset-0 bg-secondary-600 bg-opacity-75" />
        <div className="fixed inset-y-0 left-0 flex w-full max-w-xs flex-col bg-secondary-900">
          {/* Close button */}
          <div className="absolute top-0 right-0 -mr-12 pt-2">
            <button
              type="button"
              className="ml-1 flex h-10 w-10 items-center justify-center rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
              onClick={() => setOpen(false)}
            >
              <X className="h-6 w-6 text-white" />
            </button>
          </div>

          {/* Logo */}
          <div className="flex h-16 flex-shrink-0 items-center px-4 bg-secondary-800">
            <div className="flex items-center">
              <div className="h-8 w-8 bg-primary-600 rounded-lg flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div className="ml-3">
                <h1 className="text-white font-semibold text-lg">
                  Gov Portal
                </h1>
                <p className="text-secondary-300 text-xs">
                  Admin Panel
                </p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <div className="flex flex-1 flex-col overflow-y-auto">
            <nav className="flex-1 space-y-1 px-2 py-4">
              {/* Main Navigation */}
              <div className="space-y-1">
                {filteredNavigation.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    onClick={() => setOpen(false)}
                    className={({ isActive }) =>
                      `group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                        isActive
                          ? 'bg-primary-700 text-white'
                          : 'text-secondary-300 hover:bg-secondary-700 hover:text-white'
                      }`
                    }
                  >
                    <item.icon
                      className="mr-3 h-5 w-5 flex-shrink-0"
                      aria-hidden="true"
                    />
                    {item.name}
                  </NavLink>
                ))}
              </div>

              {/* Admin Navigation */}
              {filteredAdminNavigation.length > 0 && (
                <div className="pt-6">
                  <div className="px-2 pb-2">
                    <h3 className="text-xs font-semibold text-secondary-400 uppercase tracking-wider">
                      Administration
                    </h3>
                  </div>
                  <div className="space-y-1">
                    {filteredAdminNavigation.map((item) => (
                      <NavLink
                        key={item.name}
                        to={item.href}
                        onClick={() => setOpen(false)}
                        className={({ isActive }) =>
                          `group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors duration-200 ${
                            isActive
                              ? 'bg-primary-700 text-white'
                              : 'text-secondary-300 hover:bg-secondary-700 hover:text-white'
                          }`
                        }
                      >
                        <item.icon
                          className="mr-3 h-5 w-5 flex-shrink-0"
                          aria-hidden="true"
                        />
                        {item.name}
                      </NavLink>
                    ))}
                  </div>
                </div>
              )}
            </nav>

            {/* Security Status */}
            <div className="flex-shrink-0 p-4 border-t border-secondary-700">
              <div className="bg-success-900/50 rounded-lg p-3">
                <div className="flex items-center">
                  <Shield className="h-5 w-5 text-success-400" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-success-400">
                      Security Status
                    </p>
                    <p className="text-xs text-success-300">
                      All systems operational
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* User Info */}
            <div className="flex-shrink-0 p-4 border-t border-secondary-700">
              <div className="flex items-center">
                <div className="h-8 w-8 bg-primary-600 rounded-full flex items-center justify-center">
                  <span className="text-sm font-medium text-white">
                    {user?.firstName?.[0]}{user?.lastName?.[0]}
                  </span>
                </div>
                <div className="ml-3 flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    {user?.firstName} {user?.lastName}
                  </p>
                  <p className="text-xs text-secondary-300 truncate capitalize">
                    {user?.role?.replace('_', ' ')}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
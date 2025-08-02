import React, { useState, useEffect } from 'react';
import { 
  Users, 
  Shield, 
  Activity, 
  AlertTriangle, 
  TrendingUp, 
  Clock, 
  CheckCircle, 
  XCircle,
  Eye,
  UserCheck,
  UserX,
  ArrowUpRight,
  ArrowDownRight,
  Calendar,
  Filter
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { adminAPI } from '../../services/api';
import { format, subDays, isToday, isYesterday } from 'date-fns';
import toast from 'react-hot-toast';

const Dashboard = () => {
  const { user } = useAuth();
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('7d');
  const [refreshing, setRefreshing] = useState(false);

  // Fetch dashboard data
  const fetchDashboardData = async () => {
    try {
      setRefreshing(true);
      const response = await adminAPI.getDashboard();
      setDashboardData(response.data.data);
    } catch (error) {
      console.error('Dashboard fetch error:', error);
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    
    // Auto-refresh every 5 minutes
    const interval = setInterval(fetchDashboardData, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const formatDate = (date) => {
    const d = new Date(date);
    if (isToday(d)) return 'Today';
    if (isYesterday(d)) return 'Yesterday';
    return format(d, 'MMM dd, yyyy');
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'text-success-600 bg-success-100',
      inactive: 'text-secondary-600 bg-secondary-100',
      suspended: 'text-warning-600 bg-warning-100',
      pending: 'text-primary-600 bg-primary-100',
      approved: 'text-success-600 bg-success-100',
      rejected: 'text-danger-600 bg-danger-100',
      cancelled: 'text-secondary-600 bg-secondary-100',
    };
    return colors[status] || 'text-secondary-600 bg-secondary-100';
  };

  const getPriorityColor = (priority) => {
    const colors = {
      urgent: 'text-danger-600 bg-danger-100',
      high: 'text-warning-600 bg-warning-100',
      medium: 'text-primary-600 bg-primary-100',
      low: 'text-success-600 bg-success-100',
    };
    return colors[priority] || 'text-secondary-600 bg-secondary-100';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-secondary-50 flex items-center justify-center">
        <div className="text-center">
          <div className="spinner w-12 h-12 mx-auto mb-4"></div>
          <p className="text-secondary-600">Loading secure dashboard...</p>
        </div>
      </div>
    );
  }

  const { userStats, transferStats, pendingTransfers, recentTransfers } = dashboardData || {};

  return (
    <div className="min-h-screen bg-secondary-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-secondary-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-primary-600 mr-3" />
              <div>
                <h1 className="text-xl font-semibold text-secondary-900">
                  Admin Dashboard
                </h1>
                <p className="text-sm text-secondary-600">
                  Welcome back, {user?.firstName} {user?.lastName}
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Time Range Filter */}
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="form-input text-sm py-1 px-2"
              >
                <option value="1d">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
              </select>
              
              {/* Refresh Button */}
              <button
                onClick={fetchDashboardData}
                disabled={refreshing}
                className="btn-secondary text-sm py-1 px-3"
              >
                {refreshing ? (
                  <div className="spinner w-4 h-4"></div>
                ) : (
                  'Refresh'
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Security Alert */}
        <div className="mb-6 p-4 bg-primary-50 border border-primary-200 rounded-lg">
          <div className="flex items-center">
            <Shield className="h-5 w-5 text-primary-600 mr-2" />
            <div>
              <h3 className="text-sm font-medium text-primary-800">
                Secure Government System
              </h3>
              <p className="text-sm text-primary-700 mt-1">
                All activities are monitored and logged for security compliance.
                Organization: {user?.organization?.name}
              </p>
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Total Users */}
          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Users className="h-8 w-8 text-primary-600" />
                </div>
                <div className="ml-4 flex-1">
                  <p className="text-sm font-medium text-secondary-600">
                    Total Users
                  </p>
                  <p className="text-2xl font-semibold text-secondary-900">
                    {userStats?.total || 0}
                  </p>
                  <div className="flex items-center mt-1">
                    <TrendingUp className="h-4 w-4 text-success-500 mr-1" />
                    <span className="text-sm text-success-600">
                      +{userStats?.newThisMonth || 0} this month
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Active Users */}
          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <UserCheck className="h-8 w-8 text-success-600" />
                </div>
                <div className="ml-4 flex-1">
                  <p className="text-sm font-medium text-secondary-600">
                    Active Users
                  </p>
                  <p className="text-2xl font-semibold text-secondary-900">
                    {userStats?.active || 0}
                  </p>
                  <div className="flex items-center mt-1">
                    <span className="text-sm text-secondary-600">
                      {userStats?.total ? Math.round((userStats.active / userStats.total) * 100) : 0}% of total
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Pending Transfers */}
          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Activity className="h-8 w-8 text-warning-600" />
                </div>
                <div className="ml-4 flex-1">
                  <p className="text-sm font-medium text-secondary-600">
                    Pending Transfers
                  </p>
                  <p className="text-2xl font-semibold text-secondary-900">
                    {pendingTransfers || 0}
                  </p>
                  <div className="flex items-center mt-1">
                    <Clock className="h-4 w-4 text-warning-500 mr-1" />
                    <span className="text-sm text-warning-600">
                      Requires attention
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Security Level */}
          <div className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Shield className="h-8 w-8 text-success-600" />
                </div>
                <div className="ml-4 flex-1">
                  <p className="text-sm font-medium text-secondary-600">
                    Security Level
                  </p>
                  <p className="text-2xl font-semibold text-success-600">
                    HIGH
                  </p>
                  <div className="flex items-center mt-1">
                    <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                    <span className="text-sm text-success-600">
                      All systems secure
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Transfer Requests */}
          <div className="card">
            <div className="card-header">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-secondary-900">
                  Recent Transfer Requests
                </h3>
                <button className="btn-secondary text-sm">
                  View All
                </button>
              </div>
            </div>
            <div className="card-body p-0">
              {recentTransfers && recentTransfers.length > 0 ? (
                <div className="divide-y divide-secondary-200">
                  {recentTransfers.slice(0, 5).map((transfer) => (
                    <div key={transfer._id} className="p-4 hover:bg-secondary-50">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            <p className="text-sm font-medium text-secondary-900">
                              {transfer.user?.firstName} {transfer.user?.lastName}
                            </p>
                            <span className={`ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(transfer.status)}`}>
                              {transfer.status}
                            </span>
                          </div>
                          <p className="text-sm text-secondary-600 mt-1">
                            From: {transfer.fromAdmin?.firstName} {transfer.fromAdmin?.lastName}
                          </p>
                          <p className="text-sm text-secondary-600">
                            To: {transfer.toAdmin?.firstName} {transfer.toAdmin?.lastName}
                          </p>
                          <div className="flex items-center mt-2">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getPriorityColor(transfer.priority)}`}>
                              {transfer.priority}
                            </span>
                            <span className="ml-2 text-xs text-secondary-500">
                              {formatDate(transfer.createdAt)}
                            </span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <button className="text-primary-600 hover:text-primary-800">
                            <Eye className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 text-center">
                  <Activity className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
                  <p className="text-secondary-600">No recent transfer requests</p>
                </div>
              )}
            </div>
          </div>

          {/* User Activity Summary */}
          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-medium text-secondary-900">
                User Activity Summary
              </h3>
            </div>
            <div className="card-body">
              <div className="space-y-4">
                {/* Active Users */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-3 h-3 bg-success-500 rounded-full mr-3"></div>
                    <span className="text-sm text-secondary-700">Active Users</span>
                  </div>
                  <span className="text-sm font-medium text-secondary-900">
                    {userStats?.active || 0}
                  </span>
                </div>

                {/* Inactive Users */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-3 h-3 bg-secondary-400 rounded-full mr-3"></div>
                    <span className="text-sm text-secondary-700">Inactive Users</span>
                  </div>
                  <span className="text-sm font-medium text-secondary-900">
                    {userStats?.inactive || 0}
                  </span>
                </div>

                {/* Suspended Users */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-3 h-3 bg-warning-500 rounded-full mr-3"></div>
                    <span className="text-sm text-secondary-700">Suspended Users</span>
                  </div>
                  <span className="text-sm font-medium text-secondary-900">
                    {userStats?.suspended || 0}
                  </span>
                </div>

                {/* Locked Users */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-3 h-3 bg-danger-500 rounded-full mr-3"></div>
                    <span className="text-sm text-secondary-700">Locked Users</span>
                  </div>
                  <span className="text-sm font-medium text-secondary-900">
                    {userStats?.locked || 0}
                  </span>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="mt-6 pt-6 border-t border-secondary-200">
                <h4 className="text-sm font-medium text-secondary-900 mb-3">
                  Quick Actions
                </h4>
                <div className="grid grid-cols-2 gap-3">
                  <button className="btn-secondary text-sm py-2">
                    Add User
                  </button>
                  <button className="btn-secondary text-sm py-2">
                    View Reports
                  </button>
                  <button className="btn-secondary text-sm py-2">
                    Security Logs
                  </button>
                  <button className="btn-secondary text-sm py-2">
                    Settings
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Security Footer */}
        <div className="mt-8 text-center text-sm text-secondary-500">
          <p>
            Secure Government Portal • Last updated: {format(new Date(), 'PPpp')} • 
            Session expires in 30 minutes
          </p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
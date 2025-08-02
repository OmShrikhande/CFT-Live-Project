import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { Eye, EyeOff, Shield, Lock, Mail, AlertTriangle, CheckCircle } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

// Validation schema
const loginSchema = yup.object({
  email: yup
    .string()
    .email('Please enter a valid email address')
    .required('Email is required')
    .matches(
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      'Please enter a valid email format'
    ),
  password: yup
    .string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters'),
});

const Login = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [lockoutTime, setLockoutTime] = useState(null);
  const [securityLevel, setSecurityLevel] = useState('high');
  
  const { login, isLoading, error, clearError } = useAuth();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    watch,
    reset,
  } = useForm({
    resolver: yupResolver(loginSchema),
    mode: 'onChange',
  });

  const watchedEmail = watch('email');
  const watchedPassword = watch('password');

  // Security lockout mechanism
  useEffect(() => {
    const storedAttempts = localStorage.getItem('admin_login_attempts');
    const storedLockout = localStorage.getItem('admin_lockout_time');
    
    if (storedAttempts) {
      setLoginAttempts(parseInt(storedAttempts));
    }
    
    if (storedLockout) {
      const lockoutTime = new Date(storedLockout);
      const now = new Date();
      
      if (now < lockoutTime) {
        setIsLocked(true);
        setLockoutTime(lockoutTime);
      } else {
        // Clear expired lockout
        localStorage.removeItem('admin_login_attempts');
        localStorage.removeItem('admin_lockout_time');
      }
    }
  }, []);

  // Lockout countdown
  useEffect(() => {
    if (isLocked && lockoutTime) {
      const interval = setInterval(() => {
        const now = new Date();
        if (now >= lockoutTime) {
          setIsLocked(false);
          setLockoutTime(null);
          setLoginAttempts(0);
          localStorage.removeItem('admin_login_attempts');
          localStorage.removeItem('admin_lockout_time');
          clearInterval(interval);
        }
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isLocked, lockoutTime]);

  // Clear error when user starts typing
  useEffect(() => {
    if (error) {
      clearError();
    }
  }, [watchedEmail, watchedPassword, clearError]);

  const onSubmit = async (data) => {
    if (isLocked) {
      toast.error('Account temporarily locked due to multiple failed attempts');
      return;
    }

    try {
      await login(data);
      
      // Clear login attempts on successful login
      localStorage.removeItem('admin_login_attempts');
      localStorage.removeItem('admin_lockout_time');
      setLoginAttempts(0);
      
      navigate('/dashboard');
    } catch (error) {
      const newAttempts = loginAttempts + 1;
      setLoginAttempts(newAttempts);
      localStorage.setItem('admin_login_attempts', newAttempts.toString());
      
      // Lock account after 5 failed attempts
      if (newAttempts >= 5) {
        const lockoutEnd = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        setIsLocked(true);
        setLockoutTime(lockoutEnd);
        localStorage.setItem('admin_lockout_time', lockoutEnd.toISOString());
        toast.error('Account locked for 15 minutes due to multiple failed attempts');
      } else {
        toast.error(`Login failed. ${5 - newAttempts} attempts remaining.`);
      }
    }
  };

  const getRemainingTime = () => {
    if (!lockoutTime) return '';
    
    const now = new Date();
    const remaining = Math.max(0, Math.ceil((lockoutTime - now) / 1000));
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  const getSecurityIndicator = () => {
    const indicators = {
      high: { color: 'text-green-600', bg: 'bg-green-100', text: 'High Security' },
      medium: { color: 'text-yellow-600', bg: 'bg-yellow-100', text: 'Medium Security' },
      low: { color: 'text-red-600', bg: 'bg-red-100', text: 'Low Security' },
    };
    
    return indicators[securityLevel];
  };

  return (
    
    <div className="min-h-screen bg-gradient-to-br from-primary-900 via-primary-800 to-secondary-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"%3E%3Cg fill="none" fill-rule="evenodd"%3E%3Cg fill="%23ffffff" fill-opacity="0.05"%3E%3Ccircle cx="30" cy="30" r="2"/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] opacity-20"></div>
      
      <div className="max-w-md w-full space-y-8 relative">
        {/* Government Seal */}
        <div className="text-center">
          <div className="mx-auto h-20 w-20 bg-white rounded-full flex items-center justify-center shadow-lg gov-seal">
            <Shield className="h-12 w-12 text-primary-600" />
          </div>
          <h2 className="mt-6 text-3xl font-bold text-white">
            Secure Admin Access
          </h2>
          <p className="mt-2 text-sm text-primary-200">
            Government Security Portal
          </p>
          
          {/* Security Level Indicator */}
          <div className="mt-4 flex items-center justify-center">
            <div className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getSecurityIndicator().bg} ${getSecurityIndicator().color}`}>
              <CheckCircle className="w-3 h-3 mr-1" />
              {getSecurityIndicator().text}
            </div>
          </div>
        </div>

        {/* Login Form */}
        <div className="bg-white/95 backdrop-blur-sm rounded-lg shadow-xl p-8 border border-white/20">
          {/* Security Warning */}
          {loginAttempts > 0 && !isLocked && (
            <div className="mb-4 p-3 bg-warning-50 border border-warning-200 rounded-md">
              <div className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-warning-600 mr-2" />
                <p className="text-sm text-warning-800">
                  {loginAttempts} failed attempt{loginAttempts > 1 ? 's' : ''}. 
                  {5 - loginAttempts} remaining before lockout.
                </p>
              </div>
            </div>
          )}

          {/* Lockout Warning */}
          {isLocked && (
            <div className="mb-4 p-3 bg-danger-50 border border-danger-200 rounded-md">
              <div className="flex items-center">
                <Lock className="h-4 w-4 text-danger-600 mr-2" />
                <p className="text-sm text-danger-800">
                  Account locked. Try again in {getRemainingTime()}
                </p>
              </div>
            </div>
          )}

          <form className="space-y-6" onSubmit={handleSubmit(onSubmit)}>
            {/* Email Field */}
            <div>
              <label htmlFor="email" className="form-label">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-secondary-400" />
                </div>
                <input
                  {...register('email')}
                  type="email"
                  autoComplete="email"
                  className={`form-input pl-10 ${errors.email ? 'form-input-error' : ''}`}
                  placeholder="admin@government.gov"
                  disabled={isLocked}
                />
              </div>
              {errors.email && (
                <p className="form-error">{errors.email.message}</p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label htmlFor="password" className="form-label">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-secondary-400" />
                </div>
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  className={`form-input pl-10 pr-10 ${errors.password ? 'form-input-error' : ''}`}
                  placeholder="Enter your secure password"
                  disabled={isLocked}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isLocked}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-secondary-400 hover:text-secondary-600" />
                  ) : (
                    <Eye className="h-5 w-5 text-secondary-400 hover:text-secondary-600" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="form-error">{errors.password.message}</p>
              )}
            </div>

            {/* Security Notice */}
            <div className="text-xs text-secondary-600 bg-secondary-50 p-3 rounded-md">
              <p className="font-medium mb-1">Security Notice:</p>
              <ul className="space-y-1">
                <li>• This is a secure government system</li>
                <li>• All activities are monitored and logged</li>
                <li>• Unauthorized access is prohibited</li>
              </ul>
            </div>

            {/* Submit Button */}
            <div>
              <button
                type="submit"
                disabled={isSubmitting || isLoading || isLocked}
                className="w-full btn-primary py-3 text-base font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting || isLoading ? (
                  <div className="flex items-center justify-center">
                    <div className="spinner w-5 h-5 mr-2"></div>
                    Authenticating...
                  </div>
                ) : (
                  <div className="flex items-center justify-center">
                    <Shield className="w-5 h-5 mr-2" />
                    Secure Login
                  </div>
                )}
              </button>
            </div>
          </form>

          {/* Footer */}
          <div className="mt-6 text-center">
            <p className="text-xs text-secondary-500">
              Protected by government-grade security protocols
            </p>
            <div className="mt-2 flex items-center justify-center space-x-4 text-xs text-secondary-400">
              <span>SSL Encrypted</span>
              <span>•</span>
              <span>Multi-Factor Ready</span>
              <span>•</span>
              <span>Audit Logged</span>
            </div>
          </div>
        </div>

        {/* Legal Notice */}
        <div className="text-center text-xs text-primary-200">
          <p>
            By accessing this system, you acknowledge that you are authorized to use it
            and agree to comply with all applicable security policies.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
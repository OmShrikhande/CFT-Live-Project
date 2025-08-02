import React from 'react';
import { Shield } from 'lucide-react';

const LoadingScreen = ({ message = 'Loading secure system...' }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-900 via-primary-800 to-secondary-900 flex items-center justify-center">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%23ffffff%22%20fill-opacity%3D%220.05%22%3E%3Ccircle%20cx%3D%2230%22%20cy%3D%2230%22%20r%3D%222%22/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] opacity-20"></div>
      
      <div className="text-center relative">
        {/* Government Seal with Animation */}
        <div className="mx-auto h-20 w-20 bg-white rounded-full flex items-center justify-center shadow-lg gov-seal mb-6">
          <Shield className="h-12 w-12 text-primary-600 animate-pulse" />
        </div>
        
        {/* Loading Spinner */}
        <div className="relative mb-6">
          <div className="spinner w-12 h-12 mx-auto border-4 border-white/20 border-t-white"></div>
        </div>
        
        {/* Loading Text */}
        <h2 className="text-xl font-semibold text-white mb-2">
          {message}
        </h2>
        
        {/* Security Notice */}
        <p className="text-primary-200 text-sm max-w-md mx-auto">
          Authenticating secure government portal access...
        </p>
        
        {/* Progress Dots */}
        <div className="flex justify-center space-x-2 mt-6">
          <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse"></div>
          <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
          <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
        </div>
        
        {/* Security Footer */}
        <div className="mt-8 text-xs text-primary-300">
          <p>Secured by government-grade encryption</p>
        </div>
      </div>
    </div>
  );
};

export default LoadingScreen;
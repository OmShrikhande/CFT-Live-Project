import React from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null, 
      errorInfo: null 
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error details
    console.error('Error Boundary caught an error:', error, errorInfo);
    
    this.setState({
      error: error,
      errorInfo: errorInfo
    });

    // Report error to monitoring service in production
    if (process.env.NODE_ENV === 'production') {
      // You can integrate with error reporting services like Sentry here
      console.error('Production error:', {
        error: error.toString(),
        errorInfo: errorInfo.componentStack,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href
      });
    }
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/dashboard';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-secondary-50 flex items-center justify-center px-4">
          <div className="max-w-md w-full text-center">
            {/* Error Icon */}
            <div className="mx-auto h-16 w-16 bg-danger-100 rounded-full flex items-center justify-center mb-6">
              <AlertTriangle className="h-8 w-8 text-danger-600" />
            </div>
            
            {/* Error Title */}
            <h1 className="text-2xl font-bold text-secondary-900 mb-4">
              System Error Detected
            </h1>
            
            {/* Error Description */}
            <p className="text-secondary-600 mb-6">
              A critical error has occurred in the secure government portal. 
              Our security team has been notified and is investigating the issue.
            </p>
            
            {/* Error Details (Development Only) */}
            {process.env.NODE_ENV === 'development' && this.state.error && (
              <div className="mb-6 p-4 bg-danger-50 border border-danger-200 rounded-lg text-left">
                <h3 className="text-sm font-medium text-danger-800 mb-2">
                  Error Details (Development Mode):
                </h3>
                <pre className="text-xs text-danger-700 overflow-auto max-h-32">
                  {this.state.error.toString()}
                </pre>
                {this.state.errorInfo && (
                  <details className="mt-2">
                    <summary className="text-xs text-danger-600 cursor-pointer">
                      Component Stack
                    </summary>
                    <pre className="text-xs text-danger-600 mt-1 overflow-auto max-h-32">
                      {this.state.errorInfo.componentStack}
                    </pre>
                  </details>
                )}
              </div>
            )}
            
            {/* Action Buttons */}
            <div className="space-y-3">
              <button
                onClick={this.handleReload}
                className="w-full btn-primary flex items-center justify-center"
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Reload Application
              </button>
              
              <button
                onClick={this.handleGoHome}
                className="w-full btn-secondary flex items-center justify-center"
              >
                <Home className="w-4 h-4 mr-2" />
                Return to Dashboard
              </button>
            </div>
            
            {/* Security Notice */}
            <div className="mt-8 p-4 bg-primary-50 border border-primary-200 rounded-lg">
              <p className="text-sm text-primary-800">
                <strong>Security Notice:</strong> This error has been logged for security analysis. 
                If you believe this is a security-related issue, please contact the system administrator immediately.
              </p>
            </div>
            
            {/* Error ID for Support */}
            <div className="mt-4 text-xs text-secondary-500">
              Error ID: {Date.now().toString(36).toUpperCase()}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
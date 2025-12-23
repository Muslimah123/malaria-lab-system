//src/components/common/Toast.jsx
// This component displays toast notifications for various events in the application.
import React, { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { selectToasts, removeToast } from '../../store/slices/notificationsSlice';
import { NOTIFICATION_TYPES } from '../../utils/constants';

const Toast = () => {
  const dispatch = useDispatch();
  const toasts = useSelector(selectToasts);

  const getToastIcon = (type) => {
    switch (type) {
      case NOTIFICATION_TYPES.SUCCESS:
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case NOTIFICATION_TYPES.ERROR:
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      case NOTIFICATION_TYPES.WARNING:
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case NOTIFICATION_TYPES.INFO:
      default:
        return <Info className="w-5 h-5 text-blue-400" />;
    }
  };

  const getToastStyles = (type) => {
    switch (type) {
      case NOTIFICATION_TYPES.SUCCESS:
        return 'toast-success';
      case NOTIFICATION_TYPES.ERROR:
        return 'toast-error';
      case NOTIFICATION_TYPES.WARNING:
        return 'toast-warning';
      case NOTIFICATION_TYPES.INFO:
      default:
        return 'toast-info';
    }
  };

  const handleRemoveToast = (toastId) => {
    dispatch(removeToast(toastId));
  };

  return (
    <div className="fixed bottom-0 right-0 z-50 p-4 space-y-2">
      {toasts.map((toast) => (
        <ToastItem
          key={toast.id}
          toast={toast}
          onRemove={handleRemoveToast}
          icon={getToastIcon(toast.type)}
          className={getToastStyles(toast.type)}
        />
      ))}
    </div>
  );
};

const ToastItem = ({ toast, onRemove, icon, className }) => {
  const dispatch = useDispatch();

  useEffect(() => {
    if (toast.autoHide) {
      const timer = setTimeout(() => {
        onRemove(toast.id);
      }, toast.duration || 5000);

      return () => clearTimeout(timer);
    }
  }, [toast.id, toast.autoHide, toast.duration, onRemove]);

  const handleClick = () => {
    if (toast.actionUrl) {
      window.location.href = toast.actionUrl;
    }
  };

  return (
    <div
      className={`toast ${className} animate-slide-up max-w-sm w-full pointer-events-auto ${
        toast.actionUrl ? 'cursor-pointer' : ''
      }`}
      onClick={handleClick}
    >
      <div className="p-4">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            {icon}
          </div>
          <div className="ml-3 w-0 flex-1">
            {toast.title && (
              <p className="text-sm font-medium text-gray-900">
                {toast.title}
              </p>
            )}
            <p className={`text-sm ${toast.title ? 'mt-1 text-gray-500' : 'text-gray-900'}`}>
              {toast.message}
            </p>
            {toast.actionUrl && (
              <p className="text-xs text-gray-400 mt-1">
                Click to view details
              </p>
            )}
          </div>
          <div className="ml-4 flex-shrink-0 flex">
            <button
              className="bg-white rounded-md inline-flex text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              onClick={(e) => {
                e.stopPropagation();
                onRemove(toast.id);
              }}
            >
              <span className="sr-only">Close</span>
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>
        
        {/* Progress bar for auto-hide toasts */}
        {toast.autoHide && (
          <div className="mt-3">
            <div className="bg-gray-200 rounded-full h-1">
              <div
                className="bg-gray-400 h-1 rounded-full transition-all ease-linear"
                style={{
                  width: '100%',
                  animation: `shrink ${toast.duration || 5000}ms linear`
                }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Add CSS animation for progress bar
const style = document.createElement('style');
style.textContent = `
  @keyframes shrink {
    from {
      width: 100%;
    }
    to {
      width: 0%;
    }
  }
`;
document.head.appendChild(style);

export default Toast;
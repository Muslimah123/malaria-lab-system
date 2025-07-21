// src/components/common/Modal.jsx
import React, { useEffect, useRef } from 'react';
import { X, AlertTriangle, CheckCircle, Info, AlertCircle } from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';

const Modal = ({
  isOpen = false,
  onClose,
  title,
  children,
  size = 'md',
  type = 'default',
  showCloseButton = true,
  closeOnOverlay = true,
  closeOnEscape = true,
  footer = null,
  className = "",
  loading = false
}) => {
  const modalRef = useRef(null);
  const overlayRef = useRef(null);

  // Handle escape key
  useEffect(() => {
    const handleEscape = (e) => {
      if (closeOnEscape && e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, closeOnEscape, onClose]);

  // Handle click outside
  const handleOverlayClick = (e) => {
    if (closeOnOverlay && e.target === overlayRef.current) {
      onClose();
    }
  };

  // Focus management
  useEffect(() => {
    if (isOpen && modalRef.current) {
      modalRef.current.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-full mx-4'
  };

  const typeConfig = {
    default: {
      icon: null,
      bgColor: 'bg-gray-900',
      borderColor: 'border-white/20'
    },
    success: {
      icon: CheckCircle,
      bgColor: 'bg-gray-900',
      borderColor: 'border-green-500/30'
    },
    warning: {
      icon: AlertTriangle,
      bgColor: 'bg-gray-900',
      borderColor: 'border-yellow-500/30'
    },
    error: {
      icon: AlertCircle,
      bgColor: 'bg-gray-900',
      borderColor: 'border-red-500/30'
    },
    info: {
      icon: Info,
      bgColor: 'bg-gray-900',
      borderColor: 'border-blue-500/30'
    }
  };

  const config = typeConfig[type];
  const IconComponent = config.icon;

  return (
    <div 
      ref={overlayRef}
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={handleOverlayClick}
    >
      <div 
        ref={modalRef}
        className={`
          ${config.bgColor} 
          border 
          ${config.borderColor} 
          rounded-lg 
          shadow-xl 
          w-full 
          ${sizeClasses[size]} 
          max-h-[90vh] 
          overflow-hidden 
          focus:outline-none
          ${className}
        `}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? "modal-title" : undefined}
      >
        {/* Header */}
        {(title || showCloseButton) && (
          <div className="flex items-center justify-between p-6 border-b border-white/20">
            <div className="flex items-center space-x-3">
              {IconComponent && (
                <IconComponent className={`h-6 w-6 ${
                  type === 'success' ? 'text-green-400' :
                  type === 'warning' ? 'text-yellow-400' :
                  type === 'error' ? 'text-red-400' :
                  type === 'info' ? 'text-blue-400' :
                  'text-gray-400'
                }`} />
              )}
              {title && (
                <h2 id="modal-title" className="text-xl font-semibold text-white">
                  {title}
                </h2>
              )}
            </div>
            {showCloseButton && (
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white p-1 rounded transition-colors"
                aria-label="Close modal"
              >
                <X className="h-6 w-6" />
              </button>
            )}
          </div>
        )}

        {/* Content */}
        <div className="overflow-y-auto max-h-[calc(90vh-140px)]">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner size="lg" color="white" />
            </div>
          ) : (
            <div className="p-6">
              {children}
            </div>
          )}
        </div>

        {/* Footer */}
        {footer && (
          <div className="border-t border-white/20 p-6">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

// Pre-configured modal variants
export const ConfirmModal = ({
  isOpen,
  onClose,
  onConfirm,
  title = "Confirm Action",
  message,
  confirmText = "Confirm",
  cancelText = "Cancel",
  type = "warning",
  loading = false
}) => (
  <Modal
    isOpen={isOpen}
    onClose={onClose}
    title={title}
    type={type}
    size="sm"
    footer={
      <div className="flex items-center justify-end space-x-3">
        <button
          onClick={onClose}
          disabled={loading}
          className="btn btn-outline"
        >
          {cancelText}
        </button>
        <button
          onClick={onConfirm}
          disabled={loading}
          className={`btn ${
            type === 'error' ? 'btn-danger' : 
            type === 'warning' ? 'btn-warning' : 
            'btn-primary'
          }`}
        >
          {loading ? (
            <LoadingSpinner size="sm" color="white" />
          ) : (
            confirmText
          )}
        </button>
      </div>
    }
  >
    <p className="text-blue-200">{message}</p>
  </Modal>
);

export const AlertModal = ({
  isOpen,
  onClose,
  title,
  message,
  type = "info",
  buttonText = "OK"
}) => (
  <Modal
    isOpen={isOpen}
    onClose={onClose}
    title={title}
    type={type}
    size="sm"
    footer={
      <div className="flex justify-end">
        <button onClick={onClose} className="btn btn-primary">
          {buttonText}
        </button>
      </div>
    }
  >
    <p className="text-blue-200">{message}</p>
  </Modal>
);

export const FormModal = ({
  isOpen,
  onClose,
  onSubmit,
  title,
  children,
  submitText = "Save",
  cancelText = "Cancel",
  loading = false,
  size = "md"
}) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(e);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      size={size}
      footer={
        <div className="flex items-center justify-end space-x-3">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="btn btn-outline"
          >
            {cancelText}
          </button>
          <button
            type="submit"
            form="modal-form"
            disabled={loading}
            className="btn btn-primary"
          >
            {loading ? (
              <>
                <LoadingSpinner size="sm" color="white" />
                <span className="ml-2">Saving...</span>
              </>
            ) : (
              submitText
            )}
          </button>
        </div>
      }
    >
      <div id="modal-form" onSubmit={handleSubmit}>
        {children}
      </div>
    </Modal>
  );
};

// Custom hook for modal state management
export const useModal = (initialState = false) => {
  const [isOpen, setIsOpen] = React.useState(initialState);

  const openModal = React.useCallback(() => setIsOpen(true), []);
  const closeModal = React.useCallback(() => setIsOpen(false), []);
  const toggleModal = React.useCallback(() => setIsOpen(prev => !prev), []);

  return {
    isOpen,
    openModal,
    closeModal,
    toggleModal,
    setIsOpen
  };
};

export default Modal;
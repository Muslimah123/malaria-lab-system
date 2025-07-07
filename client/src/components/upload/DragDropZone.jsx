import React, { useCallback } from 'react';
import { Upload, FileImage, AlertCircle, Info } from 'lucide-react';
import clsx from 'clsx';

const DragDropZone = ({
  onDrop,
  onDragOver,
  onDragLeave,
  onFileSelect,
  dragActive = false,
  fileInputRef,
  maxFiles = 10,
  maxFileSize = 10 * 1024 * 1024, // 10MB
  acceptedTypes = ['image/jpeg', 'image/png', 'image/tiff'],
  disabled = false,
  className = ''
}) => {

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getAcceptedTypesDisplay = () => {
    const typeMap = {
      'image/jpeg': 'JPEG',
      'image/jpg': 'JPG', 
      'image/png': 'PNG',
      'image/tiff': 'TIFF',
      'image/tif': 'TIF'
    };
    
    return acceptedTypes
      .map(type => typeMap[type] || type.split('/')[1].toUpperCase())
      .join(', ');
  };

  const handleClick = () => {
    if (!disabled && fileInputRef?.current) {
      fileInputRef.current.click();
    }
  };

  const handleKeyDown = (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <div
      className={clsx(
        'relative border-2 border-dashed rounded-lg p-8 text-center transition-all duration-200 cursor-pointer',
        dragActive 
          ? 'border-primary-500 bg-primary-50' 
          : 'border-gray-300 hover:border-primary-400 hover:bg-gray-50',
        disabled && 'opacity-50 cursor-not-allowed',
        className
      )}
      onDrop={!disabled ? onDrop : undefined}
      onDragOver={!disabled ? onDragOver : undefined}
      onDragLeave={!disabled ? onDragLeave : undefined}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-label="Upload files"
    >
      {/* Upload Icon */}
      <div className={clsx(
        'mx-auto w-16 h-16 rounded-full flex items-center justify-center mb-4 transition-colors',
        dragActive 
          ? 'bg-primary-100 text-primary-600' 
          : 'bg-gray-100 text-gray-500'
      )}>
        {dragActive ? (
          <FileImage className="w-8 h-8" />
        ) : (
          <Upload className="w-8 h-8" />
        )}
      </div>

      {/* Main Text */}
      <div className="mb-4">
        <h3 className={clsx(
          'text-lg font-medium mb-2',
          dragActive ? 'text-primary-900' : 'text-gray-900'
        )}>
          {dragActive ? 'Drop files here' : 'Upload blood smear images'}
        </h3>
        <p className={clsx(
          'text-sm',
          dragActive ? 'text-primary-700' : 'text-gray-600'
        )}>
          {dragActive 
            ? 'Release to upload files'
            : 'Drag and drop files here, or click to browse'
          }
        </p>
      </div>

      {/* File Requirements */}
      <div className="space-y-2 text-xs text-gray-500">
        <div className="flex items-center justify-center space-x-4">
          <div className="flex items-center">
            <FileImage className="w-4 h-4 mr-1" />
            <span>Max {maxFiles} files</span>
          </div>
          <div className="flex items-center">
            <Info className="w-4 h-4 mr-1" />
            <span>Up to {formatFileSize(maxFileSize)} each</span>
          </div>
        </div>
        <p>Supported formats: {getAcceptedTypesDisplay()}</p>
      </div>

      {/* Quality Guidelines */}
      <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
        <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center">
          <Info className="w-4 h-4 mr-1" />
          Image Quality Guidelines
        </h4>
        <ul className="text-xs text-blue-800 space-y-1 text-left">
          <li>• Use high-resolution images (minimum 1024x768)</li>
          <li>• Ensure good lighting and clear focus</li>
          <li>• Include multiple fields of view for better analysis</li>
          <li>• Avoid blurry, overexposed, or underexposed images</li>
        </ul>
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept={acceptedTypes.join(',')}
        onChange={(e) => onFileSelect && onFileSelect(e.target.files)}
        className="hidden"
        disabled={disabled}
      />

      {/* Loading overlay */}
      {disabled && (
        <div className="absolute inset-0 bg-white bg-opacity-75 flex items-center justify-center rounded-lg">
          <div className="text-center">
            <div className="inline-block w-6 h-6 border-2 border-gray-300 border-t-primary-600 rounded-full animate-spin mb-2" />
            <p className="text-sm text-gray-600">Processing...</p>
          </div>
        </div>
      )}
    </div>
  );
};

// Specialized drag drop zones
export const CompactDragDropZone = ({ onFileSelect, disabled, className }) => {
  const fileInputRef = React.useRef(null);
  
  return (
    <div
      className={clsx(
        'border-2 border-dashed border-gray-300 rounded-lg p-4 text-center cursor-pointer hover:border-primary-400 hover:bg-gray-50 transition-colors',
        disabled && 'opacity-50 cursor-not-allowed',
        className
      )}
      onClick={() => !disabled && fileInputRef.current?.click()}
    >
      <Upload className="w-6 h-6 mx-auto text-gray-400 mb-2" />
      <p className="text-sm text-gray-600">Click to add more images</p>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept="image/*"
        onChange={(e) => onFileSelect && onFileSelect(e.target.files)}
        className="hidden"
        disabled={disabled}
      />
    </div>
  );
};

export const SingleFileDragDropZone = ({ 
  onFileSelect, 
  accept = 'image/*', 
  title = 'Upload Image',
  subtitle = 'Click to browse or drag and drop',
  disabled = false 
}) => {
  const fileInputRef = React.useRef(null);
  const [dragActive, setDragActive] = React.useState(false);

  const handleDrop = React.useCallback((e) => {
    e.preventDefault();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onFileSelect && onFileSelect(e.dataTransfer.files[0]);
      e.dataTransfer.clearData();
    }
  }, [onFileSelect]);

  const handleDragOver = React.useCallback((e) => {
    e.preventDefault();
    setDragActive(true);
  }, []);

  const handleDragLeave = React.useCallback((e) => {
    e.preventDefault();
    setDragActive(false);
  }, []);

  return (
    <div
      className={clsx(
        'border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors',
        dragActive 
          ? 'border-primary-500 bg-primary-50' 
          : 'border-gray-300 hover:border-primary-400 hover:bg-gray-50',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
      onDrop={!disabled ? handleDrop : undefined}
      onDragOver={!disabled ? handleDragOver : undefined}
      onDragLeave={!disabled ? handleDragLeave : undefined}
      onClick={() => !disabled && fileInputRef.current?.click()}
    >
      <FileImage className={clsx(
        'w-8 h-8 mx-auto mb-2',
        dragActive ? 'text-primary-600' : 'text-gray-400'
      )} />
      <h4 className="text-sm font-medium text-gray-900 mb-1">{title}</h4>
      <p className="text-xs text-gray-600">{subtitle}</p>
      
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        onChange={(e) => onFileSelect && onFileSelect(e.target.files?.[0])}
        className="hidden"
        disabled={disabled}
      />
    </div>
  );
};

export default DragDropZone;
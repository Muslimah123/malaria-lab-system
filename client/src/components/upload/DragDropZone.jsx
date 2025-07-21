import React, { useCallback } from 'react';
import { Upload, FileImage, AlertCircle, Info } from 'lucide-react';
import clsx from 'clsx';

const DragDropZone = ({
  onDrop,
  onDragOver,
  onDragLeave,
  onBrowseClick,
  dragActive = false,
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
    if (!disabled) {
      onBrowseClick();
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
      'relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 cursor-pointer upload-drag-zone',
      dragActive 
        ? 'border-white/50 bg-white/10 drag-active' 
        : 'border-white/30 hover:border-white/40 hover:bg-white/5',
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
    {/* Upload Icon with glassmorphism */}
    <div className={clsx(
      'mx-auto w-16 h-16 rounded-full flex items-center justify-center mb-4 transition-all border',
      dragActive 
        ? 'bg-white/20 text-white border-white/30' 
        : 'bg-white/10 text-blue-200 border-white/20'
    )}>
      {dragActive ? (
        <FileImage className="w-8 h-8" />
      ) : (
        <Upload className="w-8 h-8" />
      )}
    </div>

    {/* Main Text */}
    <div className="mb-6">
      <h3 className={clsx(
        'text-lg font-medium mb-2',
        dragActive ? 'text-white' : 'text-white'
      )}>
        {dragActive ? 'Drop files here' : 'Upload blood smear images'}
      </h3>
      <p className={clsx(
        'text-sm',
        dragActive ? 'text-blue-100' : 'text-blue-200'
      )}>
        {dragActive 
          ? 'Release to upload files'
          : 'Drag and drop files here, or click to browse'
        }
      </p>
    </div>

    {/* File Requirements */}
    <div className="bg-white/5 rounded-lg p-4 mb-4 border border-white/20">
      <div className="grid grid-cols-3 gap-4 text-xs text-blue-200 mb-3">
        <div className="flex items-center justify-center space-x-1">
          <FileImage className="w-4 h-4" />
          <span>Max {maxFiles} files</span>
        </div>
        <div className="flex items-center justify-center space-x-1">
          <Upload className="w-4 h-4" />
          <span>Up to {formatFileSize(maxFileSize)} each</span>
        </div>
        <div className="flex items-center justify-center space-x-1">
          <FileImage className="w-4 h-4" />
          <span>{getAcceptedTypesDisplay()}</span>
        </div>
      </div>
    </div>

    {/* Quality Guidelines */}
    <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
      <h4 className="text-sm font-medium text-blue-200 mb-3 flex items-center justify-center">
        <FileImage className="w-4 h-4 mr-2" />
        Image Quality Guidelines
      </h4>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-blue-300">
        <div>
          <p className="font-medium mb-2 text-green-300">✓ Good Quality</p>
          <ul className="space-y-1 text-left">
            <li>• High resolution (≥1024px)</li>
            <li>• Clear focus and lighting</li>
            <li>• Multiple fields of view</li>
          </ul>
        </div>
        <div>
          <p className="font-medium mb-2 text-red-300">✗ Avoid</p>
          <ul className="space-y-1 text-left">
            <li>• Blurry or out-of-focus</li>
            <li>• Over/under exposed</li>
            <li>• Poor color quality</li>
          </ul>
        </div>
      </div>
    </div>


    {/* Loading overlay */}
    {disabled && (
      <div className="absolute inset-0 bg-black/20 backdrop-blur-sm flex items-center justify-center rounded-xl">
        <div className="text-center">
          <div className="upload-spinner mb-2 mx-auto" />
          <p className="text-sm text-blue-200">Processing...</p>
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
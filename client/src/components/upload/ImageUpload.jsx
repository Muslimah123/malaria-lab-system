import React, { useState, useRef, useCallback } from 'react';
import { Upload, X, FileImage, AlertCircle, CheckCircle } from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';

const ImageUpload = ({
  onFilesSelected,
  maxFiles = 5,
  maxFileSize = 10 * 1024 * 1024, // 10MB
  acceptedTypes = ['image/jpeg', 'image/png', 'image/tiff'],
  existingFiles = [],
  disabled = false
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [validationErrors, setValidationErrors] = useState([]);
  const fileInputRef = useRef(null);

  const validateFile = useCallback((file) => {
    const errors = [];
    
    if (!acceptedTypes.includes(file.type)) {
      errors.push(`${file.name}: Invalid file type. Accepted: ${acceptedTypes.join(', ')}`);
    }
    
    if (file.size > maxFileSize) {
      const maxSizeMB = (maxFileSize / (1024 * 1024)).toFixed(1);
      errors.push(`${file.name}: File too large. Maximum size: ${maxSizeMB}MB`);
    }
    
    if (file.size === 0) {
      errors.push(`${file.name}: Empty file`);
    }

    return errors;
  }, [acceptedTypes, maxFileSize]);

  const validateFiles = useCallback((files) => {
    const fileArray = Array.from(files);
    const totalFiles = existingFiles.length + fileArray.length;
    const errors = [];

    if (totalFiles > maxFiles) {
      errors.push(`Too many files. Maximum allowed: ${maxFiles}`);
    }

    fileArray.forEach(file => {
      errors.push(...validateFile(file));
    });

    return errors;
  }, [existingFiles.length, maxFiles, validateFile]);

  const handleFiles = useCallback((files) => {
    if (disabled) return;
    
    const errors = validateFiles(files);
    setValidationErrors(errors);

    if (errors.length === 0) {
      onFilesSelected(files);
    }
  }, [disabled, validateFiles, onFilesSelected]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFiles(e.dataTransfer.files);
      e.dataTransfer.clearData();
    }
  }, [handleFiles]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setDragActive(true);
    }
  }, [disabled]);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  }, []);

  const handleFileSelect = useCallback((e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(e.target.files);
      // Reset input
      e.target.value = '';
    }
  }, [handleFiles]);

  const clearErrors = () => {
    setValidationErrors([]);
  };

  const formatFileSize = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="space-y-4">
      {/* Upload Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        className={`
          relative border-2 border-dashed rounded-lg p-6 transition-all duration-200
          ${disabled 
            ? 'border-gray-200 bg-gray-50 cursor-not-allowed opacity-50' 
            : dragActive
              ? 'border-primary-500 bg-primary-50 scale-105'
              : 'border-gray-300 hover:border-gray-400 cursor-pointer'
          }
        `}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <div className="text-center">
          <div className={`mx-auto w-12 h-12 rounded-full flex items-center justify-center mb-4 ${
            disabled 
              ? 'bg-gray-200' 
              : dragActive 
                ? 'bg-primary-100' 
                : 'bg-gray-100'
          }`}>
            {disabled ? (
              <LoadingSpinner size="sm" />
            ) : (
              <Upload className={`w-6 h-6 ${
                dragActive ? 'text-primary-600' : 'text-gray-400'
              }`} />
            )}
          </div>

          <div className="mb-4">
            <p className={`text-base font-medium mb-1 ${
              disabled ? 'text-gray-400' : 'text-gray-900'
            }`}>
              {disabled 
                ? 'Upload in progress...'
                : dragActive 
                  ? 'Drop your images here' 
                  : 'Upload blood smear images'
              }
            </p>
            {!disabled && (
              <p className="text-sm text-gray-600">
                Drag and drop files here, or click to browse
              </p>
            )}
          </div>

          {/* File Stats */}
          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="bg-white rounded-lg p-2 border">
              <p className="text-lg font-semibold text-gray-900">{existingFiles.length}</p>
              <p className="text-xs text-gray-500">Uploaded</p>
            </div>
            <div className="bg-white rounded-lg p-2 border">
              <p className="text-lg font-semibold text-gray-900">{maxFiles - existingFiles.length}</p>
              <p className="text-xs text-gray-500">Remaining</p>
            </div>
            <div className="bg-white rounded-lg p-2 border">
              <p className="text-lg font-semibold text-gray-900">{formatFileSize(maxFileSize)}</p>
              <p className="text-xs text-gray-500">Max Size</p>
            </div>
          </div>
        </div>

        {/* Drag Overlay */}
        {dragActive && !disabled && (
          <div className="absolute inset-0 bg-primary-500 bg-opacity-10 rounded-lg flex items-center justify-center">
            <div className="bg-white rounded-lg p-4 shadow-lg">
              <Upload className="w-8 h-8 text-primary-600 mx-auto mb-2" />
              <p className="text-primary-700 font-medium">Drop files to upload</p>
            </div>
          </div>
        )}
      </div>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept={acceptedTypes.join(',')}
        onChange={handleFileSelect}
        className="hidden"
        disabled={disabled}
      />

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-2">
              <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-medium text-red-800 mb-2">
                  Upload Validation Errors
                </h4>
                <ul className="text-sm text-red-700 space-y-1">
                  {validationErrors.map((error, index) => (
                    <li key={index}>• {error}</li>
                  ))}
                </ul>
              </div>
            </div>
            <button
              onClick={clearErrors}
              className="text-red-500 hover:text-red-700"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Upload Guidelines */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-start space-x-2">
          <FileImage className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
          <div>
            <h4 className="text-sm font-medium text-blue-900 mb-2">
              Image Quality Guidelines
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
              <div>
                <h5 className="font-medium mb-1">✓ Good Quality</h5>
                <ul className="space-y-1 text-xs">
                  <li>• High resolution (≥1024px)</li>
                  <li>• Clear focus and lighting</li>
                  <li>• Proper color balance</li>
                  <li>• Multiple fields of view</li>
                </ul>
              </div>
              <div>
                <h5 className="font-medium mb-1">✗ Avoid</h5>
                <ul className="space-y-1 text-xs">
                  <li>• Blurry or out-of-focus</li>
                  <li>• Over/under exposed</li>
                  <li>• Poor color quality</li>
                  <li>• Duplicates or similar views</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Existing Files Preview */}
      {existingFiles.length > 0 && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <CheckCircle className="w-5 h-5 text-green-600" />
            <h4 className="text-sm font-medium text-green-900">
              {existingFiles.length} file(s) ready for upload
            </h4>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {existingFiles.slice(0, 4).map((file, index) => (
              <div key={index} className="text-xs text-green-800 bg-white rounded p-2 border">
                <p className="font-medium truncate">{file.name}</p>
                <p className="text-green-600">{formatFileSize(file.size)}</p>
              </div>
            ))}
            {existingFiles.length > 4 && (
              <div className="text-xs text-green-800 bg-white rounded p-2 border flex items-center justify-center">
                +{existingFiles.length - 4} more
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ImageUpload;
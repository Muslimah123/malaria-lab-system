import React, { useState, useEffect, useRef } from 'react';
import { 
  X, 
  RotateCw, 
  ZoomIn, 
  ZoomOut, 
  Eye, 
  AlertTriangle, 
  CheckCircle, 
  Edit3,
  Download,
  Info,
  RefreshCw
} from 'lucide-react';

const ImagePreview = ({ 
  files = [], 
  onRemove, 
  onReplace, 
  validationResults,
  editable = true,
  onRetryUpload // New prop for retrying individual file uploads
}) => {
  const [selectedImage, setSelectedImage] = useState(null);
  const [imageErrors, setImageErrors] = useState({});
  const modalRef = useRef(null);
  const previousFocusRef = useRef(null);

  const formatFileSize = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileStatus = (file) => {
    const validFile = validationResults?.validFiles?.find(vf => vf.name === file.name);
    const invalidFile = validationResults?.invalidFiles?.find(vf => vf.name === file.name);
    
    if (invalidFile) return 'invalid';
    if (validFile) return 'valid';
    if (file.status === 'error') return 'error';
    if (file.status === 'uploading') return 'uploading';
    if (file.status === 'failed') return 'failed';
    return 'pending';
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'valid':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'invalid':
      case 'error':
      case 'failed':
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'uploading':
        return <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />;
      default:
        return <div className="w-4 h-4 border-2 border-gray-300 rounded-full" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'valid':
        return 'border-green-200 bg-green-50';
      case 'invalid':
      case 'error':
      case 'failed':
        return 'border-red-200 bg-red-50';
      case 'uploading':
        return 'border-blue-200 bg-blue-50';
      default:
        return 'border-gray-200 bg-gray-50';
    }
  };

  const handleImageError = (fileId, error) => {
    setImageErrors(prev => ({
      ...prev,
      [fileId]: error
    }));
  };

  const handleReplaceFile = (fileId) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = (e) => {
      if (e.target.files && e.target.files[0]) {
        onReplace(fileId, e.target.files[0]);
      }
    };
    input.click();
  };

  const handleRetryUpload = (file) => {
    if (onRetryUpload && typeof onRetryUpload === 'function') {
      onRetryUpload(file);
    }
  };

  const ImageModal = ({ image, onClose }) => {
    const [zoom, setZoom] = useState(1);
    const [rotation, setRotation] = useState(0);

    useEffect(() => {
      // Store current focus
      previousFocusRef.current = document.activeElement;
      
      // Focus modal
      if (modalRef.current) {
        modalRef.current.focus();
      }

      // Handle escape key
      const handleEscape = (e) => {
        if (e.key === 'Escape') {
          onClose();
        }
      };

      document.addEventListener('keydown', handleEscape);
      
      return () => {
        document.removeEventListener('keydown', handleEscape);
        // Restore focus
        if (previousFocusRef.current) {
          previousFocusRef.current.focus();
        }
      };
    }, [onClose]);

    // Keyboard navigation
    const handleKeyDown = (e) => {
      switch (e.key) {
        case '+':
        case '=':
          e.preventDefault();
          setZoom(Math.min(3, zoom + 0.25));
          break;
        case '-':
        case '_':
          e.preventDefault();
          setZoom(Math.max(0.5, zoom - 0.25));
          break;
        case 'r':
        case 'R':
          e.preventDefault();
          setRotation((rotation + 90) % 360);
          break;
        case 'ArrowLeft':
          e.preventDefault();
          // Navigate to previous image 
          break;
        case 'ArrowRight':
          e.preventDefault();
          // Navigate to next image
          break;
      }
    };

    if (!image) return null;

    return (
      <div 
        className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <div 
          ref={modalRef}
          className="max-w-4xl max-h-full w-full h-full flex flex-col focus:outline-none"
          tabIndex={-1}
          onKeyDown={handleKeyDown}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-4 bg-white">
            <div>
              <h3 id="modal-title" className="text-lg font-medium text-gray-900">{image.name}</h3>
              <p className="text-sm text-gray-500">{formatFileSize(image.size)}</p>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setZoom(Math.max(0.5, zoom - 0.25))}
                className="p-2 text-gray-600 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary-500 rounded"
                disabled={zoom <= 0.5}
                aria-label="Zoom out"
                title="Zoom out (- key)"
              >
                <ZoomOut className="w-5 h-5" />
              </button>
              <span className="text-sm text-gray-600" aria-live="polite">{Math.round(zoom * 100)}%</span>
              <button
                onClick={() => setZoom(Math.min(3, zoom + 0.25))}
                className="p-2 text-gray-600 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary-500 rounded"
                disabled={zoom >= 3}
                aria-label="Zoom in"
                title="Zoom in (+ key)"
              >
                <ZoomIn className="w-5 h-5" />
              </button>
              <button
                onClick={() => setRotation((rotation + 90) % 360)}
                className="p-2 text-gray-600 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary-500 rounded"
                aria-label="Rotate image"
                title="Rotate (R key)"
              >
                <RotateCw className="w-5 h-5" />
              </button>
              <button
                onClick={onClose}
                className="p-2 text-gray-600 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary-500 rounded"
                aria-label="Close modal"
                title="Close (Esc key)"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Image */}
          <div className="flex-1 flex items-center justify-center p-4 bg-gray-900 overflow-hidden">
            <img
              src={image.preview}
              alt={image.name}
              className="max-w-full max-h-full object-contain transition-transform"
              style={{
                transform: `scale(${zoom}) rotate(${rotation}deg)`
              }}
            />
          </div>

          {/* Keyboard shortcuts help */}
          <div className="bg-gray-800 text-gray-300 text-xs p-2 text-center">
            Keyboard shortcuts: <kbd>+/-</kbd> Zoom • <kbd>R</kbd> Rotate • <kbd>Esc</kbd> Close
          </div>
        </div>
      </div>
    );
  };

  if (files.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <Eye className="w-12 h-12 mx-auto mb-4 text-gray-300" />
        <p>No images to preview</p>
      </div>
    );
  }

  return (
    <>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-md font-medium text-gray-900">
            Image Preview ({files.length} file{files.length !== 1 ? 's' : ''})
          </h4>
          {validationResults && (
            <div className="flex items-center space-x-4 text-sm">
              <span className="text-green-600">
                ✓ {validationResults.validFiles?.length || 0} valid
              </span>
              {validationResults.invalidFiles?.length > 0 && (
                <span className="text-red-600">
                  ✗ {validationResults.invalidFiles.length} invalid
                </span>
              )}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {files.map((file) => {
            const status = getFileStatus(file);
            const hasError = imageErrors[file.id] || status === 'error' || status === 'failed';
            
            return (
              <div
                key={file.id}
                className={`relative rounded-lg border-2 p-3 transition-all ${getStatusColor(status)}`}
              >
                {/* Status Badge */}
                <div className="absolute top-2 left-2 z-10" aria-label={`File status: ${status}`}>
                  {getStatusIcon(status)}
                </div>

                {/* Actions */}
                {editable && (
                  <div className="absolute top-2 right-2 z-10 flex space-x-1">
                    <button
                      onClick={() => setSelectedImage(file)}
                      className="p-1 bg-white rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500"
                      title="View full size"
                      aria-label={`View ${file.name} in full size`}
                    >
                      <Eye className="w-4 h-4 text-gray-600" />
                    </button>
                    {(status === 'failed' || status === 'error') && onRetryUpload && (
                      <button
                        onClick={() => handleRetryUpload(file)}
                        className="p-1 bg-white rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500"
                        title="Retry upload"
                        aria-label={`Retry uploading ${file.name}`}
                      >
                        <RefreshCw className="w-4 h-4 text-orange-600" />
                      </button>
                    )}
                    <button
                      onClick={() => handleReplaceFile(file.id)}
                      className="p-1 bg-white rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500"
                      title="Replace image"
                      aria-label={`Replace ${file.name}`}
                    >
                      <Edit3 className="w-4 h-4 text-gray-600" />
                    </button>
                    <button
                      onClick={() => onRemove(file.id)}
                      className="p-1 bg-white rounded-md shadow-sm hover:bg-gray-50 text-red-600 focus:outline-none focus:ring-2 focus:ring-red-500"
                      title="Remove image"
                      aria-label={`Remove ${file.name}`}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

                {/* Image Preview */}
                <div className="aspect-square mb-3 bg-gray-100 rounded-md overflow-hidden">
                  {hasError ? (
                    <div className="w-full h-full flex items-center justify-center text-gray-400">
                      <div className="text-center">
                        <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
                        <p className="text-xs">Failed to load</p>
                        {(status === 'failed' || status === 'error') && onRetryUpload && (
                          <button
                            onClick={() => handleRetryUpload(file)}
                            className="mt-2 text-xs text-blue-600 hover:text-blue-800 font-medium"
                          >
                            Retry Upload
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    <button
                      onClick={() => setSelectedImage(file)}
                      className="w-full h-full relative group focus:outline-none focus:ring-2 focus:ring-primary-500"
                      aria-label={`View ${file.name} in full size`}
                    >
                      <img
                        src={file.preview}
                        alt={file.name}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                        onError={() => handleImageError(file.id, 'Failed to load image')}
                      />
                      <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-10 transition-opacity" />
                    </button>
                  )}
                </div>

                {/* File Info */}
                <div className="space-y-2">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate" title={file.name}>
                        {file.name}
                      </p>
                      <p className="text-xs text-gray-500">
                        {formatFileSize(file.size)} • {file.type.split('/')[1].toUpperCase()}
                      </p>
                    </div>
                  </div>

                  {/* Validation Messages */}
                  {status === 'invalid' && validationResults?.invalidFiles && (
                    <div className="text-xs text-red-600" role="alert">
                      {validationResults.invalidFiles
                        .find(f => f.name === file.name)
                        ?.errors?.slice(0, 2)
                        .map((error, index) => (
                          <p key={index}>• {error}</p>
                        ))}
                    </div>
                  )}

                  {/* Upload Error Message */}
                  {status === 'failed' && file.errorMessage && (
                    <div className="text-xs text-red-600" role="alert">
                      <p>• {file.errorMessage}</p>
                    </div>
                  )}

                  {/* Upload Progress */}
                  {status === 'uploading' && file.progress !== undefined && (
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs text-gray-600">
                        <span>Uploading...</span>
                        <span aria-live="polite">{file.progress}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-1" role="progressbar" aria-valuenow={file.progress} aria-valuemin="0" aria-valuemax="100">
                        <div
                          className="bg-blue-500 h-1 rounded-full transition-all"
                          style={{ width: `${file.progress}%` }}
                        />
                      </div>
                    </div>
                  )}

                  {/* File Analysis Info */}
                  {status === 'valid' && (
                    <div className="flex items-center space-x-2 text-xs text-green-600">
                      <Info className="w-3 h-3" />
                      <span>Ready for analysis</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Summary */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <p className="text-lg font-semibold text-gray-900">{files.length}</p>
              <p className="text-xs text-gray-500">Total Files</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-green-600">
                {validationResults?.validFiles?.length || files.filter(f => getFileStatus(f) === 'valid').length}
              </p>
              <p className="text-xs text-gray-500">Valid</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-red-600">
                {validationResults?.invalidFiles?.length || files.filter(f => ['invalid', 'error', 'failed'].includes(getFileStatus(f))).length}
              </p>
              <p className="text-xs text-gray-500">Invalid/Failed</p>
            </div>
            <div>
              <p className="text-lg font-semibold text-gray-900">
                {formatFileSize(files.reduce((total, file) => total + file.size, 0))}
              </p>
              <p className="text-xs text-gray-500">Total Size</p>
            </div>
          </div>
        </div>
      </div>

      {/* Image Modal */}
      {selectedImage && (
        <ImageModal
          image={selectedImage}
          onClose={() => setSelectedImage(null)}
        />
      )}
    </>
  );
};

export default ImagePreview;
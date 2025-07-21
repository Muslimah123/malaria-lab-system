// src/components/results/ImageAnnotation.jsx
import React, { useState, useRef, useEffect } from 'react';
import { 
  Camera, 
  ZoomIn, 
  ZoomOut, 
  Eye, 
  EyeOff, 
  RotateCw,
  Maximize,
  Download,
  Maximize2,
  X,
  Info
} from 'lucide-react';

const ImageAnnotation = ({ images = [], className = '' }) => {
  const [selectedImage, setSelectedImage] = useState(0);
  const [showAnnotations, setShowAnnotations] = useState(true);
  const [imageZoom, setImageZoom] = useState(1);
  const [fullscreen, setFullscreen] = useState(false);
  const [imageDimensions, setImageDimensions] = useState({ width: 1, height: 1 });
  const imageRef = useRef(null);
  const containerRef = useRef(null);

  // Update image dimensions when image loads
  const handleImageLoad = (e) => {
    const { naturalWidth, naturalHeight } = e.target;
    setImageDimensions({ width: naturalWidth, height: naturalHeight });
    console.log('Image loaded with dimensions:', naturalWidth, 'x', naturalHeight);
  };

  // Reset zoom when changing images
  useEffect(() => {
    setImageZoom(1);
  }, [selectedImage]);

  if (!images || images.length === 0) {
    return (
      <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 ${className}`}>
        <div className="text-center py-12">
          <Camera className="w-16 h-16 text-blue-300 mx-auto mb-4" />
          <p className="text-white font-medium">No Images Available</p>
          <p className="text-blue-200 text-sm">Images will appear here once analysis is complete</p>
        </div>
      </div>
    );
  }

  const currentImage = images[selectedImage];

  const getAnnotationColor = (type) => {
    const colors = {
      'PF': 'border-red-400 bg-red-400/20',
      'PM': 'border-orange-400 bg-orange-400/20',
      'PO': 'border-yellow-400 bg-yellow-400/20', 
      'PV': 'border-green-400 bg-green-400/20',
      'WBC': 'border-blue-400 bg-blue-400/20'
    };
    return colors[type] || 'border-gray-400 bg-gray-400/20';
  };

  const getParasiteShortName = (type) => {
    const names = {
      'PF': 'P.F',
      'PM': 'P.M',
      'PO': 'P.O',
      'PV': 'P.V'
    };
    return names[type] || type;
  };

  const resetZoom = () => setImageZoom(1);

  const downloadImage = () => {
    if (currentImage?.url) {
      const link = document.createElement('a');
      link.href = currentImage.url;
      link.download = currentImage.originalFilename || `image-${selectedImage + 1}.jpg`;
      link.click();
    }
  };

  const toggleFullscreen = () => {
    setFullscreen(!fullscreen);
  };

  // Calculate annotation position
  const getAnnotationPosition = (bbox) => {
    if (!bbox || !imageRef.current) return null;

    // Get the displayed image dimensions
    const imageRect = imageRef.current.getBoundingClientRect();
    const containerRect = containerRef.current.getBoundingClientRect();

    // Calculate scale factors
    const scaleX = imageRect.width / imageDimensions.width;
    const scaleY = imageRect.height / imageDimensions.height;

    // Calculate offset from container
    const offsetX = imageRect.left - containerRect.left;
    const offsetY = imageRect.top - containerRect.top;

    return {
      left: offsetX + (bbox.x1 * scaleX),
      top: offsetY + (bbox.y1 * scaleY),
      width: (bbox.x2 - bbox.x1) * scaleX,
      height: (bbox.y2 - bbox.y1) * scaleY
    };
  };

  return (
    <>
      <div className={`bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6 ${className} ${fullscreen ? 'hidden' : ''}`}>
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-lg font-semibold text-white flex items-center">
            <Camera className="w-5 h-5 mr-2 text-blue-400" />
            Analysis ({images.length} images)
          </h3>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowAnnotations(!showAnnotations)}
              className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-all hover:scale-105 ${
                showAnnotations 
                  ? 'bg-white text-blue-600' 
                  : 'bg-white/10 hover:bg-white/20 border border-white/30 text-white'
              }`}
            >
              {showAnnotations ? <Eye className="w-4 h-4 mr-1" /> : <EyeOff className="w-4 h-4 mr-1" />}
              Annotations
            </button>
            <div className="flex items-center space-x-1 bg-white/10 backdrop-blur-md rounded-lg px-3 py-2 border border-white/20">
              <button
                onClick={() => setImageZoom(Math.max(0.5, imageZoom - 0.25))}
                className="p-1 rounded hover:bg-white/20 transition-colors"
                disabled={imageZoom <= 0.5}
              >
                <ZoomOut className="w-4 h-4 text-white" />
              </button>
              <span className="text-sm text-blue-200 min-w-12 text-center">{Math.round(imageZoom * 100)}%</span>
              <button
                onClick={() => setImageZoom(Math.min(3, imageZoom + 0.25))}
                className="p-1 rounded hover:bg-white/20 transition-colors"
                disabled={imageZoom >= 3}
              >
                <ZoomIn className="w-4 h-4 text-white" />
              </button>
              <div className="w-px h-4 bg-white/20 mx-1" />
              <button
                onClick={resetZoom}
                className="p-1 rounded hover:bg-white/20 transition-colors text-xs"
                title="Reset zoom"
              >
                1:1
              </button>
            </div>
            <button
              onClick={toggleFullscreen}
              className="p-2 rounded-lg bg-white/10 hover:bg-white/20 border border-white/30 text-white transition-colors"
              title="Fullscreen"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
            <button
              onClick={downloadImage}
              className="p-2 rounded-lg bg-white/10 hover:bg-white/20 border border-white/30 text-white transition-colors"
              title="Download image"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Image Thumbnails */}
        <div className="flex space-x-3 mb-6 overflow-x-auto pb-2">
          {images.map((image, index) => (
            <button
              key={image.imageId || index}
              onClick={() => setSelectedImage(index)}
              className={`flex-shrink-0 relative p-3 rounded-lg border-2 transition-all hover:scale-105 backdrop-blur-md ${
                selectedImage === index 
                  ? 'border-white bg-white/20' 
                  : 'border-white/20 bg-white/10 hover:border-white/40'
              }`}
            >
              <div className="w-20 h-20 bg-white/10 rounded flex items-center justify-center overflow-hidden">
                {image.url ? (
                  <img 
                    src={image.url} 
                    alt={image.originalFilename}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <Camera className="w-6 h-6 text-blue-300" />
                )}
              </div>
              <div className="text-xs text-center mt-2">
                <div className="font-medium text-white">
                  {image.annotations?.summary?.parasiteCount || 0} parasites
                </div>
                <div className="text-blue-200">
                  {image.annotations?.summary?.wbcCount || 0} WBCs
                </div>
              </div>
              {selectedImage === index && (
                <div className="absolute -bottom-1 left-1/2 transform -translate-x-1/2 w-2 h-2 bg-white rounded-full" />
              )}
            </button>
          ))}
        </div>

        {/* Main Image Display */}
        <div className="border-2 border-white/20 rounded-lg overflow-hidden bg-white/5 backdrop-blur-md">
          <div ref={containerRef} className="relative h-96 overflow-hidden">
            {currentImage?.url ? (
              <div className="w-full h-full flex items-center justify-center">
                <img 
                  ref={imageRef}
                  src={currentImage.url}
                  alt={currentImage.originalFilename}
                  className="max-w-full max-h-full object-contain transition-transform duration-200"
                  style={{ transform: `scale(${imageZoom})` }}
                  onLoad={handleImageLoad}
                />
                
                {/* Annotation Overlays */}
                {showAnnotations && currentImage?.annotations?.parasites && imageRef.current && (
                  <div className="absolute inset-0 pointer-events-none">
                    {currentImage.annotations.parasites.map((annotation, index) => {
                      // Use boundingBox or bbox depending on what the API returns
                      const bbox = annotation.boundingBox || annotation.bbox;
                      if (!bbox) return null;

                      const position = getAnnotationPosition(bbox);
                      if (!position) return null;

                      return (
                        <div
                          key={index}
                          className={`absolute border-2 rounded ${getAnnotationColor(annotation.type)}`}
                          style={{
                            left: `${position.left}px`,
                            top: `${position.top}px`,
                            width: `${position.width}px`,
                            height: `${position.height}px`,
                            transform: `scale(${imageZoom})`,
                            transformOrigin: 'top left'
                          }}
                        >
                          <div className={`absolute -top-6 left-0 px-2 py-1 text-xs font-medium rounded backdrop-blur-md ${getAnnotationColor(annotation.type)} text-white whitespace-nowrap`}>
                            {getParasiteShortName(annotation.type)} {Math.round((annotation.confidence || 0) * 100)}%
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ) : (
              <div className="w-full h-full bg-gradient-to-br from-purple-900/20 via-blue-900/20 to-pink-900/20 flex items-center justify-center">
                <div className="text-center">
                  <Camera className="w-16 h-16 text-blue-300 mx-auto mb-4" />
                  <p className="text-white font-medium">Blood Smear Analysis</p>
                  <p className="text-sm text-blue-200">
                    {currentImage?.originalFilename || 'Image not available'}
                  </p>
                  <div className="mt-3 inline-flex items-center px-3 py-1 bg-white/10 backdrop-blur-md rounded-full border border-white/20">
                    <Camera className="w-3 h-3 mr-1 text-blue-400" />
                    <span className="text-xs text-blue-200">AI Analysis Complete</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Image Stats */}
        {currentImage && (
          <div className="mt-6 grid grid-cols-3 gap-4">
            <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
              <div className="text-xl font-bold text-red-400">
                {currentImage.annotations?.summary?.parasiteCount || 0}
              </div>
              <div className="text-sm text-blue-200">Parasites Detected</div>
            </div>
            <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
              <div className="text-xl font-bold text-blue-400">
                {currentImage.annotations?.summary?.wbcCount || 0}
              </div>
              <div className="text-sm text-blue-200">White Blood Cells</div>
            </div>
            <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
              <div className="text-xl font-bold text-purple-400">
                {currentImage.annotations?.parasites?.length || 0}
              </div>
              <div className="text-sm text-blue-200">Annotations</div>
            </div>
          </div>
        )}

        {/* Image Info */}
        {currentImage && (
          <div className="mt-4 flex items-center justify-between text-sm">
            <div className="flex items-center text-blue-200">
              <Info className="w-4 h-4 mr-1" />
              {currentImage.originalFilename} 
              {currentImage.metadata?.size && (
                <span className="ml-2">• {(currentImage.metadata.size / 1024 / 1024).toFixed(1)} MB</span>
              )}
            </div>
            {currentImage.annotations?.parasites && currentImage.annotations.parasites.length > 0 && (
              <div className="flex items-center space-x-2">
                {Object.entries(
                  currentImage.annotations.parasites.reduce((acc, p) => {
                    acc[p.type] = (acc[p.type] || 0) + 1;
                    return acc;
                  }, {})
                ).map(([type, count]) => (
                  <span key={type} className={`px-2 py-1 rounded text-xs font-medium ${getAnnotationColor(type)} text-white`}>
                    {count} {type}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Fullscreen Mode */}
      {fullscreen && currentImage && (
        <div className="fixed inset-0 z-50 bg-black/95 flex items-center justify-center">
          <button
            onClick={toggleFullscreen}
            className="absolute top-4 right-4 p-2 bg-white/10 hover:bg-white/20 rounded-lg text-white transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
          
          <div className="relative max-w-full max-h-full p-8">
            <img 
              src={currentImage.url}
              alt={currentImage.originalFilename}
              className="max-w-full max-h-full object-contain"
              style={{ transform: `scale(${imageZoom})` }}
            />
          </div>

          {/* Zoom Controls in Fullscreen */}
          <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 flex items-center space-x-2 bg-white/10 backdrop-blur-md rounded-lg px-4 py-2">
            <button
              onClick={() => setImageZoom(Math.max(0.5, imageZoom - 0.25))}
              className="p-1 rounded hover:bg-white/20 transition-colors"
            >
              <ZoomOut className="w-5 h-5 text-white" />
            </button>
            <span className="text-white min-w-16 text-center">{Math.round(imageZoom * 100)}%</span>
            <button
              onClick={() => setImageZoom(Math.min(3, imageZoom + 0.25))}
              className="p-1 rounded hover:bg-white/20 transition-colors"
            >
              <ZoomIn className="w-5 h-5 text-white" />
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export default ImageAnnotation;
// src/components/results/ImageAnnotation.jsx
import React, { useState, useRef, useEffect, useCallback } from 'react';
import { 
  Camera, 
  ZoomIn, 
  ZoomOut, 
  Eye, 
  EyeOff, 
  Download,
  Maximize2,
  X,
  Info,
  Sparkles,
  Target,
  Activity
} from 'lucide-react';

const ImageAnnotation = ({ images = [], className = '' }) => {
  const [selectedImage, setSelectedImage] = useState(0);
  const [showAnnotations, setShowAnnotations] = useState(true);
  const [imageZoom, setImageZoom] = useState(1);
  const [fullscreen, setFullscreen] = useState(false);
  const [imageDimensions, setImageDimensions] = useState({ width: 1, height: 1 });
  const [fullscreenImageDimensions, setFullscreenImageDimensions] = useState({ width: 1, height: 1 });
  
  const imageRef = useRef(null);
  const containerRef = useRef(null);
  const fullscreenImageRef = useRef(null);
  const fullscreenContainerRef = useRef(null);

  // Reset zoom when changing images
  useEffect(() => {
    setImageZoom(1);
  }, [selectedImage]);

  // Debug logging for current image data
  useEffect(() => {
    if (images && images.length > 0) {
      const currentImage = images[selectedImage];
      if (currentImage) {
        console.log('Current image changed:', currentImage);
        console.log('Image annotations:', currentImage.annotations);
                 if (currentImage.annotations) {
           console.log('Parasites count:', currentImage.annotations.parasites?.length || 0);
           console.log('WBCs count:', currentImage.annotations.wbcs?.length || 0);
           console.log('WBCs data:', currentImage.annotations.wbcs);
           console.log('Summary data:', currentImage.annotations.summary);
           console.log('First parasite annotation:', currentImage.annotations.parasites?.[0]);
           console.log('First WBC annotation:', currentImage.annotations.wbcs?.[0]);
         }
      }
    }
  }, [selectedImage, images]);

  // Calculate annotation position for regular view
  const getAnnotationPosition = useCallback((bbox) => {
    if (!bbox || !imageRef.current || !containerRef.current) return null;

    // Get the actual displayed image dimensions and position
    const imageRect = imageRef.current.getBoundingClientRect();
    const containerRect = containerRef.current.getBoundingClientRect();

    // Calculate the scale factors between original image and displayed image
    const scaleX = imageRect.width / imageDimensions.width;
    const scaleY = imageRect.height / imageDimensions.height;

    // Calculate the offset of the image within its container
    const offsetX = imageRect.left - containerRect.left;
    const offsetY = imageRect.top - containerRect.top;

    // ✅ FIXED: Handle both array and object bbox formats from detection system
    let x1, y1, x2, y2;
    
    if (Array.isArray(bbox) && bbox.length === 4) {
      // Python returns [x_min, y_min, x_max, y_max] array format
      [x1, y1, x2, y2] = bbox;
    } else if (bbox.x1 !== undefined && bbox.y1 !== undefined && bbox.x2 !== undefined && bbox.y2 !== undefined) {
      // Backend converted to {x1, y1, x2, y2} object format
      x1 = bbox.x1;
      y1 = bbox.y1;
      x2 = bbox.x2;
      y2 = bbox.y2;
    } else {
      console.error('Invalid bbox format:', bbox);
      return null;
    }

    // Calculate position using actual image coordinates
    const left = offsetX + (x1 * scaleX);
    const top = offsetY + (y1 * scaleY);
    const width = (x2 - x1) * scaleX;
    const height = (y2 - y1) * scaleY;
    
    // Debug position calculation
    console.log('Annotation position calculation:', {
      bbox: { x1, y1, x2, y2 },
      imageDimensions,
      scaleX,
      scaleY,
      offsetX,
      offsetY,
      left,
      top,
      width,
      height
    });

    return { left, top, width, height };
  }, [imageDimensions]);

  // Calculate annotation position for fullscreen view
  const getFullscreenAnnotationPosition = useCallback((bbox) => {
    if (!bbox || !fullscreenImageRef.current || !fullscreenContainerRef.current) return null;

    // Get the actual displayed fullscreen image dimensions and position
    const imageRect = fullscreenImageRef.current.getBoundingClientRect();
    const containerRect = fullscreenContainerRef.current.getBoundingClientRect();

    // Calculate the scale factors between original image and displayed fullscreen image
    const scaleX = imageRect.width / fullscreenImageDimensions.width;
    const scaleY = imageRect.height / fullscreenImageDimensions.height;

    // Calculate the offset of the image within its container
    const offsetX = imageRect.left - containerRect.left;
    const offsetY = imageRect.top - containerRect.top;

    // ✅ FIXED: Handle both array and object bbox formats from detection system
    let x1, y1, x2, y2;
    
    if (Array.isArray(bbox) && bbox.length === 4) {
      // Python returns [x_min, y_min, x_max, y_max] array format
      [x1, y1, x2, y2] = bbox;
    } else if (bbox.x1 !== undefined && bbox.y1 !== undefined && bbox.x2 !== undefined && bbox.y2 !== undefined) {
      // Backend converted to {x1, y1, x2, y2} object format
      x1 = bbox.x1;
      y1 = bbox.y1;
      x2 = bbox.x2;
      y2 = bbox.y2;
    } else {
      console.error('Invalid bbox format for fullscreen:', bbox);
      return null;
    }

    // Calculate position using actual image coordinates
    const left = offsetX + (x1 * scaleX);
    const top = offsetY + (y1 * scaleY);
    const width = (x2 - x1) * scaleX;
    const height = (y2 - y1) * scaleY;

    return { left, top, width, height };
  }, [fullscreenImageDimensions]);

  // Early return if no images
  if (!images || images.length === 0) {
    return (
      <div className={`bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl p-8 ${className}`}>
        <div className="text-center py-16">
          <div className="relative">
            <Camera className="w-20 h-20 text-blue-300 mx-auto mb-6 drop-shadow-lg" />
            <Sparkles className="w-6 h-6 text-blue-400 absolute top-0 right-4 animate-pulse" />
          </div>
          <h3 className="text-white font-bold text-xl mb-2">No Images Available</h3>
          <p className="text-blue-200 text-sm">Images will appear here once analysis is complete</p>
        </div>
      </div>
    );
  }

  // Get current image after checking if images exist
  const currentImage = images[selectedImage];
  const displayUrl = currentImage?.annotatedUrl || currentImage?.url;
  const overlayAvailable = !currentImage?.annotatedUrl;

  // Update image dimensions when image loads (regular view)
  const handleImageLoad = (e) => {
    const { naturalWidth, naturalHeight } = e.target;
    setImageDimensions({ width: naturalWidth, height: naturalHeight });
    console.log('Regular image loaded with dimensions:', naturalWidth, 'x', naturalHeight);
    
         if (currentImage?.annotations) {
       console.log('Image loaded with annotations:', currentImage.annotations);
       console.log('Parasites:', currentImage.annotations.parasites);
       console.log('WBCs:', currentImage.annotations.wbcs);
       console.log('Summary:', currentImage.annotations.summary);
       console.log('Parasite count from summary:', currentImage.annotations.summary?.parasiteCount);
       console.log('WBC count from summary:', currentImage.annotations.summary?.wbcCount);
       console.log('Image dimensions:', imageDimensions);
     }
  };

  // Update image dimensions when fullscreen image loads
  const handleFullscreenImageLoad = (e) => {
    const { naturalWidth, naturalHeight } = e.target;
    setFullscreenImageDimensions({ width: naturalWidth, height: naturalHeight });
    console.log('Fullscreen image loaded with dimensions:', naturalWidth, 'x', naturalHeight);
  };

  const getAnnotationColor = (type) => {
    // Match Python styling: red for all parasites, blue for WBCs
    if (type === 'WBC') {
      return 'border-blue-500 bg-blue-500/10';
    } else {
      // All parasite types use red (PF, PM, PO, PV, etc.)
      return 'border-red-500 bg-red-500/10';
    }
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
    if (displayUrl) {
      const link = document.createElement('a');
      link.href = displayUrl;
      link.download = currentImage.originalFilename || `image-${selectedImage + 1}.jpg`;
      link.click();
    }
  };

  const toggleFullscreen = () => {
    setFullscreen(!fullscreen);
  };

  // Component to render annotations
  const AnnotationOverlay = ({ isFullscreen = false }) => {
    if (!overlayAvailable) return null;
    const getPosition = isFullscreen ? getFullscreenAnnotationPosition : getAnnotationPosition;
    
    console.log('AnnotationOverlay rendering for:', isFullscreen ? 'fullscreen' : 'regular');
    console.log('Current image annotations:', currentImage?.annotations);
    console.log('Parasites to render:', currentImage?.annotations?.parasites);
    console.log('WBCs to render:', currentImage?.annotations?.wbcs);
    
    return (
      <div className="absolute inset-0 pointer-events-none">
                 {/* Render Parasite Annotations */}
         {currentImage?.annotations?.parasites && currentImage.annotations.parasites.map((annotation, index) => {
          // ✅ FIXED: Handle both bbox formats from detection system
          const bbox = annotation.boundingBox || annotation.bbox;
          if (!bbox) return null;
          
          // Debug bbox format
          console.log('Parasite annotation:', annotation);
          console.log('Parasite bbox:', bbox);
          console.log('Parasite confidence:', annotation.confidence);

          const position = getPosition(bbox);
          if (!position) return null;

          return (
            <div
              key={`${isFullscreen ? 'fullscreen-' : ''}parasite-${index}`}
              className="absolute"
              style={{
                left: `${position.left}px`,
                top: `${position.top}px`,
                width: `${position.width}px`,
                height: `${position.height}px`,
                transform: `scale(${imageZoom})`,
                transformOrigin: 'top left'
              }}
            >
              {/* Red bounding box - matching Python matplotlib style */}
              <div 
                className="absolute inset-0 border-2 border-red-500 bg-red-500/5 hover:bg-red-500/10 transition-colors duration-200"
                style={{
                  borderWidth: '2px',
                  borderStyle: 'solid',
                  borderColor: '#ef4444' // red-500
                }}
              />
              
              {/* Label with white background - matching Python style */}
              <div 
                className="absolute -top-6 left-0 px-2 py-1 text-xs font-bold text-red-500 whitespace-nowrap"
                style={{
                  backgroundColor: 'rgba(255, 255, 255, 0.95)',
                  border: '1px solid #ef4444',
                  borderRadius: '4px',
                  boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
                  backdropFilter: 'blur(2px)'
                }}
              >
                {annotation.type} ({Math.round((annotation.confidence || 0) * 100)}%)
              </div>
              
              {/* High confidence indicator */}
              {annotation.confidence > 0.9 && (
                <div className="absolute inset-0 border-2 border-red-500 animate-pulse opacity-50" />
              )}
            </div>
          );
        })}
        
                 {/* Render WBC Annotations */}
         {currentImage?.annotations?.wbcs && currentImage.annotations.wbcs.map((annotation, index) => {
          // ✅ FIXED: Handle both bbox formats from detection system
          const bbox = annotation.boundingBox || annotation.bbox;
          if (!bbox) return null;
          
          // Debug bbox format
          console.log('WBC annotation:', annotation);
          console.log('WBC bbox:', bbox);
          console.log('WBC confidence:', annotation.confidence);

          const position = getPosition(bbox);
          if (!position) return null;

          return (
            <div
              key={`${isFullscreen ? 'fullscreen-' : ''}wbc-${index}`}
              className="absolute"
              style={{
                left: `${position.left}px`,
                top: `${position.top}px`,
                width: `${position.width}px`,
                height: `${position.height}px`,
                transform: `scale(${imageZoom})`,
                transformOrigin: 'top left'
              }}
            >
              {/* Blue bounding box - matching Python matplotlib style */}
              <div 
                className="absolute inset-0 border-2 border-blue-500 bg-blue-500/5 hover:bg-blue-500/10 transition-colors duration-200"
                style={{
                  borderWidth: '2px',
                  borderStyle: 'solid',
                  borderColor: '#3b82f6' // blue-500
                }}
              />
              
              {/* Label with white background - matching Python style */}
              <div 
                className="absolute -top-6 left-0 px-2 py-1 text-xs font-bold text-blue-500 whitespace-nowrap"
                style={{
                  backgroundColor: 'rgba(255, 255, 255, 0.95)',
                  border: '1px solid #3b82f6',
                  borderRadius: '4px',
                  boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
                  backdropFilter: 'blur(2px)'
                }}
              >
                WBC ({Math.round((annotation.confidence || 0) * 100)}%)
              </div>
              
              {/* High confidence indicator */}
              {annotation.confidence > 0.9 && (
                <div className="absolute inset-0 border-2 border-blue-500 animate-pulse opacity-50" />
              )}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <>
      <div className={`bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl p-6 overflow-hidden ${className} ${fullscreen ? 'hidden' : ''}`}>
        {/* Background Effects */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5" />
        <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-bl from-white/10 to-transparent rounded-full blur-3xl" />
        
        <div className="relative">
          {/* Enhanced Header */}
          <div className="flex justify-between items-center mb-8">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-blue-500/20 rounded-xl border border-blue-500/30 backdrop-blur-sm">
                <Camera className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white"> Analysis</h3>
                <p className="text-blue-200 text-sm">{images.length} high-resolution images</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              {/* Enhanced Annotations Toggle */}
              {overlayAvailable ? (
                <button
                  onClick={() => setShowAnnotations(!showAnnotations)}
                  className={`flex items-center px-4 py-2 rounded-xl text-sm font-bold transition-all duration-300 hover:scale-105 shadow-lg ${
                    showAnnotations 
                      ? 'bg-gradient-to-r from-blue-500 to-blue-600 text-white shadow-blue-500/50' 
                      : 'bg-white/10 hover:bg-white/20 border border-white/30 text-white backdrop-blur-sm'
                  }`}
                >
                  {showAnnotations ? <Eye className="w-4 h-4 mr-2" /> : <EyeOff className="w-4 h-4 mr-2" />}
                  AI Annotations
                  {showAnnotations && <Sparkles className="w-3 h-3 ml-1 animate-pulse" />}
                </button>
              ) : null}
              
              {/* Enhanced Zoom Controls */}
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-md rounded-xl px-4 py-2 border border-white/20 shadow-lg">
                <button
                  onClick={() => setImageZoom(Math.max(0.5, imageZoom - 0.25))}
                  className="p-2 rounded-lg hover:bg-white/20 transition-all duration-200 hover:scale-110"
                  disabled={imageZoom <= 0.5}
                >
                  <ZoomOut className="w-4 h-4 text-white" />
                </button>
                <span className="text-sm text-blue-200 min-w-12 text-center font-bold">{Math.round(imageZoom * 100)}%</span>
                <button
                  onClick={() => setImageZoom(Math.min(3, imageZoom + 0.25))}
                  className="p-2 rounded-lg hover:bg-white/20 transition-all duration-200 hover:scale-110"
                  disabled={imageZoom >= 3}
                >
                  <ZoomIn className="w-4 h-4 text-white" />
                </button>
                <div className="w-px h-4 bg-white/20 mx-2" />
                <button
                  onClick={resetZoom}
                  className="px-2 py-1 rounded-lg hover:bg-white/20 transition-all duration-200 text-xs font-bold text-blue-200"
                  title="Reset zoom"
                >
                  1:1
                </button>
              </div>
              
              {/* Action Buttons */}
              <button
                onClick={toggleFullscreen}
                className="p-3 rounded-xl bg-white/10 hover:bg-white/20 border border-white/30 text-white transition-all duration-300 hover:scale-110 backdrop-blur-sm shadow-lg"
                title="Fullscreen"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
              <button
                onClick={downloadImage}
                className="p-3 rounded-xl bg-white/10 hover:bg-white/20 border border-white/30 text-white transition-all duration-300 hover:scale-110 backdrop-blur-sm shadow-lg"
                title="Download image"
              >
                <Download className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Enhanced Image Thumbnails */}
          <div className="mb-8">
            <div className="flex space-x-4 overflow-x-auto pb-4">
              {images.map((image, index) => (
                <button
                  key={image.imageId || index}
                  onClick={() => setSelectedImage(index)}
                  className={`group flex-shrink-0 relative p-4 rounded-xl border-2 transition-all duration-300 hover:scale-105 backdrop-blur-md ${
                    selectedImage === index 
                      ? 'border-blue-400 bg-gradient-to-br from-blue-500/20 to-blue-600/30 shadow-lg shadow-blue-500/25' 
                      : 'border-white/20 bg-white/5 hover:border-white/40 hover:bg-white/10'
                  }`}
                >
                                   <div className="w-24 h-24 bg-gradient-to-br from-white/10 to-white/5 rounded-lg flex items-center justify-center overflow-hidden border border-white/20">
                  {image.annotatedUrl || image.url ? (
                     <img 
                      src={image.annotatedUrl || image.url} 
                       alt={image.originalFilename || `Image ${index + 1}`}
                       className="w-full h-full object-cover rounded-lg"
                       onError={(e) => {
                        console.warn('Thumbnail image failed to load:', image.annotatedUrl || image.url);
                         e.target.style.display = 'none';
                       }}
                     />
                   ) : (
                     <Camera className="w-8 h-8 text-blue-300" />
                   )}
                 </div>
                  
                                     <div className="text-xs text-center mt-3 space-y-1">
                     <div className="font-bold text-white flex items-center justify-center space-x-1">
                       <Target className="w-3 h-3 text-red-400" />
                       <span>{image.annotations?.parasites?.length || 0} parasites</span>
                     </div>
                     <div className="text-blue-200 flex items-center justify-center space-x-1">
                       <Activity className="w-3 h-3 text-blue-400" />
                       <span>{image.annotations?.wbcs?.length || 0} WBCs</span>
                     </div>
                   </div>
                  
                  {/* Selection Indicator */}
                  {selectedImage === index && (
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2">
                      <div className="w-3 h-3 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 animate-pulse" />
                    </div>
                  )}
                  
                  {/* Hover Glow Effect */}
                  <div className={`absolute inset-0 rounded-xl border-2 border-blue-400/0 group-hover:border-blue-400/50 transition-all duration-300 ${selectedImage === index ? 'animate-pulse' : ''}`} />
                </button>
              ))}
            </div>
          </div>

          {/* Enhanced Main Image Display */}
          <div className="border-2 border-white/30 rounded-2xl overflow-hidden bg-gradient-to-br from-white/5 to-white/10 backdrop-blur-md">
            <div ref={containerRef} className="relative h-[500px] overflow-hidden">
                            {displayUrl ? (
                 <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-gray-900/50 to-gray-800/50">
                   <img 
                     ref={imageRef}
                    src={displayUrl}
                     alt={currentImage.originalFilename || `Image ${selectedImage + 1}`}
                     className="max-w-full max-h-full object-contain transition-transform duration-300"
                     style={{ transform: `scale(${imageZoom})` }}
                     onLoad={handleImageLoad}
                     onError={(e) => {
                      console.error('Main image failed to load:', displayUrl);
                     }}
                   />
                  
                                     {/* Enhanced Annotation Overlays */}
                  {overlayAvailable && showAnnotations && <AnnotationOverlay />}
                  {overlayAvailable && !showAnnotations && (
                     <div className="absolute top-4 left-4 bg-black/70 text-white px-3 py-2 rounded-lg">
                       Annotations hidden
                     </div>
                   )}
                  
                  {/* Zoom Level Indicator */}
                  {imageZoom !== 1 && (
                    <div className="absolute top-4 right-4 bg-black/70 backdrop-blur-md rounded-lg px-3 py-2 text-white text-sm font-bold border border-white/20">
                      <div className="flex items-center space-x-2">
                        <Target className="w-4 h-4" />
                        <span>{Math.round(imageZoom * 100)}% Magnification</span>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="w-full h-full bg-gradient-to-br from-purple-900/20 via-blue-900/20 to-pink-900/20 flex items-center justify-center">
                  <div className="text-center">
                    <Camera className="w-20 h-20 text-blue-300 mx-auto mb-6 drop-shadow-lg" />
                    <h4 className="text-white font-bold text-lg mb-2">Blood Smear Analysis</h4>
                    <p className="text-sm text-blue-200 mb-4">
                      {currentImage?.originalFilename || 'Image not available'}
                    </p>
                    <div className="inline-flex items-center px-4 py-2 bg-white/10 backdrop-blur-md rounded-full border border-white/20">
                      <Sparkles className="w-4 h-4 mr-2 text-blue-400 animate-pulse" />
                      <span className="text-xs text-blue-200 font-medium">AI Analysis Complete</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Enhanced Image Stats */}
          {currentImage && (
            <div className="mt-8 grid grid-cols-3 gap-4">
                             <div className="group text-center p-6 bg-gradient-to-br from-red-500/10 via-red-500/5 to-transparent border border-red-500/20 rounded-xl hover:bg-red-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
                 <div className="text-3xl font-bold text-red-400 group-hover:text-red-300 transition-colors mb-2">
                   {currentImage.annotations?.parasites?.length || 0}
                 </div>
                 <div className="text-sm text-red-200 font-medium flex items-center justify-center space-x-1">
                   <Target className="w-4 h-4" />
                   <span>Parasites Detected</span>
                 </div>
               </div>
               
               <div className="group text-center p-6 bg-gradient-to-br from-blue-500/10 via-blue-500/5 to-transparent border border-blue-500/20 rounded-xl hover:bg-blue-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
                 <div className="text-3xl font-bold text-blue-400 group-hover:text-blue-300 transition-colors mb-2">
                   {currentImage.annotations?.wbcs?.length || 0}
                 </div>
                 <div className="text-sm text-blue-200 font-medium flex items-center justify-center space-x-1">
                   <Activity className="w-4 h-4" />
                   <span>White Blood Cells</span>
                 </div>
               </div>
              
              <div className="group text-center p-6 bg-gradient-to-br from-purple-500/10 via-purple-500/5 to-transparent border border-purple-500/20 rounded-xl hover:bg-purple-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
                <div className="text-3xl font-bold text-purple-400 group-hover:text-purple-300 transition-colors mb-2">
                  {currentImage.annotations?.parasites?.length || 0}
                </div>
                <div className="text-sm text-purple-200 font-medium flex items-center justify-center space-x-1">
                  <Sparkles className="w-4 h-4" />
                  <span>Annotations</span>
                </div>
              </div>
            </div>
          )}

          {/* Enhanced Image Info */}
          {currentImage && (
            <div className="mt-6 p-4 bg-gradient-to-r from-white/5 via-white/10 to-white/5 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center text-blue-200 space-x-2">
                  <Info className="w-4 h-4" />
                  <span className="font-medium">{currentImage.originalFilename}</span>
                  {currentImage.metadata?.size && (
                    <span className="text-blue-300">
                      • {(currentImage.metadata.size / 1024 / 1024).toFixed(1)} MB
                    </span>
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
                      <span key={type} className={`px-1.5 py-0.5 rounded text-xs font-bold border ${getAnnotationColor(type)} text-white bg-black`}>
                        {count} {type}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Enhanced Fullscreen Mode */}
      {fullscreen && currentImage && (
        <div className="fixed inset-0 z-50 bg-black/95 backdrop-blur-sm flex items-center justify-center">
          <button
            onClick={toggleFullscreen}
            className="absolute top-6 right-6 p-3 bg-white/10 hover:bg-white/20 rounded-xl text-white transition-all duration-300 hover:scale-110 backdrop-blur-md border border-white/20 shadow-lg z-10"
          >
            <X className="w-6 h-6" />
          </button>
          
            <div ref={fullscreenContainerRef} className="relative max-w-full max-h-full p-8">
             <img 
               ref={fullscreenImageRef}
               src={displayUrl}
               alt={currentImage.originalFilename || `Image ${selectedImage + 1}`}
               className="max-w-full max-h-full object-contain transition-transform duration-300"
               style={{ transform: `scale(${imageZoom})` }}
               onLoad={handleFullscreenImageLoad}
               onError={(e) => {
                console.error('Fullscreen image failed to load:', displayUrl);
               }}
             />
            
            {/* Fullscreen Annotation Overlays */}
            {overlayAvailable && showAnnotations && <AnnotationOverlay isFullscreen={true} />}
          </div>

          {/* Enhanced Zoom Controls in Fullscreen */}
          <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 flex items-center space-x-4 bg-black/70 backdrop-blur-md rounded-2xl px-6 py-3 border border-white/20 shadow-2xl">
            <button
              onClick={() => setImageZoom(Math.max(0.5, imageZoom - 0.25))}
              className="p-2 rounded-xl hover:bg-white/20 transition-all duration-200 hover:scale-110"
            >
              <ZoomOut className="w-6 h-6 text-white" />
            </button>
            <span className="text-white font-bold min-w-20 text-center text-lg">{Math.round(imageZoom * 100)}%</span>
            <button
              onClick={() => setImageZoom(Math.min(3, imageZoom + 0.25))}
              className="p-2 rounded-xl hover:bg-white/20 transition-all duration-200 hover:scale-110"
            >
              <ZoomIn className="w-6 h-6 text-white" />
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export default ImageAnnotation;
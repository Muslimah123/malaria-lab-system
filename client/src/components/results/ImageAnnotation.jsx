// src/components/results/ImageAnnotation.jsx
import React, { useState } from 'react';
import {
  Camera,
  ZoomIn,
  ZoomOut,
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
  const [imageZoom, setImageZoom] = useState(1);
  const [fullscreen, setFullscreen] = useState(false);
  const [viewMode, setViewMode] = useState('ai'); // 'ai' | 'reviewed'

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

  const currentImage = images[selectedImage];
  const hasReviewed  = !!currentImage?.reviewedImageUrl;
  // In reviewed mode show the clinician image; AI mode shows the model-baked image
  const displayUrl = viewMode === 'reviewed' && hasReviewed
    ? currentImage.reviewedImageUrl
    : currentImage?.annotatedUrl || currentImage?.originalUrl || currentImage?.url;

  const resetZoom = () => setImageZoom(1);

  const downloadImage = () => {
    if (displayUrl) {
      const link = document.createElement('a');
      link.href = displayUrl;
      link.download = currentImage.originalFilename || `image-${selectedImage + 1}.jpg`;
      link.click();
    }
  };

  return (
    <>
      <div className={`bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl p-6 overflow-hidden ${className} ${fullscreen ? 'hidden' : ''}`}>
        {/* Background Effects */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5" />
        <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-bl from-white/10 to-transparent rounded-full blur-3xl" />

        <div className="relative">
          {/* Header */}
          <div className="flex justify-between items-center mb-8">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-blue-500/20 rounded-xl border border-blue-500/30 backdrop-blur-sm">
                <Camera className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Analysis</h3>
                <p className="text-blue-200 text-sm">{images.length} high-resolution images</p>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              {/* AI vs Reviewed toggle — only shown when reviewed image exists */}
              {hasReviewed && (
                <div className="flex rounded-xl overflow-hidden border border-white/20 text-xs font-medium">
                  <button
                    onClick={() => setViewMode('ai')}
                    className={`px-3 py-2 transition-colors ${viewMode === 'ai' ? 'bg-blue-600 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}
                  >
                    AI Detection
                  </button>
                  <button
                    onClick={() => setViewMode('reviewed')}
                    className={`px-3 py-2 transition-colors ${viewMode === 'reviewed' ? 'bg-green-600 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}
                  >
                    Clinician Reviewed
                  </button>
                </div>
              )}
              {/* Zoom Controls */}
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

              <button
                onClick={() => setFullscreen(true)}
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

          {/* Thumbnails */}
          <div className="mb-8">
            <div className="flex space-x-4 overflow-x-auto pb-4">
              {images.map((image, index) => (
                <button
                  key={image.imageId || index}
                  onClick={() => { setSelectedImage(index); setImageZoom(1); }}
                  className={`group flex-shrink-0 relative p-4 rounded-xl border-2 transition-all duration-300 hover:scale-105 backdrop-blur-md ${
                    selectedImage === index
                      ? 'border-blue-400 bg-gradient-to-br from-blue-500/20 to-blue-600/30 shadow-lg shadow-blue-500/25'
                      : 'border-white/20 bg-white/5 hover:border-white/40 hover:bg-white/10'
                  }`}
                >
                  <div className="w-24 h-24 bg-gradient-to-br from-white/10 to-white/5 rounded-lg flex items-center justify-center overflow-hidden border border-white/20">
                    {image.annotatedUrl || image.originalUrl || image.url ? (
                      <img
                        src={image.annotatedUrl || image.originalUrl || image.url}
                        alt={image.originalFilename || `Image ${index + 1}`}
                        className="w-full h-full object-cover rounded-lg"
                        onError={(e) => { e.target.style.display = 'none'; }}
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

                  {selectedImage === index && (
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2">
                      <div className="w-3 h-3 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 animate-pulse" />
                    </div>
                  )}
                  <div className={`absolute inset-0 rounded-xl border-2 border-blue-400/0 group-hover:border-blue-400/50 transition-all duration-300 ${selectedImage === index ? 'animate-pulse' : ''}`} />
                </button>
              ))}
            </div>
          </div>

          {/* Main Image */}
          <div className="border-2 border-white/30 rounded-2xl overflow-hidden bg-gradient-to-br from-white/5 to-white/10 backdrop-blur-md">
            <div className="relative h-[500px] overflow-hidden">
              {displayUrl ? (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-gray-900/50 to-gray-800/50">
                  <img
                    src={displayUrl}
                    alt={currentImage.originalFilename || `Image ${selectedImage + 1}`}
                    className="max-w-full max-h-full object-contain transition-transform duration-300"
                    style={{ transform: `scale(${imageZoom})` }}
                    onError={(e) => { console.error('Main image failed to load:', displayUrl); }}
                  />
                  {/* Version badge */}
                  <div className={`absolute top-4 left-4 px-2 py-1 rounded-lg text-xs font-bold border backdrop-blur-md ${
                    viewMode === 'reviewed' && hasReviewed
                      ? 'bg-green-600/80 border-green-400/50 text-white'
                      : 'bg-blue-600/80 border-blue-400/50 text-white'
                  }`}>
                    {viewMode === 'reviewed' && hasReviewed ? 'Clinician Reviewed' : 'AI Detection'}
                  </div>
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

          {/* Image Stats */}
          {currentImage && (
            <div className="mt-8 grid grid-cols-2 gap-4">
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
            </div>
          )}

          {/* Image Info */}
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
                {currentImage.annotations?.parasites?.length > 0 && (
                  <div className="flex items-center space-x-2">
                    {Object.entries(
                      currentImage.annotations.parasites.reduce((acc, p) => {
                        acc[p.type] = (acc[p.type] || 0) + 1;
                        return acc;
                      }, {})
                    ).map(([type, count]) => (
                      <span
                        key={type}
                        className="px-1.5 py-0.5 rounded text-xs font-bold text-white bg-white/20"
                      >
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

      {/* Fullscreen Mode */}
      {fullscreen && currentImage && (
        <div className="fixed inset-0 z-50 bg-black/95 backdrop-blur-sm flex items-center justify-center">
          <button
            onClick={() => setFullscreen(false)}
            className="absolute top-6 right-6 p-3 bg-white/10 hover:bg-white/20 rounded-xl text-white transition-all duration-300 hover:scale-110 backdrop-blur-md border border-white/20 shadow-lg z-10"
          >
            <X className="w-6 h-6" />
          </button>

          <div className="relative max-w-full max-h-full p-8">
            <img
              src={displayUrl}
              alt={currentImage.originalFilename || `Image ${selectedImage + 1}`}
              className="max-w-full max-h-full object-contain transition-transform duration-300"
              style={{ transform: `scale(${imageZoom})` }}
              onError={(e) => { console.error('Fullscreen image failed to load:', displayUrl); }}
            />
          </div>

          {/* Zoom Controls */}
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

// 📁 src/components/upload/ProcessingStatus.jsx - COMPLETE REPLACEMENT
import React, { useEffect, useState } from 'react';
import { Activity, AlertCircle, CheckCircle, RefreshCw, X, Zap, Brain, Eye, FileText, Cpu } from 'lucide-react';

const ProcessingStatus = ({ session, progress, error, onRetry, onCancel }) => {
  const [animatedProgress, setAnimatedProgress] = useState(0);

  // ✅ IMPROVED: Handle real backend progress data structure
  const getProgressData = () => {
    console.log('📊 ProcessingStatus received progress:', progress);
    
    if (progress) {
      // Real progress data from backend
      return {
        overall: progress.overall || progress.progress || 0,
        stage: progress.stage || 'preparing',
        currentFile: progress.currentFile || 'Processing...',
        processedFiles: progress.processedFiles || 0,
        totalFiles: progress.totalFiles || session?.files?.length || 1,
        estimatedTimeRemaining: progress.estimatedTimeRemaining || 120
      };
    }
    
    // Default/fallback data
    return {
      overall: 0,
      stage: 'preparing',
      currentFile: session?.files?.[0]?.originalName || 'Preparing...',
      processedFiles: 0,
      totalFiles: session?.files?.length || 1,
      estimatedTimeRemaining: 180
    };
  };

  const currentProgress = getProgressData();

  // Animate overall progress
  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedProgress(currentProgress.overall);
    }, 300);
    return () => clearTimeout(timer);
  }, [currentProgress.overall]);

  // ✅ SIMPLIFIED: Map backend stages to UI stages
  const getStageInfo = (backendStage) => {
    const stageMap = {
      'preparing': { ui: 'preprocessing', progress: 10 },
      'fileValidation': { ui: 'preprocessing', progress: 15 },
      'imagePreperation': { ui: 'segmentation', progress: 30 },
      'apiSubmission': { ui: 'feature_extraction', progress: 50 },
      'analysis': { ui: 'classification', progress: 80 },
      'reportGeneration': { ui: 'report_generation', progress: 95 },
      'completed': { ui: 'report_generation', progress: 100 },
      'failed': { ui: 'classification', progress: 0 }
    };

    return stageMap[backendStage] || { ui: 'preprocessing', progress: 0 };
  };

  const currentStageInfo = getStageInfo(currentProgress.stage);

  // ✅ SIMPLIFIED: Create stage progress based on current stage and overall progress
  const createStageProgress = () => {
    const stages = ['preprocessing', 'segmentation', 'feature_extraction', 'classification', 'report_generation'];
    const stageProgress = {};
    
    const currentStageIndex = stages.indexOf(currentStageInfo.ui);
    
    stages.forEach((stage, index) => {
      if (currentProgress.stage === 'completed') {
        stageProgress[stage] = 100;
      } else if (index < currentStageIndex) {
        stageProgress[stage] = 100;
      } else if (index === currentStageIndex) {
        stageProgress[stage] = Math.min(currentProgress.overall || 0, 99);
      } else {
        stageProgress[stage] = 0;
      }
    });
    
    return stageProgress;
  };

  const stageProgress = createStageProgress();

  const getStageStatus = (stageName) => {
    const progress = stageProgress[stageName] || 0;
    if (progress === 100) return 'completed';
    if (progress > 0) return 'processing';
    return 'pending';
  };

  const getStageIcon = (stage, status) => {
    const iconMap = {
      preprocessing: Cpu,
      segmentation: Eye,
      feature_extraction: Brain,
      classification: Zap,
      report_generation: FileText
    };
    
    const IconComponent = iconMap[stage] || Activity;
    
    switch (status) {
      case 'completed':
        return (
          <div className="relative">
            <div className="w-10 h-10 bg-green-500/20 border border-green-500/30 rounded-full flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div className="absolute inset-0 bg-green-400/20 rounded-full animate-ping" />
          </div>
        );
      case 'processing':
        return (
          <div className="relative">
            <div className="w-10 h-10 bg-blue-500/20 border border-blue-500/30 rounded-full flex items-center justify-center">
              <IconComponent className="w-5 h-5 text-blue-400 animate-pulse" />
            </div>
            <div className="absolute inset-0 bg-blue-400/20 rounded-full animate-pulse" />
          </div>
        );
      default:
        return (
          <div className="w-10 h-10 bg-white/10 border border-white/20 rounded-full flex items-center justify-center">
            <IconComponent className="w-5 h-5 text-white/40" />
          </div>
        );
    }
  };

  const formatTime = (seconds) => {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  const stages = [
    { key: 'preprocessing', label: 'Image Preprocessing', description: 'Enhancing image quality and removing noise' },
    { key: 'segmentation', label: 'Cell Segmentation', description: 'Identifying and isolating individual cells' },
    { key: 'feature_extraction', label: 'Feature Analysis', description: 'Extracting morphological characteristics' },
    { key: 'classification', label: 'AI Classification', description: 'Detecting malaria parasites using deep learning' },
    { key: 'report_generation', label: 'Report Generation', description: 'Compiling comprehensive analysis results' }
  ];

  // Circular progress component
  const CircularProgress = ({ percentage, size = 120, strokeWidth = 8 }) => {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const strokeDasharray = `${circumference} ${circumference}`;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;

    return (
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="transform -rotate-90" width={size} height={size}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="rgba(255, 255, 255, 0.1)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="url(#gradient)"
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={strokeDasharray}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        
        <svg className="absolute inset-0" width={0} height={0}>
          <defs>
            <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#3B82F6" />
              <stop offset="100%" stopColor="#06B6D4" />
            </linearGradient>
          </defs>
        </svg>
        
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{Math.round(percentage)}%</div>
            <div className="text-xs text-blue-200">Complete</div>
          </div>
        </div>
      </div>
    );
  };

  if (error) {
    return (
      <div className="p-8">
        <div className="max-w-md mx-auto text-center">
          <div className="relative mb-6">
            <div className="w-20 h-20 bg-red-500/20 border border-red-500/30 rounded-full flex items-center justify-center mx-auto">
              <AlertCircle className="w-10 h-10 text-red-400" />
            </div>
            <div className="absolute inset-0 bg-red-400/20 rounded-full animate-ping" />
          </div>
          
          <h3 className="text-xl font-semibold text-white mb-3">Analysis Failed</h3>
          <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4 mb-6">
            <p className="text-red-200 text-sm">{error}</p>
          </div>
          
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <button
              onClick={onRetry}
              className="flex items-center justify-center space-x-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:from-blue-600 hover:to-blue-700 transition-all transform hover:scale-105"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Retry Analysis</span>
            </button>
            <button
              onClick={onCancel}
              className="flex items-center justify-center space-x-2 bg-white/10 hover:bg-white/20 border border-white/30 text-white px-6 py-3 rounded-lg transition-all"
            >
              <X className="w-4 h-4" />
              <span>Cancel</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header Section */}
        <div className="text-center mb-8">
          <div className="relative mb-6">
            <div className="w-20 h-20 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center mx-auto border border-white/30 shadow-lg">
              <Activity className="w-10 h-10 text-white animate-pulse" />
            </div>
            <div className="absolute inset-0 bg-white/10 rounded-full animate-ping" />
          </div>
          
          <h3 className="text-2xl font-bold text-white mb-2">AI Analysis in Progress</h3>
          <p className="text-blue-200 text-lg">
            Advanced deep learning models are analyzing your blood smear images
          </p>
          
          {/* ✅ ADD: Current stage indicator */}
          <div className="mt-4 inline-flex items-center space-x-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-full px-4 py-2">
            <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
            <span className="text-sm text-blue-200 capitalize">
              {currentProgress.stage.replace(/([A-Z])/g, ' $1').toLowerCase()}
            </span>
          </div>
        </div>

        {/* Main Progress Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Circular Progress */}
          <div className="flex justify-center">
            <CircularProgress percentage={animatedProgress} />
          </div>
          
          {/* Progress Details */}
          <div className="space-y-6">
            {/* Current Status */}
            <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center">
                <div className="w-2 h-2 bg-blue-400 rounded-full mr-3 animate-pulse" />
                Current Status
              </h4>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-blue-200 text-sm">Processing File</span>
                  <span className="text-white font-medium text-sm">{currentProgress.currentFile}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-blue-200 text-sm">Files Completed</span>
                  <span className="text-white font-medium text-sm">
                    {currentProgress.processedFiles} / {currentProgress.totalFiles}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-blue-200 text-sm">Time Remaining</span>
                  <span className="text-white font-medium text-sm">
                    ~{formatTime(currentProgress.estimatedTimeRemaining)}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-blue-200 text-sm">Current Stage</span>
                  <span className="text-white font-medium text-sm capitalize">
                    {currentProgress.stage.replace(/([A-Z])/g, ' $1')}
                  </span>
                </div>
              </div>
            </div>

            {/* Performance Metrics */}
            <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6">
              <h4 className="text-lg font-semibold text-white mb-4">Analysis Metrics</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">99.7%</div>
                  <div className="text-xs text-blue-200">Accuracy</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">&lt;30s</div>
                  <div className="text-xs text-blue-200">Per Image</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ✅ IMPROVED: Processing Stages with real progress */}
        <div className="bg-white/5 backdrop-blur-md border border-white/10 rounded-xl p-6 mb-8">
          <h4 className="text-lg font-semibold text-white mb-6 text-center">Processing Pipeline</h4>
          <div className="space-y-4">
            {stages.map((stage, index) => {
              const status = getStageStatus(stage.key);
              const progress = stageProgress[stage.key] || 0;
              const isActive = currentStageInfo.ui === stage.key;
              
              return (
                <div key={stage.key} className={`relative group transition-all duration-300 ${
                  isActive ? 'scale-105' : ''
                }`}>
                  <div className="flex items-center space-x-4 p-4 rounded-lg bg-white/5 hover:bg-white/10 transition-all">
                    {/* Stage Icon */}
                    <div className="flex-shrink-0">
                      {getStageIcon(stage.key, status)}
                    </div>
                    
                    {/* Stage Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between items-center mb-2">
                        <h5 className={`font-medium transition-colors ${
                          status === 'completed' ? 'text-green-300' : 
                          status === 'processing' ? 'text-blue-300' : 
                          'text-white/60'
                        }`}>
                          {stage.label}
                        </h5>
                        <div className="flex items-center space-x-2">
                          <span className={`text-xs px-2 py-1 rounded-full ${
                            status === 'completed' ? 'bg-green-500/20 text-green-300' :
                            status === 'processing' ? 'bg-blue-500/20 text-blue-300' :
                            'bg-white/10 text-white/60'
                          }`}>
                            {Math.round(progress)}%
                          </span>
                        </div>
                      </div>
                      
                      <p className="text-blue-200 text-sm mb-3">{stage.description}</p>
                      
                      {/* Progress Bar */}
                      <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                        <div 
                          className={`h-full transition-all duration-500 ease-out ${
                            status === 'completed' ? 'bg-gradient-to-r from-green-400 to-green-500' :
                            status === 'processing' ? 'bg-gradient-to-r from-blue-400 to-blue-500' :
                            'bg-white/20'
                          }`}
                          style={{ 
                            width: `${progress}%`,
                            boxShadow: status === 'processing' ? '0 0 10px rgba(59, 130, 246, 0.5)' : 'none'
                          }}
                        />
                      </div>
                    </div>
                  </div>
                  
                  {/* Active stage glow effect */}
                  {isActive && (
                    <div className="absolute inset-0 rounded-lg border border-blue-400/30 shadow-lg shadow-blue-400/20 -z-10" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="text-center">
          <button
            onClick={onCancel}
            className="inline-flex items-center space-x-2 px-6 py-3 bg-white/10 hover:bg-white/20 border border-white/30 text-white rounded-lg transition-all hover:scale-105 backdrop-blur-md"
          >
            <X className="w-4 h-4" />
            <span>Cancel Analysis</span>
          </button>
          
          <div className="mt-4 text-center">
            <p className="text-blue-200 text-sm">
              This process typically takes 2-5 minutes depending on image complexity
            </p>
          </div>
        </div>

        {/* ✅ ADD: Debug info (remove in production) */}
        {process.env.NODE_ENV === 'development' && (
          <div className="mt-8 bg-black/20 border border-white/10 rounded-lg p-4">
            <h5 className="text-white font-medium mb-2">Debug Info</h5>
            <pre className="text-xs text-gray-300 overflow-auto">
              {JSON.stringify({
                receivedProgress: progress,
                parsedProgress: currentProgress,
                currentStageInfo,
                stageProgress
              }, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProcessingStatus;
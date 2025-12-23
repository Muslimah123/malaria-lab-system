// 📁 src/components/upload/ProcessingStatus.jsx - ADVANCED REDESIGN
import React, { useEffect, useState } from 'react';
import { 
  Activity, 
  AlertCircle, 
  CheckCircle, 
  RefreshCw, 
  X, 
  Clock, 
  Brain,
  Microscope,
  Target,
  Zap,
  Cpu,
  Memory,
  HardDrive,
  Network,
  Layers,
  Sparkles,
  TrendingUp,
  AlertTriangle,
  Info,
  FileImage,
  Database,
  Shield,
  BarChart3,
  FileText,
  Settings,
  Play,
  Pause,
  RotateCcw,
  Download,
  Eye,
  BarChart,
  PieChart,
  LineChart,
  User
} from 'lucide-react';

const ProcessingStatus = ({ 
  session, 
  progress, 
  error, 
  onRetry, 
  onCancel, 
  onComplete, 
  onManualRefresh, 
  connectivityStatus = 'connected', 
  socketService, 
  operationDuration = 0, 
  isProcessing = false 
}) => {
  const [animatedProgress, setAnimatedProgress] = useState(0);
  const [showAdvancedInfo, setShowAdvancedInfo] = useState(false);

  // ✅ ENHANCED: Handle real backend progress data structure
  const getProgressData = () => {
    if (!progress) {
      return {
        stage: 'idle',
        percentage: 0,
        message: 'Waiting to start...',
        details: {},
        overall: 0
      };
    }

    // Handle different progress formats
    if (typeof progress === 'object' && progress.stage) {
      return progress;
    }

    // Handle numeric progress (legacy)
    if (typeof progress === 'number') {
      return {
        stage: progress >= 100 ? 'completed' : 'processing',
        percentage: progress,
        message: progress >= 100 ? 'Processing complete!' : 'Processing image...',
        details: {},
        overall: progress
      };
    }

    return {
      stage: 'idle',
      percentage: 0,
      message: 'Waiting to start...',
      details: {},
      overall: 0
    };
  };

  // ✅ FIXED: Define currentProgress before using it in useEffect
  const currentProgress = getProgressData();

  // ✅ FIXED: Auto-redirect when processing is complete
  useEffect(() => {
    if (currentProgress.stage === 'completed') {
      console.log('🎉 Processing complete, redirecting to results...');
      // Auto-redirect after a short delay to show completion message
      const redirectTimer = setTimeout(() => {
        if (onComplete) {
          onComplete(); // Navigate to results
        } else if (onRetry) {
          onRetry(); // Fallback to retry
        }
      }, 3000);
      return () => clearTimeout(redirectTimer);
    }
  }, [currentProgress.stage, onComplete, onRetry]);

  // Animate progress bar
  useEffect(() => {
    if (currentProgress.stage === 'processing') {
      const timer = setInterval(() => {
        setAnimatedProgress(prev => {
          const target = currentProgress.percentage || 0;
          if (prev >= target) return target;
          return Math.min(prev + 1, target);
        });
      }, 50);
      return () => clearInterval(timer);
    } else if (currentProgress.stage === 'completed') {
      setAnimatedProgress(100);
    }
  }, [currentProgress.stage, currentProgress.percentage]);

  // Basic operation duration tracking
  const [showLongOperationWarning, setShowLongOperationWarning] = useState(false);
  
  // Update operation duration warning
  useEffect(() => {
    // Show warning after 4 minutes (approaching 5 minute timeout)
    if (operationDuration > 240000 && !showLongOperationWarning) {
      setShowLongOperationWarning(true);
    }
  }, [operationDuration, showLongOperationWarning]);
  
  // Format duration for display
  const formatDuration = (ms) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    }
    return `${seconds}s`;
  };

  // ✅ ENHANCED: Get stage-specific styling and content with advanced design
  const getStageConfig = (stage) => {
    switch (stage) {
      case 'uploading':
        return {
          icon: <Activity className="w-8 h-8 text-blue-400" />,
          color: 'blue',
          bgColor: 'bg-gradient-to-r from-blue-500/20 via-blue-600/20 to-blue-700/20',
          borderColor: 'border-blue-500/30',
          textColor: 'text-blue-300',
          accentColor: 'text-blue-400'
        };
      case 'processing':
        return {
          icon: <Brain className="w-8 h-8 text-purple-400" />,
          color: 'purple',
          bgColor: 'bg-gradient-to-r from-purple-500/20 via-purple-600/20 to-purple-700/20',
          borderColor: 'border-purple-500/30',
          textColor: 'text-purple-300',
          accentColor: 'text-purple-400'
        };
      case 'analyzing':
        return {
          icon: <Microscope className="w-8 h-8 text-indigo-400" />,
          color: 'indigo',
          bgColor: 'bg-gradient-to-r from-indigo-500/20 via-indigo-600/20 to-indigo-700/20',
          borderColor: 'border-indigo-500/30',
          textColor: 'text-indigo-300',
          accentColor: 'text-indigo-400'
        };
      case 'completed':
        return {
          icon: <CheckCircle className="w-8 h-8 text-green-400" />,
          color: 'green',
          bgColor: 'bg-gradient-to-r from-green-500/20 via-green-600/20 to-green-700/20',
          borderColor: 'border-green-500/30',
          textColor: 'text-green-300',
          accentColor: 'text-green-400'
        };
      case 'error':
        return {
          icon: <AlertCircle className="w-8 h-8 text-red-400" />,
          color: 'red',
          bgColor: 'bg-gradient-to-r from-red-500/20 via-red-600/20 to-red-700/20',
          borderColor: 'border-red-500/30',
          textColor: 'text-red-300',
          accentColor: 'text-red-400'
        };
      default:
        return {
          icon: <Activity className="w-8 h-8 text-gray-400" />,
          color: 'gray',
          bgColor: 'bg-gradient-to-r from-gray-500/20 via-gray-600/20 to-gray-700/20',
          borderColor: 'border-gray-500/30',
          textColor: 'text-gray-300',
          accentColor: 'text-gray-400'
        };
    }
  };

  const stageConfig = getStageConfig(currentProgress.stage);

  // ✅ ENHANCED: Get progress message based on stage
  const getProgressMessage = () => {
    if (error) return 'Processing failed. Please try again.';
    
    switch (currentProgress.stage) {
      case 'uploading':
        return 'Uploading images to AI analysis server...';
      case 'processing':
        return 'Running AI-powered malaria detection analysis...';
      case 'analyzing':
        return 'Analyzing results and generating comprehensive report...';
      case 'completed':
        return 'Analysis complete! Results are ready for review.';
      case 'error':
        return 'An error occurred during processing.';
      default:
        return 'Preparing to process your images...';
    }
  };

  // ✅ ENHANCED: Get detailed progress information with backend structure
  const getProgressDetails = () => {
    const details = currentProgress.details || {};
    
    if (currentProgress.stage === 'processing') {
      return [
        { 
          label: 'Model Loading', 
          status: details.modelLoaded ? 'Complete' : 'Loading...', 
          icon: details.modelLoaded ? '✓' : '⏳',
          description: 'Loading YOLO V12.pt model'
        },
        { 
          label: 'Image Preprocessing', 
          status: details.preprocessing ? 'Complete' : 'In Progress...', 
          icon: details.preprocessing ? '✓' : '⏳',
          description: 'Preparing images for AI analysis'
        },
        { 
          label: 'Parasite Detection', 
          status: details.detection ? 'Complete' : 'Running...', 
          icon: details.detection ? '✓' : '⏳',
          description: 'Detecting PF, PM, PO, PV parasites'
        },
        { 
          label: 'WBC Analysis', 
          status: details.wbcAnalysis ? 'Complete' : 'Running...', 
          icon: details.wbcAnalysis ? '✓' : '⏳',
          description: 'Counting white blood cells'
        },
        { 
          label: 'Result Generation', 
          status: details.postprocessing ? 'Complete' : 'Pending...', 
          icon: details.postprocessing ? '✓' : '⏳',
          description: 'Generating final analysis report'
        }
      ];
    }
    
    return [];
  };

  if (error) {
    // ✅ ENHANCED: Better error categorization and user guidance with advanced styling
    const getErrorDetails = (errorMessage) => {
      if (errorMessage.includes('AI analysis service is temporarily unavailable')) {
        return {
          title: 'AI Service Unavailable',
          description: 'The AI analysis service is temporarily down. This usually happens when the service crashes during processing.',
          severity: 'warning',
          suggestions: [
            'Wait a few minutes and try again',
            'The service may have completed your analysis despite the error',
            'Use "Check for Results" to see if analysis completed',
            'Contact support if the issue persists'
          ],
          isRecoverable: true,
          icon: <AlertTriangle className="w-12 h-12 text-yellow-400" />
        };
      } else if (errorMessage.includes('connection was interrupted')) {
        return {
          title: 'Connection Lost',
          description: 'The connection to the AI service was interrupted during processing.',
          severity: 'warning',
          suggestions: [
            'Try uploading the images again',
            'Check your internet connection',
            'The service may have completed your analysis',
            'Use "Check for Results" to verify completion'
          ],
          isRecoverable: true,
          icon: <Network className="w-12 h-12 text-yellow-400" />
        };
      } else if (errorMessage.includes('taking longer than expected')) {
        return {
          title: 'Processing Delayed',
          description: 'AI analysis is taking longer than expected due to high server load.',
          severity: 'info',
          suggestions: [
            'Wait a few more minutes',
            'Try again during off-peak hours',
            'The analysis may still complete successfully',
            'Use "Check for Results" to verify status'
          ],
          isRecoverable: true,
          icon: <Clock className="w-12 h-12 text-blue-400" />
        };
      } else if (errorMessage.includes('ENOTFOUND flask-api')) {
        return {
          title: 'AI Service Crashed',
          description: 'The AI analysis service crashed during processing. This is a common issue that may not affect your results.',
          severity: 'warning',
          suggestions: [
            'Use "Check for Results" to see if analysis completed',
            'The service often completes processing before crashing',
            'Wait a few minutes and try again',
            'Contact support if no results are found'
          ],
          isRecoverable: true,
          icon: <Cpu className="w-12 h-12 text-yellow-400" />
        };
      } else if (errorMessage.includes('socket hang up')) {
        return {
          title: 'Service Connection Lost',
          description: 'The AI service connection was lost during processing. This may indicate the service crashed.',
          severity: 'warning',
          suggestions: [
            'Use "Check for Results" to see if analysis completed',
            'The service may have finished before disconnecting',
            'Try uploading the images again',
            'Contact support if no results are found'
          ],
          isRecoverable: true,
          icon: <Network className="w-12 h-12 text-yellow-400" />
        };
      } else if (errorMessage.includes('No valid images found')) {
        return {
          title: 'Invalid Images',
          description: 'The uploaded files could not be processed for analysis.',
          severity: 'error',
          suggestions: [
            'Check file formats (JPG, PNG, TIFF)',
            'Ensure files are not corrupted',
            'Try uploading different images'
          ],
          isRecoverable: false,
          icon: <FileImage className="w-12 h-12 text-red-400" />
        };
      } else if (errorMessage.includes('failed validation')) {
        return {
          title: 'File Validation Failed',
          description: 'One or more uploaded files failed validation checks.',
          severity: 'error',
          suggestions: [
            'Check file sizes (max 10MB per file)',
            'Ensure files are actual images',
            'Try compressing large images'
          ],
          isRecoverable: false,
          icon: <Shield className="w-12 h-12 text-red-400" />
        };
      } else {
        return {
          title: 'Processing Failed',
          description: errorMessage || 'An unexpected error occurred during processing.',
          severity: 'error',
          suggestions: [
            'Try uploading the images again',
            'Check your internet connection',
            'Contact support for assistance'
          ],
          isRecoverable: true,
          icon: <AlertCircle className="w-12 h-12 text-red-400" />
        };
      }
    };

    const errorDetails = getErrorDetails(error);
    const isRecoverable = errorDetails.isRecoverable;

    return (
      <div className={`${errorDetails.severity === 'error' ? 'bg-gradient-to-r from-red-500/10 via-red-600/10 to-red-700/10' : errorDetails.severity === 'warning' ? 'bg-gradient-to-r from-yellow-500/10 via-yellow-600/10 to-yellow-700/10' : 'bg-gradient-to-r from-blue-500/10 via-blue-600/10 to-blue-700/10'} border ${errorDetails.severity === 'error' ? 'border-red-500/30' : errorDetails.severity === 'warning' ? 'border-yellow-500/30' : 'border-blue-500/30'} rounded-2xl p-8 text-center backdrop-blur-sm`}>
        <div className="inline-flex items-center justify-center w-20 h-20 bg-black/20 rounded-full mb-6 border border-white/10">
          {errorDetails.icon}
        </div>
        
        <h3 className={`text-2xl font-bold ${errorDetails.severity === 'error' ? 'text-red-300' : errorDetails.severity === 'warning' ? 'text-yellow-300' : 'text-blue-300'} mb-3`}>
          {errorDetails.title}
        </h3>
        
        <p className={`text-lg ${errorDetails.severity === 'error' ? 'text-red-200' : errorDetails.severity === 'warning' ? 'text-yellow-200' : 'text-blue-200'} mb-6 max-w-2xl mx-auto`}>
          {errorDetails.description}
        </p>

        {/* Suggestions */}
        {errorDetails.suggestions.length > 0 && (
          <div className="bg-black/20 rounded-xl p-6 mb-8 text-left max-w-2xl mx-auto">
            <h4 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
              <Info className="w-5 h-5 text-blue-400" />
              <span>Suggestions</span>
            </h4>
            <ul className="space-y-3">
              {errorDetails.suggestions.map((suggestion, index) => (
                <li key={index} className="flex items-start space-x-3 text-sm">
                  <span className="text-blue-400 mt-1">•</span>
                  <span className="text-gray-300">{suggestion}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex justify-center space-x-4">
          {isRecoverable && (
            <>
              <button
                onClick={onRetry}
                className={`inline-flex items-center space-x-3 px-6 py-3 bg-${errorDetails.severity === 'error' ? 'red' : errorDetails.severity === 'warning' ? 'yellow' : 'blue'}-500 hover:bg-${errorDetails.severity === 'error' ? 'red' : errorDetails.severity === 'warning' ? 'yellow' : 'blue'}-600 text-white rounded-xl transition-all duration-200 hover:scale-105 font-semibold`}
              >
                <RefreshCw className="w-5 h-5" />
                <span>Try Again</span>
              </button>
              
              {/* Check for existing results button */}
              <button
                onClick={async () => {
                  console.log('🔍 Checking for existing results...');
                  try {
                    // Call the recovery API
                    const response = await fetch(`/api/upload/${session?.sessionId}/check-results`, {
                      method: 'GET',
                      headers: {
                        'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
                        'Content-Type': 'application/json'
                      }
                    });
                    
                    const data = await response.json();
                    
                    if (data.success && data.data.recovered) {
                      console.log('✅ Results recovered successfully!');
                      // Trigger completion flow
                      if (onComplete) {
                        onComplete();
                      } else if (onRetry) {
                        onRetry();
                      }
                    } else {
                      console.log('❌ No existing results found');
                      // Show message that no results were found
                      alert('No existing results found. You may need to retry the analysis.');
                    }
                  } catch (error) {
                    console.error('Error checking for results:', error);
                    alert('Failed to check for existing results. Please try again.');
                  }
                }}
                className="inline-flex items-center space-x-3 px-6 py-3 bg-green-500 hover:bg-green-600 text-white rounded-xl transition-all duration-200 hover:scale-105 font-semibold"
              >
                <CheckCircle className="w-5 h-5" />
                <span>Check for Results</span>
              </button>
            </>
          )}
          {onCancel && (
            <button
              onClick={onCancel}
              className="inline-flex items-center space-x-3 px-6 py-3 bg-gray-600 hover:bg-gray-700 text-white rounded-xl transition-all duration-200 hover:scale-105 font-semibold"
            >
              <X className="w-5 h-5" />
              <span>Cancel</span>
            </button>
          )}
        </div>

        {/* Recovery note for recoverable errors */}
        {isRecoverable && (
          <div className="mt-8 p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl max-w-2xl mx-auto">
            <p className="text-blue-200 text-sm">
              💡 <strong>Note:</strong> This error may be temporary. The AI service might have completed your analysis despite the connection issue.
            </p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={`${stageConfig.bgColor} border ${stageConfig.borderColor} rounded-2xl p-8 backdrop-blur-sm`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center space-x-4">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-black/20 rounded-full border border-white/10">
            {stageConfig.icon}
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">AI-Powered Malaria Detection</h2>
            <p className={`text-lg ${stageConfig.textColor}`}>
              {getProgressMessage()}
            </p>
          </div>
        </div>
        
        {currentProgress.stage !== 'completed' && onCancel && (
          <button
            onClick={onCancel}
            className="p-3 text-gray-400 hover:text-white transition-all duration-200 hover:bg-black/20 rounded-xl"
            title="Cancel processing"
          >
            <X className="w-6 h-6" />
          </button>
        )}
      </div>

      {/* ✅ ENHANCED: Advanced Progress Visualization */}
      <div className="mb-8">
        {/* Main Progress Bar */}
        <div className="w-full bg-black/20 rounded-full h-4 mb-4 border border-white/10">
          <div 
            className="bg-gradient-to-r from-blue-500 via-purple-500 to-green-500 h-4 rounded-full transition-all duration-1000 ease-out shadow-lg"
            style={{ width: `${currentProgress?.overall || 0}%` }}
          />
        </div>
        
        {/* Progress Stats */}
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-300">Progress: {Math.round(currentProgress?.overall || 0)}%</span>
          <span className="text-gray-300">Stage: {currentProgress.stage}</span>
          <span className="text-gray-300">Duration: {formatDuration(operationDuration)}</span>
        </div>
      </div>
      
      {/* ✅ ENHANCED: Operation Duration and Status */}
      <div className="text-center mb-8">
        {/* Long Operation Warning */}
        {showLongOperationWarning && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 mb-4 max-w-2xl mx-auto">
            <div className="flex items-center text-yellow-300">
              <Clock className="w-5 h-5 mr-3" />
              <span className="text-sm font-medium">
                Analysis is taking longer than expected. This is normal for complex samples and may take up to 5 minutes.
              </span>
            </div>
          </div>
        )}
        
        {/* Connectivity Status */}
        {connectivityStatus === 'disconnected' && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-4 max-w-2xl mx-auto">
            <div className="flex items-center text-red-300">
              <Network className="w-5 h-5 mr-3" />
              <span className="text-sm font-medium">
                Connection lost. Using fallback status checking...
              </span>
            </div>
          </div>
        )}
      </div>

      {/* ✅ ENHANCED: Stage Details with Advanced Design */}
      {currentProgress.stage === 'processing' && (
        <div className="mb-8">
          <h4 className="text-lg font-semibold text-white mb-6 flex items-center space-x-2">
            <Layers className="w-5 h-5 text-purple-400" />
            <span>Processing Steps</span>
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getProgressDetails().map((detail, index) => (
              <div key={index} className="bg-white/5 rounded-xl p-4 border border-white/10">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-white font-medium">{detail.label}</span>
                  <div className="flex items-center space-x-2">
                    <span className={`text-xs px-2 py-1 rounded-full ${
                      detail.status.includes('Complete') 
                        ? 'bg-green-500/20 text-green-300 border border-green-500/30' 
                        : 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                    }`}>
                      {detail.status}
                    </span>
                    <span className="text-gray-500">{detail.icon}</span>
                  </div>
                </div>
                <p className="text-gray-300 text-sm">{detail.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ✅ ENHANCED: Processing Configuration Info */}
      <div className="bg-black/20 rounded-xl p-6 mb-8">
        <h4 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
          <Settings className="w-5 h-5 text-blue-400" />
          <span>Processing Configuration</span>
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white/5 rounded-lg p-4 border border-white/10">
            <div className="flex items-center space-x-2 mb-2">
              <Brain className="w-4 h-4 text-purple-400" />
              <span className="text-gray-300 text-sm font-medium">Mode</span>
            </div>
            <p className="text-white font-semibold capitalize">Advanced AI Processing</p>
          </div>
          <div className="bg-white/5 rounded-lg p-4 border border-white/10">
            <div className="flex items-center space-x-2 mb-2">
              <Target className="w-4 h-4 text-green-400" />
              <span className="text-gray-300 text-sm font-medium">Features</span>
            </div>
            <p className="text-white text-sm">
              Parasite detection, WBC counting, confidence scoring
            </p>
          </div>
          <div className="bg-white/5 rounded-lg p-4 border border-white/10">
            <div className="flex items-center space-x-2 mb-2">
              <Zap className="w-4 h-4 text-yellow-400" />
              <span className="text-gray-300 text-sm font-medium">Model</span>
            </div>
            <p className="text-white font-mono text-sm">YOLO V12.pt</p>
          </div>
        </div>
      </div>

      {/* Session Info */}
      {session && (
        <div className="bg-black/20 rounded-xl p-6 mb-8">
          <h4 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
            <Database className="w-5 h-5 text-indigo-400" />
            <span>Session Information</span>
          </h4>
          
          {/* Debug info */}
          {process.env.NODE_ENV === 'development' && (
            <div className="mb-4 p-3 bg-blue-500/20 border border-blue-500/30 rounded-lg text-xs text-blue-300">
              <p><strong>Debug:</strong> createdAt: {JSON.stringify(session.createdAt)}</p>
              <p><strong>Debug:</strong> startTime: {JSON.stringify(session.startTime)}</p>
            </div>
          )}
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Database className="w-4 h-4 text-indigo-400" />
                <span className="text-gray-300 text-sm font-medium">Session ID</span>
              </div>
              <p className="text-white font-mono text-sm">{session.sessionId}</p>
            </div>
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Clock className="w-4 h-4 text-indigo-400" />
                <span className="text-gray-300 text-sm font-medium">Started</span>
              </div>
              <p className="text-white text-sm">
                {session.startTime ? new Date(session.startTime).toLocaleTimeString() : 
                 session.createdAt ? new Date(session.createdAt).toLocaleTimeString() : 'N/A'}
              </p>
            </div>
            {session.patientInfo && (
              <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex items-center space-x-2 mb-2">
                  <User className="w-4 h-4 text-indigo-400" />
                  <span className="text-gray-300 text-sm font-medium">Patient</span>
                </div>
                <p className="text-white text-sm">{session.patientInfo.firstName} {session.patientInfo.lastName}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ✅ ENHANCED: Action Buttons with Advanced Styling */}
      <div className="flex justify-center space-x-4 mb-8">
        {currentProgress.stage === 'completed' ? (
          <button
            onClick={() => {
              console.log('🎯 Navigating to results...');
              if (onComplete) {
                onComplete(); // Use the completion handler
              } else if (onRetry) {
                onRetry(); // Fallback to retry
              } else {
                // Fallback navigation
                window.location.href = '/results';
              }
            }}
            className="inline-flex items-center space-x-3 px-8 py-4 bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white rounded-xl transition-all duration-200 hover:scale-105 font-semibold shadow-lg"
          >
            <CheckCircle className="w-5 h-5" />
            <span>View Results</span>
          </button>
        ) : currentProgress.stage === 'error' ? (
          <button
            onClick={onRetry}
            className="inline-flex items-center space-x-3 px-8 py-4 bg-gradient-to-r from-red-500 to-pink-500 hover:from-red-600 hover:to-pink-600 text-white rounded-xl transition-all duration-200 hover:scale-105 font-semibold shadow-lg"
          >
            <RefreshCw className="w-5 h-5" />
            <span>Retry Processing</span>
          </button>
        ) : (
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3 text-gray-300">
              <div className="w-4 h-4 bg-purple-400 rounded-full animate-pulse"></div>
              <span className="font-medium">Processing in progress...</span>
            </div>
            
            {/* ✅ ENHANCED: Manual refresh button for stuck processing */}
            {onManualRefresh && (
              <button
                onClick={onManualRefresh}
                className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 text-blue-300 rounded-lg transition-all duration-200 hover:scale-105 text-sm"
                title="Check for completion if processing seems stuck"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Check Status</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* ✅ ENHANCED: Additional Info with Advanced Design */}
      {currentProgress.stage === 'processing' && (
        <div className="text-center">
          <p className="text-sm text-gray-400 mb-4">
            This may take a few minutes depending on image complexity and server load.
          </p>
          
          {/* ✅ ENHANCED: Advanced debug panel */}
          <details className="text-left max-w-4xl mx-auto">
            <summary className="text-sm text-blue-400 cursor-pointer hover:text-blue-300 flex items-center justify-center space-x-2 mb-4">
              <Settings className="w-4 h-4" />
              <span>Advanced Information</span>
            </summary>
            <div className="bg-black/20 rounded-xl p-6 border border-white/10">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h5 className="text-sm font-semibold text-white mb-3">Processing Status</h5>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Stage:</span>
                      <span className="text-white">{currentProgress.stage}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Progress:</span>
                      <span className="text-white">{Math.round(animatedProgress)}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Message:</span>
                      <span className="text-white">{currentProgress.message}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Mode:</span>
                      <span className="text-white capitalize">Advanced AI Processing</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h5 className="text-sm font-semibold text-white mb-3">System Status</h5>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Connection:</span>
                      <span className={`${connectivityStatus === 'connected' ? 'text-green-400' : 'text-yellow-400'}`}>
                        {connectivityStatus === 'connected' ? 'Connected' : 'Disconnected'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Duration:</span>
                      <span className="text-white">{formatDuration(operationDuration)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Last Update:</span>
                      <span className="text-white">{new Date().toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="text-gray-400 text-xs">
                <p className="mb-2">If processing seems stuck, try the "Check Status" button above.</p>
                <p>This will manually check the backend for completion status.</p>
                {connectivityStatus === 'disconnected' && (
                  <div className="mt-3 p-3 bg-yellow-500/20 border border-yellow-500/30 rounded-lg text-yellow-300">
                    <p className="font-medium">⚠️ Connection Issue Detected</p>
                    <p>The system is using fallback status checking. This may cause delays in progress updates.</p>
                  </div>
                )}
              </div>
            </div>
          </details>
        </div>
      )}
    </div>
  );
};

export default ProcessingStatus;
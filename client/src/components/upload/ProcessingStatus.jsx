import React from 'react';
import { Activity, AlertCircle, CheckCircle, RefreshCw, X } from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';

const ProcessingStatus = ({ session, progress, error, onRetry, onCancel }) => {
  // Sample progress data if none provided
  const sampleProgress = {
    overall: 65,
    stage: 'analyzing',
    currentFile: 'blood_smear_001.jpg',
    processedFiles: 3,
    totalFiles: 5,
    stageProgress: {
      preprocessing: 100,
      segmentation: 100,
      feature_extraction: 80,
      classification: 45,
      report_generation: 0
    },
    estimatedTimeRemaining: 120 // seconds
  };

  const currentProgress = progress || sampleProgress;

  const getStageStatus = (stageName) => {
    const stageProgress = currentProgress.stageProgress?.[stageName] || 0;
    if (stageProgress === 100) return 'completed';
    if (stageProgress > 0) return 'processing';
    return 'pending';
  };

  const getStageIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'processing':
        return <LoadingSpinner size="sm" />;
      default:
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300" />;
    }
  };

  const formatTime = (seconds) => {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  const stages = [
    { key: 'preprocessing', label: 'Image Preprocessing', description: 'Enhancing image quality' },
    { key: 'segmentation', label: 'Cell Segmentation', description: 'Identifying cell boundaries' },
    { key: 'feature_extraction', label: 'Feature Extraction', description: 'Analyzing cell characteristics' },
    { key: 'classification', label: 'AI Classification', description: 'Detecting malaria parasites' },
    { key: 'report_generation', label: 'Report Generation', description: 'Generating final report' }
  ];

  return (
    <div className="p-8">
      {error ? (
        // Error State
        <div className="text-center">
          <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertCircle className="w-8 h-8 text-red-600" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">Processing Failed</h3>
          <p className="text-red-600 mb-6">{error}</p>
          <div className="space-x-4">
            <button
              onClick={onRetry}
              className="btn btn-primary"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Retry Processing
            </button>
            <button
              onClick={onCancel}
              className="btn btn-outline"
            >
              <X className="w-4 h-4 mr-2" />
              Cancel
            </button>
          </div>
        </div>
      ) : (
        // Processing State
        <div>
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Activity className="w-8 h-8 text-blue-600 animate-pulse" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">Processing Blood Samples</h3>
            <p className="text-gray-600">
              Our AI is analyzing your blood smear images for malaria detection
            </p>
          </div>

          {/* Overall Progress */}
          <div className="mb-8">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-medium text-gray-700">Overall Progress</span>
              <span className="text-sm text-gray-500">{currentProgress.overall}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div 
                className="bg-blue-600 h-3 rounded-full transition-all duration-300"
                style={{ width: `${currentProgress.overall}%` }}
              />
            </div>
          </div>

          {/* Current Processing Info */}
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-sm text-gray-500">Current File</p>
                <p className="font-medium text-gray-900">{currentProgress.currentFile}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Files Processed</p>
                <p className="font-medium text-gray-900">
                  {currentProgress.processedFiles} / {currentProgress.totalFiles}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Time Remaining</p>
                <p className="font-medium text-gray-900">
                  ~{formatTime(currentProgress.estimatedTimeRemaining)}
                </p>
              </div>
            </div>
          </div>

          {/* Processing Stages */}
          <div className="space-y-4 mb-8">
            <h4 className="text-md font-medium text-gray-900">Processing Stages</h4>
            {stages.map((stage, index) => {
              const status = getStageStatus(stage.key);
              const stageProgress = currentProgress.stageProgress?.[stage.key] || 0;
              
              return (
                <div key={stage.key} className="flex items-center space-x-4">
                  <div className="flex-shrink-0">
                    {getStageIcon(status)}
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between items-center mb-1">
                      <span className={`text-sm font-medium ${
                        status === 'completed' ? 'text-green-700' : 
                        status === 'processing' ? 'text-blue-700' : 
                        'text-gray-500'
                      }`}>
                        {stage.label}
                      </span>
                      <span className="text-xs text-gray-500">{stageProgress}%</span>
                    </div>
                    <p className="text-xs text-gray-500 mb-2">{stage.description}</p>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-300 ${
                          status === 'completed' ? 'bg-green-500' : 
                          status === 'processing' ? 'bg-blue-500' : 
                          'bg-gray-300'
                        }`}
                        style={{ width: `${stageProgress}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Cancel Button */}
          <div className="text-center">
            <button
              onClick={onCancel}
              className="btn btn-outline"
            >
              <X className="w-4 h-4 mr-2" />
              Cancel Processing
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProcessingStatus;
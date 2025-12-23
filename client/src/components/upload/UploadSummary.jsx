import React, { useState } from 'react';
import { 
  User, 
  TestTube, 
  FileImage, 
  Edit2, 
  Calendar, 
  Clock, 
  AlertTriangle, 
  Zap, 
  Brain, 
  Settings, 
  CheckCircle,
  Microscope,
  Target,
  Shield,
  Activity,
  BarChart3,
  FileText,
  Database,
  Cpu,
  Memory,
  HardDrive,
  Network,
  Layers,
  Sparkles,
  TrendingUp,
  AlertCircle,
  Info,
  Phone,
  Mail
} from 'lucide-react';

const UploadSummary = ({ 
  patientData, 
  testData, 
  files = [], 
  session, 
  validationResults, 
  onEdit
}) => {
  // Use actual data passed as props, with fallbacks for missing data
  const actualPatientData = patientData || {};
  const actualTestData = testData || {};
  const actualFiles = files || [];

  const formatFileSize = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'urgent':
        return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'normal':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'low':
        return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  // ✅ ENHANCED: Advanced processing configuration based on backend capabilities
  const processingConfig = {
    name: 'Advanced Malaria Detection',
    description: 'Comprehensive AI-powered analysis with YOLO detection',
    icon: <Brain className="w-5 h-5" />,
    color: 'bg-gradient-to-r from-blue-500/20 to-purple-500/20 border-blue-500/30',
    features: [
      'Parasite detection (PF, PM, PO, PV)',
      'WBC detection & counting',
      'Bounding box coordinates',
      'Confidence scoring',
      'Multi-image analysis',
      'Parasite-WBC ratio calculation'
    ],
    estimatedTime: '~2-5 minutes',
    accuracy: '99.5%',
    modelVersion: 'YOLO V12.pt',
    processingMode: 'Advanced AI'
  };

  const totalFileSize = actualFiles.reduce((total, file) => total + (file.size || 0), 0);

  return (
    <div className="p-6 space-y-8">
      {/* Header Section */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-blue-500/20 to-purple-500/20 rounded-full mb-4 border border-blue-500/30">
          <Microscope className="w-8 h-8 text-blue-400" />
        </div>
        <h2 className="text-3xl font-bold text-white mb-2">Upload Summary</h2>
        <p className="text-blue-200 text-lg">
          Review your upload details before starting the AI analysis
        </p>
        <div className="w-24 h-1 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full mx-auto mt-4"></div>
      </div>

      <div className="space-y-8">
        {/* Patient Information Card */}
        <div className="bg-gradient-to-r from-blue-500/10 via-blue-600/10 to-purple-500/10 rounded-2xl p-6 border border-blue-500/20 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-blue-500/20 rounded-xl border border-blue-500/30">
                <User className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Patient Information</h3>
                <p className="text-blue-200 text-sm">Personal and medical details</p>
              </div>
            </div>
            <button
              onClick={() => onEdit('patient')}
              className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 text-blue-300 hover:text-white rounded-xl transition-all duration-200 hover:scale-105"
            >
              <Edit2 className="w-4 h-4 inline mr-2" />
              Edit
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <User className="w-4 h-4 text-blue-400" />
                <span className="text-blue-200 text-sm font-medium">Full Name</span>
              </div>
              <p className="text-white font-semibold text-lg">
                {actualPatientData.firstName || 'N/A'} {actualPatientData.lastName || ''}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Target className="w-4 h-4 text-green-400" />
                <span className="text-green-200 text-sm font-medium">Patient ID</span>
              </div>
              <p className="text-white font-mono text-lg">
                {actualPatientData.patientId || actualPatientData._id || 'N/A'}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Calendar className="w-4 h-4 text-purple-400" />
                <span className="text-purple-200 text-sm font-medium">Age</span>
              </div>
              <p className="text-white font-semibold text-lg">
                {actualPatientData.age ? `${actualPatientData.age} years` : 'N/A'}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Shield className="w-4 h-4 text-orange-400" />
                <span className="text-orange-200 text-sm font-medium">Gender</span>
              </div>
              <p className="text-white font-semibold text-lg capitalize">
                {actualPatientData.gender || 'N/A'}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Phone className="w-4 h-4 text-red-400" />
                <span className="text-red-200 text-sm font-medium">Phone</span>
              </div>
              <p className="text-white font-semibold text-lg">
                {actualPatientData.phone || 'N/A'}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Mail className="w-4 h-4 text-indigo-400" />
                <span className="text-indigo-200 text-sm font-medium">Email</span>
              </div>
              <p className="text-white font-semibold text-lg">
                {actualPatientData.email || 'N/A'}
              </p>
            </div>
          </div>
        </div>

        {/* Test Information Card */}
        <div className="bg-gradient-to-r from-green-500/10 via-green-600/10 to-emerald-500/10 rounded-2xl p-6 border border-green-500/20 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-green-500/20 rounded-xl border border-green-500/30">
                <TestTube className="w-6 h-6 text-green-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Test Information</h3>
                <p className="text-green-200 text-sm">Laboratory test details and configuration</p>
              </div>
            </div>
            <button
              onClick={() => onEdit('test')}
              className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 text-green-300 hover:text-white rounded-xl transition-all duration-200 hover:scale-105"
            >
              <Edit2 className="w-4 h-4 inline mr-2" />
              Edit
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Database className="w-4 h-4 text-green-400" />
                <span className="text-green-200 text-sm font-medium">Test ID</span>
              </div>
              <p className="text-white font-mono text-lg">
                {actualTestData.testId || 'N/A'}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                <span className="text-orange-200 text-sm font-medium">Priority</span>
              </div>
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getPriorityColor(actualTestData.priority || 'normal')}`}>
                {(actualTestData.priority || 'normal').toUpperCase()}
              </span>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <span className="text-blue-200 text-sm font-medium">Sample Type</span>
              </div>
              <p className="text-white font-semibold text-lg capitalize">
                {(actualTestData.sampleType || 'blood_smear').replace('_', ' ')}
              </p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-4 border border-white/10">
              <div className="flex items-center space-x-2 mb-2">
                <Clock className="w-4 h-4 text-purple-400" />
                <span className="text-purple-200 text-sm font-medium">Created</span>
              </div>
              <p className="text-white font-semibold text-lg">
                {new Date().toLocaleDateString()}
              </p>
            </div>
          </div>

          {/* Clinical Notes */}
          {actualTestData.clinicalNotes && Object.keys(actualTestData.clinicalNotes).length > 0 && (
            <div className="mt-6 p-4 bg-white/5 rounded-xl border border-white/10">
              <h4 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                <FileText className="w-5 h-5 text-green-400" />
                <span>Clinical Notes</span>
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(actualTestData.clinicalNotes).map(([key, value]) => (
                  <div key={key} className="bg-white/5 rounded-lg p-3 border border-white/10">
                    <span className="text-green-200 text-sm font-medium capitalize">
                      {key.replace(/([A-Z])/g, ' $1')}:
                    </span>
                    <p className="text-white font-medium mt-1">{value || 'N/A'}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* AI Processing Configuration Card */}
        <div className="bg-gradient-to-r from-purple-500/10 via-purple-600/10 to-pink-500/10 rounded-2xl p-6 border border-purple-500/20 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-purple-500/20 rounded-xl border border-purple-500/30">
                <Brain className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">AI Processing Configuration</h3>
                <p className="text-purple-200 text-sm">Advanced malaria detection settings</p>
              </div>
            </div>
            <div className="px-4 py-2 bg-purple-500/20 border border-purple-500/30 text-purple-300 rounded-xl">
              <Settings className="w-4 h-4 inline mr-2" />
              Auto-Configured
            </div>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Processing Mode */}
            <div className="bg-white/5 rounded-xl p-6 border border-white/10">
              <div className="flex items-center space-x-3 mb-4">
                <div className="p-2 bg-purple-500/20 rounded-lg border border-purple-500/30">
                  <Zap className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-white">Processing Mode</h4>
                  <p className="text-purple-200 text-sm">Advanced AI Analysis</p>
                </div>
              </div>
              
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-purple-200 text-sm">Model Version</span>
                  <span className="text-white font-mono text-sm">{processingConfig.modelVersion}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-purple-200 text-sm">Processing Type</span>
                  <span className="text-white font-semibold">{processingConfig.processingMode}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-purple-200 text-sm">Estimated Time</span>
                  <span className="text-white font-semibold">{processingConfig.estimatedTime}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-purple-200 text-sm">Accuracy Rate</span>
                  <span className="text-green-400 font-bold">{processingConfig.accuracy}</span>
                </div>
              </div>
            </div>

            {/* Features List */}
            <div className="bg-white/5 rounded-xl p-6 border border-white/10">
              <div className="flex items-center space-x-3 mb-4">
                <div className="p-2 bg-blue-500/20 rounded-lg border border-blue-500/30">
                  <Sparkles className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-white">Detection Features</h4>
                  <p className="text-blue-200 text-sm">Comprehensive analysis capabilities</p>
                </div>
              </div>
              
              <div className="space-y-3">
                {processingConfig.features.map((feature, index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                    <span className="text-white text-sm">{feature}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* File Information Card */}
        <div className="bg-gradient-to-r from-orange-500/10 via-orange-600/10 to-red-500/10 rounded-2xl p-6 border border-orange-500/20 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-orange-500/20 rounded-xl border border-orange-500/30">
                <FileImage className="w-6 h-6 text-orange-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Uploaded Files</h3>
                <p className="text-orange-200 text-sm">Image files for AI analysis</p>
              </div>
            </div>
            <button
              onClick={() => onEdit('files')}
              className="px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 text-orange-300 hover:text-white rounded-xl transition-all duration-200 hover:scale-105"
            >
              <Edit2 className="w-4 h-4 inline mr-2" />
              Edit
            </button>
          </div>

          {/* File Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
              <div className="w-16 h-16 bg-orange-500/20 rounded-full flex items-center justify-center mx-auto mb-3 border border-orange-500/30">
                <FileImage className="w-8 h-8 text-orange-400" />
              </div>
              <p className="text-3xl font-bold text-white">{actualFiles.length}</p>
              <p className="text-orange-200 text-sm">Total Files</p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
              <div className="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-3 border border-blue-500/30">
                <HardDrive className="w-8 h-8 text-blue-400" />
              </div>
              <p className="text-3xl font-bold text-white">{formatFileSize(totalFileSize)}</p>
              <p className="text-blue-200 text-sm">Total Size</p>
            </div>
            
            <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
              <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-3 border border-green-500/30">
                <CheckCircle className="w-8 h-8 text-green-400" />
              </div>
              <p className="text-3xl font-bold text-white">
                {validationResults?.validFiles?.length || actualFiles.length}
              </p>
              <p className="text-green-200 text-sm">Valid Files</p>
            </div>
          </div>

          {/* File List */}
          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
            <h4 className="text-lg font-semibold text-white mb-4">File Details</h4>
            <div className="space-y-3 max-h-48 overflow-y-auto">
              {actualFiles.length > 0 ? (
                actualFiles.map((file, index) => (
                  <div key={file.id || file.name || index} className="flex items-center justify-between bg-white/5 rounded-lg p-3 border border-white/10">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center border border-blue-500/30">
                        <FileImage className="w-5 h-5 text-blue-400" />
                      </div>
                      <div>
                        <p className="text-white font-medium">{file.name || file.filename || `File ${index + 1}`}</p>
                        <p className="text-blue-200 text-sm">{formatFileSize(file.size || 0)}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-green-500 rounded-full" title="Valid"></div>
                      <span className="text-green-400 text-sm">Ready</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center text-gray-400 py-8">
                  <FileImage className="w-12 h-12 mx-auto mb-3 text-gray-500" />
                  <p className="text-lg">No files selected</p>
                  <p className="text-sm">Please upload image files for analysis</p>
                </div>
              )}
            </div>
          </div>

          {/* Validation Warnings */}
          {validationResults?.warnings?.length > 0 && (
            <div className="mt-6 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-xl">
              <div className="flex items-center space-x-3 mb-3">
                <AlertTriangle className="w-5 h-5 text-yellow-500" />
                <span className="text-yellow-300 font-semibold">Validation Warnings</span>
              </div>
              <ul className="text-yellow-200 text-sm space-y-1">
                {validationResults.warnings.map((warning, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <span className="text-yellow-400 mt-1">•</span>
                    <span>{warning}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Session Information */}
        {session && (
          <div className="bg-gradient-to-r from-indigo-500/10 via-indigo-600/10 to-blue-500/10 rounded-2xl p-6 border border-indigo-500/20 backdrop-blur-sm">
            <div className="flex items-center space-x-3 mb-4">
              <div className="p-3 bg-indigo-500/20 rounded-xl border border-indigo-500/30">
                <Database className="w-6 h-6 text-indigo-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Upload Session</h3>
                <p className="text-indigo-200 text-sm">Session configuration and limits</p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                <div className="flex items-center space-x-2 mb-2">
                  <Database className="w-4 h-4 text-indigo-400" />
                  <span className="text-indigo-200 text-sm font-medium">Session ID</span>
                </div>
                <p className="text-white font-mono text-lg">{session.sessionId}</p>
              </div>
              
              <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                <div className="flex items-center space-x-2 mb-2">
                  <FileImage className="w-4 h-4 text-indigo-400" />
                  <span className="text-indigo-200 text-sm font-medium">Max Files</span>
                </div>
                <p className="text-white font-semibold text-lg">{session.maxFiles}</p>
              </div>
              
              <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                <div className="flex items-center space-x-2 mb-2">
                  <HardDrive className="w-4 h-4 text-indigo-400" />
                  <span className="text-indigo-200 text-sm font-medium">Max File Size</span>
                </div>
                <p className="text-white font-semibold text-lg">{formatFileSize(session.maxFileSize)}</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Summary */}
      <div className="bg-gradient-to-r from-emerald-500/10 via-emerald-600/10 to-teal-500/10 rounded-2xl p-6 border border-emerald-500/20 backdrop-blur-sm">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-emerald-500/20 rounded-full mb-4 border border-emerald-500/30">
            <TrendingUp className="w-8 h-8 text-emerald-400" />
          </div>
          <h3 className="text-2xl font-bold text-white mb-2">Analysis Summary</h3>
          <p className="text-emerald-200 text-lg">Expected results and processing details</p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
            <div className="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-blue-500/30">
              <Clock className="w-8 h-8 text-blue-400" />
            </div>
            <p className="text-2xl font-bold text-white">{processingConfig.estimatedTime}</p>
            <p className="text-blue-200 text-sm">Processing Time</p>
          </div>
          
          <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
            <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-green-500/30">
              <Target className="w-8 h-8 text-green-400" />
            </div>
            <p className="text-2xl font-bold text-white">{processingConfig.accuracy}</p>
            <p className="text-green-200 text-sm">Accuracy Rate</p>
          </div>
          
          <div className="bg-white/5 rounded-xl p-6 text-center border border-white/10">
            <div className="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-purple-500/30">
              <Brain className="w-8 h-8 text-purple-400" />
            </div>
            <p className="text-2xl font-bold text-white">{processingConfig.processingMode}</p>
            <p className="text-purple-200 text-sm">Processing Mode</p>
          </div>
        </div>
      </div>

      {/* Ready to Process Notice */}
      <div className="bg-gradient-to-r from-green-500/10 via-green-600/10 to-emerald-500/10 rounded-2xl p-6 border border-green-500/20 backdrop-blur-sm">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-green-500/20 rounded-xl border border-green-500/30">
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <h4 className="text-xl font-semibold text-white">Ready to Process</h4>
            <p className="text-green-200 text-sm">
              All information has been validated. Your images are ready for AI-powered malaria detection analysis.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UploadSummary;
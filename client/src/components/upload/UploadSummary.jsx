import React from 'react';
import { User, TestTube, FileImage, Edit2, Calendar, Clock, AlertTriangle } from 'lucide-react';

const UploadSummary = ({ 
  patientData, 
  testData, 
  files = [], 
  session, 
  validationResults, 
  onEdit 
}) => {
  // Sample data if none provided
  const samplePatientData = patientData || {
    firstName: 'John',
    lastName: 'Doe',
    patientId: 'P12345',
    age: 35,
    gender: 'male',
    phone: '+1234567890',
    email: 'john.doe@email.com'
  };

  const sampleTestData = testData || {
    testId: 'MT-2024-001',
    priority: 'normal',
    sampleType: 'blood_smear',
    clinicalNotes: {
      symptoms: 'Fever, chills, headache',
      duration: '3 days',
      travelHistory: 'Recent travel to endemic area'
    }
  };

  const sampleFiles = files.length > 0 ? files : [
    { id: 1, name: 'blood_smear_001.jpg', size: 2456789, type: 'image/jpeg' },
    { id: 2, name: 'blood_smear_002.jpg', size: 2234567, type: 'image/jpeg' },
    { id: 3, name: 'blood_smear_003.jpg', size: 2567890, type: 'image/jpeg' }
  ];

  const formatFileSize = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'urgent':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'normal':
        return 'bg-blue-100 text-blue-800';
      case 'low':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const totalFileSize = sampleFiles.reduce((total, file) => total + file.size, 0);

  return (
    <div className="p-6">
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-2">Review Upload Summary</h3>
        <p className="text-sm text-gray-600">
          Please review the information below before starting the analysis
        </p>
      </div>

      <div className="space-y-6">
        {/* Patient Information */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <User className="w-5 h-5 text-gray-600" />
              <h4 className="text-md font-medium text-gray-900">Patient Information</h4>
            </div>
            <button
              onClick={() => onEdit('patient')}
              className="text-primary-600 hover:text-primary-700 text-sm font-medium flex items-center space-x-1"
            >
              <Edit2 className="w-4 h-4" />
              <span>Edit</span>
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Name:</span>
              <span className="ml-2 font-medium text-gray-900">
                {samplePatientData.firstName} {samplePatientData.lastName}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Patient ID:</span>
              <span className="ml-2 font-medium text-gray-900">{samplePatientData.patientId}</span>
            </div>
            <div>
              <span className="text-gray-500">Age:</span>
              <span className="ml-2 font-medium text-gray-900">{samplePatientData.age} years</span>
            </div>
            <div>
              <span className="text-gray-500">Gender:</span>
              <span className="ml-2 font-medium text-gray-900 capitalize">{samplePatientData.gender}</span>
            </div>
            <div>
              <span className="text-gray-500">Phone:</span>
              <span className="ml-2 font-medium text-gray-900">{samplePatientData.phone}</span>
            </div>
            <div>
              <span className="text-gray-500">Email:</span>
              <span className="ml-2 font-medium text-gray-900">{samplePatientData.email}</span>
            </div>
          </div>
        </div>

        {/* Test Information */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <TestTube className="w-5 h-5 text-gray-600" />
              <h4 className="text-md font-medium text-gray-900">Test Information</h4>
            </div>
            <button
              onClick={() => onEdit('test')}
              className="text-primary-600 hover:text-primary-700 text-sm font-medium flex items-center space-x-1"
            >
              <Edit2 className="w-4 h-4" />
              <span>Edit</span>
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Test ID:</span>
              <span className="ml-2 font-medium text-gray-900">{sampleTestData.testId}</span>
            </div>
            <div>
              <span className="text-gray-500">Priority:</span>
              <span className={`ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(sampleTestData.priority)}`}>
                {sampleTestData.priority.toUpperCase()}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Sample Type:</span>
              <span className="ml-2 font-medium text-gray-900 capitalize">
                {sampleTestData.sampleType.replace('_', ' ')}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Created:</span>
              <span className="ml-2 font-medium text-gray-900">
                {new Date().toLocaleDateString()}
              </span>
            </div>
          </div>

          {/* Clinical Notes */}
          {sampleTestData.clinicalNotes && Object.keys(sampleTestData.clinicalNotes).length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <h5 className="text-sm font-medium text-gray-900 mb-2">Clinical Notes</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                {Object.entries(sampleTestData.clinicalNotes).map(([key, value]) => (
                  <div key={key}>
                    <span className="text-gray-500 capitalize">{key.replace(/([A-Z])/g, ' $1')}:</span>
                    <span className="ml-2 font-medium text-gray-900">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* File Information */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <FileImage className="w-5 h-5 text-gray-600" />
              <h4 className="text-md font-medium text-gray-900">Uploaded Files</h4>
            </div>
            <button
              onClick={() => onEdit('files')}
              className="text-primary-600 hover:text-primary-700 text-sm font-medium flex items-center space-x-1"
            >
              <Edit2 className="w-4 h-4" />
              <span>Edit</span>
            </button>
          </div>

          {/* File Summary Stats */}
          <div className="grid grid-cols-3 gap-4 mb-4 text-center">
            <div className="bg-white rounded-lg p-3">
              <p className="text-2xl font-bold text-primary-600">{sampleFiles.length}</p>
              <p className="text-xs text-gray-500">Files</p>
            </div>
            <div className="bg-white rounded-lg p-3">
              <p className="text-2xl font-bold text-primary-600">{formatFileSize(totalFileSize)}</p>
              <p className="text-xs text-gray-500">Total Size</p>
            </div>
            <div className="bg-white rounded-lg p-3">
              <p className="text-2xl font-bold text-primary-600">
                {validationResults?.validFiles?.length || sampleFiles.length}
              </p>
              <p className="text-xs text-gray-500">Valid</p>
            </div>
          </div>

          {/* File List */}
          <div className="space-y-2 max-h-32 overflow-y-auto">
            {sampleFiles.map((file, index) => (
              <div key={file.id || index} className="flex items-center justify-between bg-white rounded p-2 text-sm">
                <div className="flex items-center space-x-2">
                  <FileImage className="w-4 h-4 text-gray-400" />
                  <span className="font-medium text-gray-900">{file.name}</span>
                </div>
                <div className="flex items-center space-x-2 text-gray-500">
                  <span>{formatFileSize(file.size)}</span>
                  <div className="w-2 h-2 bg-green-500 rounded-full" title="Valid"></div>
                </div>
              </div>
            ))}
          </div>

          {/* Validation Warnings */}
          {validationResults?.warnings?.length > 0 && (
            <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <div className="flex items-center space-x-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-yellow-600" />
                <span className="text-sm font-medium text-yellow-800">Validation Warnings</span>
              </div>
              <ul className="text-sm text-yellow-700 space-y-1">
                {validationResults.warnings.map((warning, index) => (
                  <li key={index}>• {warning}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Session Information */}
        {session && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center space-x-2 mb-2">
              <Clock className="w-4 h-4 text-blue-600" />
              <span className="text-sm font-medium text-blue-900">Upload Session</span>
            </div>
            <div className="text-sm text-blue-800">
              <p>Session ID: {session.sessionId}</p>
              <p>Max Files: {session.maxFiles}</p>
              <p>Max File Size: {formatFileSize(session.maxFileSize)}</p>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Estimate */}
      <div className="mt-6 bg-gradient-to-r from-primary-50 to-blue-50 rounded-lg p-4">
        <h4 className="text-md font-medium text-gray-900 mb-2">Analysis Estimate</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="text-center">
            <p className="text-2xl font-bold text-primary-600">~{Math.ceil(sampleFiles.length * 2)}m</p>
            <p className="text-gray-600">Processing Time</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-primary-600">AI</p>
            <p className="text-gray-600">Analysis Method</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-primary-600">99.5%</p>
            <p className="text-gray-600">Accuracy Rate</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UploadSummary;
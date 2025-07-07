import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  ArrowLeft, 
  ArrowRight, 
  Check, 
  AlertCircle, 
  Upload, 
  FileImage,
  User,
  TestTube,
  Activity,
  X,
  RefreshCw
} from 'lucide-react';

import {
  createUploadSession,
  uploadFiles,
  processFiles,
  validateFiles,
  selectCurrentSession,
  selectUploadProgress,
  selectIsUploading,
  selectIsProcessing,
  selectUploadError,
  clearCurrentSession,
  setCurrentSession
} from '../store/slices/uploadsSlice';

import { showSuccessToast, showErrorToast, showWarningToast } from '../store/slices/notificationsSlice';
import { selectUser, selectHasPermission } from '../store/slices/authSlice';

import PatientForm from '../components/upload/PatientForm';
import ImageUpload from '../components/upload/ImageUpload';
import DragDropZone from '../components/upload/DragDropZone';
import ImagePreview from '../components/upload/ImagePreview';
import ProcessingStatus from '../components/upload/ProcessingStatus';
import UploadSummary from '../components/upload/UploadSummary';

import LoadingSpinner, { OverlayLoader } from '../components/common/LoadingSpinner';
import socketService from '../services/socketService';
import apiService from '../services/api';

import { ROUTES, UPLOAD_CONFIG, PERMISSIONS } from '../utils/constants';

const UPLOAD_STEPS = {
  PATIENT_INFO: 'patient',
  FILE_UPLOAD: 'upload',
  REVIEW: 'review',
  PROCESSING: 'processing',
  COMPLETE: 'complete'
};

const SampleUpload = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  
  const user = useSelector(selectUser);
  const canUpload = useSelector(selectHasPermission(PERMISSIONS.CAN_UPLOAD_SAMPLES));
  const currentSession = useSelector(selectCurrentSession);
  const uploadProgress = useSelector(selectUploadProgress);
  const isUploading = useSelector(selectIsUploading);
  const isProcessing = useSelector(selectIsProcessing);
  const uploadError = useSelector(selectUploadError);

  // Component state
  const [currentStep, setCurrentStep] = useState(UPLOAD_STEPS.PATIENT_INFO);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [patientData, setPatientData] = useState(null);
  const [testData, setTestData] = useState({
    priority: 'normal',
    sampleType: 'blood_smear',
    clinicalNotes: {}
  });
  const [validationResults, setValidationResults] = useState(null);
  const [uploadConfig, setUploadConfig] = useState(UPLOAD_CONFIG);
  const [errors, setErrors] = useState({});
  const [dragActive, setDragActive] = useState(false);

  // Refs
  const fileInputRef = useRef(null);
  const abortControllerRef = useRef(null);

  // Check permissions
  useEffect(() => {
    if (!canUpload) {
      dispatch(showErrorToast('You do not have permission to upload samples'));
      navigate(ROUTES.DASHBOARD);
    }
  }, [canUpload, dispatch, navigate]);

  // Handle URL parameters for pre-filled data
  useEffect(() => {
    const patientId = searchParams.get('patientId');
    const testId = searchParams.get('testId');
    
    if (patientId) {
      fetchPatientData(patientId);
    }
    
    if (testId) {
      fetchTestData(testId);
    }
  }, [searchParams]);

  // Socket listeners for real-time updates
  useEffect(() => {
    if (currentSession?.sessionId) {
      socketService.subscribeToUploadSession(currentSession.sessionId);
      
      return () => {
        socketService.unsubscribeFromUploadSession(currentSession.sessionId);
      };
    }
  }, [currentSession?.sessionId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      
      // Clean up session if not completed
      if (currentSession && currentStep !== UPLOAD_STEPS.COMPLETE) {
        dispatch(clearCurrentSession());
      }
    };
  }, []);

  const fetchPatientData = async (patientId) => {
    try {
      const response = await apiService.patients.getById(patientId);
      setPatientData(response.data.data.patient);
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
    } catch (error) {
      dispatch(showErrorToast('Failed to load patient data'));
    }
  };

  const fetchTestData = async (testId) => {
    try {
      const response = await apiService.tests.getById(testId);
      const test = response.data.data.test;
      
      setTestData({
        testId: test.testId,
        priority: test.priority,
        sampleType: test.sampleType,
        clinicalNotes: test.clinicalNotes
      });
      
      setPatientData(test.patient);
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
    } catch (error) {
      dispatch(showErrorToast('Failed to load test data'));
    }
  };

  const handlePatientSubmit = async (data) => {
    try {
      setErrors({});
      
      let patient = data;
      
      // Create patient if new
      if (!data._id) {
        const response = await apiService.patients.create(data);
        patient = response.data.data.patient;
        dispatch(showSuccessToast('Patient created successfully'));
      }
      
      // Create test
      const testResponse = await apiService.tests.create({
        patientId: patient.patientId,
        priority: testData.priority,
        sampleType: testData.sampleType,
        clinicalNotes: testData.clinicalNotes
      });
      
      const test = testResponse.data.data.test;
      setTestData(prev => ({ ...prev, testId: test.testId }));
      setPatientData(patient);
      
      // Create upload session
      const sessionResponse = await dispatch(createUploadSession({
        testId: test.testId,
        maxFiles: uploadConfig.MAX_FILES,
        maxFileSize: uploadConfig.MAX_FILE_SIZE
      })).unwrap();
      
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
      dispatch(showSuccessToast('Ready to upload samples'));
      
    } catch (error) {
      setErrors({ submit: apiService.handleApiError(error) });
      dispatch(showErrorToast('Failed to create test'));
    }
  };

  const handleFileSelection = useCallback(async (files) => {
    try {
      // Validate files first
      const fileArray = Array.from(files);
      
      // Client-side validation
      const validFiles = [];
      const invalidFiles = [];
      
      for (const file of fileArray) {
        const validation = validateFile(file);
        if (validation.isValid) {
          validFiles.push({
            file,
            id: Date.now() + Math.random(),
            name: file.name,
            size: file.size,
            type: file.type,
            preview: URL.createObjectURL(file),
            status: 'pending'
          });
        } else {
          invalidFiles.push({
            file,
            name: file.name,
            errors: validation.errors
          });
        }
      }
      
      if (invalidFiles.length > 0) {
        const errorMsg = `${invalidFiles.length} file(s) were invalid. Check file types and sizes.`;
        dispatch(showWarningToast(errorMsg));
      }
      
      if (validFiles.length === 0) {
        dispatch(showErrorToast('No valid files selected'));
        return;
      }
      
      // Server-side validation
      const formData = new FormData();
      validFiles.forEach(({ file }) => formData.append('files', file));
      
      const validationResponse = await dispatch(validateFiles(validFiles.map(f => f.file))).unwrap();
      
      setValidationResults(validationResponse);
      setSelectedFiles(validFiles);
      
      if (validationResponse.validFiles.length > 0) {
        dispatch(showSuccessToast(`${validationResponse.validFiles.length} files ready for upload`));
      }
      
    } catch (error) {
      dispatch(showErrorToast('File validation failed'));
    }
  }, [dispatch]);

  const validateFile = (file) => {
    const errors = [];
    
    // Check file type
    if (!uploadConfig.ALLOWED_TYPES.includes(file.type)) {
      errors.push('Invalid file type. Please upload JPEG, PNG, or TIFF images.');
    }
    
    // Check file size
    if (file.size > uploadConfig.MAX_FILE_SIZE) {
      errors.push(`File size exceeds ${(uploadConfig.MAX_FILE_SIZE / (1024 * 1024)).toFixed(1)}MB limit.`);
    }
    
    // Check if file is actually an image
    if (!file.type.startsWith('image/')) {
      errors.push('File must be an image.');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  };

  const handleUpload = async () => {
    try {
      if (!currentSession || selectedFiles.length === 0) return;
      
      setErrors({});
      
      // Create abort controller for cancellation
      abortControllerRef.current = new AbortController();
      
      const validFiles = selectedFiles.filter(f => f.status !== 'error');
      const files = validFiles.map(f => f.file);
      
      // Upload files with progress tracking
      await dispatch(uploadFiles({
        sessionId: currentSession.sessionId,
        files,
        onProgress: (progress) => {
          // Progress is handled by Redux middleware
        }
      })).unwrap();
      
      setCurrentStep(UPLOAD_STEPS.REVIEW);
      dispatch(showSuccessToast('Files uploaded successfully'));
      
    } catch (error) {
      if (error.name === 'AbortError') {
        dispatch(showWarningToast('Upload cancelled'));
      } else {
        setErrors({ upload: apiService.handleApiError(error) });
        dispatch(showErrorToast('Upload failed'));
      }
    }
  };

  const handleProcessing = async () => {
    try {
      if (!currentSession) return;
      
      setCurrentStep(UPLOAD_STEPS.PROCESSING);
      
      await dispatch(processFiles(currentSession.sessionId)).unwrap();
      
      dispatch(showSuccessToast('Processing started successfully'));
      
    } catch (error) {
      setErrors({ processing: apiService.handleApiError(error) });
      dispatch(showErrorToast('Failed to start processing'));
      setCurrentStep(UPLOAD_STEPS.REVIEW);
    }
  };

  const handleCancel = async () => {
    try {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      
      if (currentSession) {
        await apiService.uploads.cancelSession(currentSession.sessionId, 'User cancelled');
        dispatch(clearCurrentSession());
      }
      
      navigate(ROUTES.DASHBOARD);
      
    } catch (error) {
      console.error('Failed to cancel upload:', error);
      navigate(ROUTES.DASHBOARD);
    }
  };

  const handleRetry = () => {
    setErrors({});
    if (currentStep === UPLOAD_STEPS.PROCESSING) {
      handleProcessing();
    } else {
      handleUpload();
    }
  };

  const removeFile = (fileId) => {
    setSelectedFiles(prev => prev.filter(f => f.id !== fileId));
  };

  const replaceFile = (fileId, newFile) => {
    const validation = validateFile(newFile);
    if (!validation.isValid) {
      dispatch(showErrorToast(validation.errors[0]));
      return;
    }
    
    setSelectedFiles(prev => prev.map(f => 
      f.id === fileId ? {
        ...f,
        file: newFile,
        name: newFile.name,
        size: newFile.size,
        preview: URL.createObjectURL(newFile),
        status: 'pending'
      } : f
    ));
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelection(e.dataTransfer.files);
      e.dataTransfer.clearData();
    }
  }, [handleFileSelection]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  }, []);

  // Navigation helpers
  const canGoNext = () => {
    switch (currentStep) {
      case UPLOAD_STEPS.PATIENT_INFO:
        return patientData !== null;
      case UPLOAD_STEPS.FILE_UPLOAD:
        return selectedFiles.length > 0 && validationResults?.validFiles.length > 0;
      case UPLOAD_STEPS.REVIEW:
        return true;
      default:
        return false;
    }
  };

  const canGoBack = () => {
    return currentStep !== UPLOAD_STEPS.PATIENT_INFO && currentStep !== UPLOAD_STEPS.PROCESSING;
  };

  const getStepIndex = (step) => {
    const steps = Object.values(UPLOAD_STEPS);
    return steps.indexOf(step);
  };

  // Step navigation
  const goToStep = (step) => {
    if (step === UPLOAD_STEPS.PROCESSING) return; // Can't manually go to processing
    setCurrentStep(step);
  };

  const goNext = () => {
    const steps = Object.values(UPLOAD_STEPS);
    const currentIndex = getStepIndex(currentStep);
    if (currentIndex < steps.length - 1) {
      const nextStep = steps[currentIndex + 1];
      if (nextStep === UPLOAD_STEPS.PROCESSING) {
        handleProcessing();
      } else {
        setCurrentStep(nextStep);
      }
    }
  };

  const goBack = () => {
    const steps = Object.values(UPLOAD_STEPS);
    const currentIndex = getStepIndex(currentStep);
    if (currentIndex > 0) {
      setCurrentStep(steps[currentIndex - 1]);
    }
  };

  // Real-time progress from socket
  const currentProgress = uploadProgress[currentSession?.sessionId];

  // Processing completion handler
  useEffect(() => {
    if (currentProgress?.stage === 'completed' && currentStep === UPLOAD_STEPS.PROCESSING) {
      setCurrentStep(UPLOAD_STEPS.COMPLETE);
      dispatch(showSuccessToast('Analysis completed successfully!'));
    } else if (currentProgress?.stage === 'failed' && currentStep === UPLOAD_STEPS.PROCESSING) {
      setErrors({ processing: 'Analysis failed. Please try again.' });
    }
  }, [currentProgress, currentStep, dispatch]);

  if (!canUpload) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Access Denied</h2>
          <p className="text-gray-600">You don't have permission to upload samples.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Processing Overlay */}
      <OverlayLoader 
        show={isProcessing && currentStep === UPLOAD_STEPS.PROCESSING}
        text={`Processing samples... ${currentProgress?.overall || 0}% complete`}
      />

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Upload Blood Samples</h1>
            <p className="mt-1 text-sm text-gray-600">
              Upload and analyze blood smear images for malaria detection
            </p>
          </div>
          <button
            onClick={handleCancel}
            className="btn btn-outline"
            disabled={isUploading || isProcessing}
          >
            <X className="w-4 h-4 mr-2" />
            Cancel
          </button>
        </div>

        {/* Progress Steps */}
        <div className="mt-8">
          <nav aria-label="Progress">
            <ol className="flex items-center">
              {Object.entries(UPLOAD_STEPS).map(([key, step], index) => {
                const isActive = currentStep === step;
                const isCompleted = getStepIndex(currentStep) > index;
                const isAccessible = getStepIndex(currentStep) >= index;
                
                const stepNames = {
                  [UPLOAD_STEPS.PATIENT_INFO]: 'Patient Info',
                  [UPLOAD_STEPS.FILE_UPLOAD]: 'Upload Files',
                  [UPLOAD_STEPS.REVIEW]: 'Review',
                  [UPLOAD_STEPS.PROCESSING]: 'Processing',
                  [UPLOAD_STEPS.COMPLETE]: 'Complete'
                };

                return (
                  <li key={step} className={`relative ${index !== Object.keys(UPLOAD_STEPS).length - 1 ? 'pr-8 sm:pr-20' : ''}`}>
                    {index !== Object.keys(UPLOAD_STEPS).length - 1 && (
                      <div className="absolute inset-0 flex items-center" aria-hidden="true">
                        <div className={`h-0.5 w-full ${isCompleted ? 'bg-primary-600' : 'bg-gray-200'}`} />
                      </div>
                    )}
                    <button
                      className={`relative flex h-8 w-8 items-center justify-center rounded-full ${
                        isCompleted 
                          ? 'bg-primary-600 hover:bg-primary-700' 
                          : isActive 
                            ? 'border-2 border-primary-600 bg-white' 
                            : 'border-2 border-gray-300 bg-white hover:border-gray-400'
                      } ${isAccessible ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}`}
                      onClick={() => isAccessible && goToStep(step)}
                      disabled={!isAccessible}
                    >
                      {isCompleted ? (
                        <Check className="h-5 w-5 text-white" />
                      ) : (
                        <span className={`text-sm font-medium ${
                          isActive ? 'text-primary-600' : 'text-gray-500'
                        }`}>
                          {index + 1}
                        </span>
                      )}
                    </button>
                    <div className="mt-2">
                      <span className={`text-xs font-medium ${
                        isActive ? 'text-primary-600' : 'text-gray-500'
                      }`}>
                        {stepNames[step]}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ol>
          </nav>
        </div>
      </div>

      {/* Step Content */}
      <div className="bg-white rounded-lg shadow-medical border border-gray-200">
        {currentStep === UPLOAD_STEPS.PATIENT_INFO && (
          <PatientForm
            initialData={patientData}
            testData={testData}
            onSubmit={handlePatientSubmit}
            onTestDataChange={setTestData}
            loading={false}
            error={errors.submit}
          />
        )}

        {currentStep === UPLOAD_STEPS.FILE_UPLOAD && (
          <div className="p-6">
            <div className="mb-6">
              <h3 className="text-lg font-medium text-gray-900 mb-2">Upload Blood Smear Images</h3>
              <p className="text-sm text-gray-600">
                Upload high-quality blood smear images for analysis. Supported formats: JPEG, PNG, TIFF
              </p>
            </div>

            {selectedFiles.length === 0 ? (
              <DragDropZone
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                dragActive={dragActive}
                onFileSelect={handleFileSelection}
                fileInputRef={fileInputRef}
                maxFiles={uploadConfig.MAX_FILES}
                maxFileSize={uploadConfig.MAX_FILE_SIZE}
                acceptedTypes={uploadConfig.ALLOWED_TYPES}
              />
            ) : (
              <div>
                <ImagePreview
                  files={selectedFiles}
                  onRemove={removeFile}
                  onReplace={replaceFile}
                  validationResults={validationResults}
                />
                
                <div className="mt-4 flex justify-center">
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="btn btn-outline"
                    disabled={selectedFiles.length >= uploadConfig.MAX_FILES}
                  >
                    <FileImage className="w-4 h-4 mr-2" />
                    Add More Images
                  </button>
                </div>
              </div>
            )}

            {errors.upload && (
              <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
                <div className="flex items-center">
                  <AlertCircle className="w-5 h-5 text-red-400 mr-2" />
                  <span className="text-red-800 text-sm">{errors.upload}</span>
                </div>
              </div>
            )}

            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept={uploadConfig.ALLOWED_TYPES.join(',')}
              onChange={(e) => handleFileSelection(e.target.files)}
              className="hidden"
            />
          </div>
        )}

        {currentStep === UPLOAD_STEPS.REVIEW && (
          <UploadSummary
            patientData={patientData}
            testData={testData}
            files={selectedFiles}
            session={currentSession}
            validationResults={validationResults}
            onEdit={(section) => {
              if (section === 'patient') goToStep(UPLOAD_STEPS.PATIENT_INFO);
              if (section === 'files') goToStep(UPLOAD_STEPS.FILE_UPLOAD);
            }}
          />
        )}

        {currentStep === UPLOAD_STEPS.PROCESSING && (
          <ProcessingStatus
            session={currentSession}
            progress={currentProgress}
            error={errors.processing}
            onRetry={handleRetry}
            onCancel={handleCancel}
          />
        )}

        {currentStep === UPLOAD_STEPS.COMPLETE && (
          <div className="p-8 text-center">
            <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Check className="w-8 h-8 text-success-600" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">Analysis Complete!</h3>
            <p className="text-gray-600 mb-6">
              Your blood samples have been successfully analyzed. The results are now available.
            </p>
            <div className="space-x-4">
              <button
                onClick={() => navigate(`/results/${testData.testId}`)}
                className="btn btn-primary"
              >
                View Results
              </button>
              <button
                onClick={() => {
                  dispatch(clearCurrentSession());
                  navigate(ROUTES.UPLOAD);
                }}
                className="btn btn-outline"
              >
                Upload More Samples
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Navigation */}
      {currentStep !== UPLOAD_STEPS.COMPLETE && currentStep !== UPLOAD_STEPS.PROCESSING && (
        <div className="mt-8 flex justify-between">
          <button
            onClick={goBack}
            disabled={!canGoBack() || isUploading}
            className="btn btn-outline"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </button>

          <div className="space-x-4">
            {currentStep === UPLOAD_STEPS.FILE_UPLOAD && selectedFiles.length > 0 && (
              <button
                onClick={handleUpload}
                disabled={!canGoNext() || isUploading}
                className="btn btn-primary"
              >
                {isUploading ? (
                  <>
                    <LoadingSpinner size="sm" color="white" />
                    <span className="ml-2">Uploading...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4 mr-2" />
                    Upload Files
                  </>
                )}
              </button>
            )}

            {currentStep === UPLOAD_STEPS.REVIEW && (
              <button
                onClick={handleProcessing}
                disabled={!canGoNext() || isProcessing}
                className="btn btn-primary"
              >
                <Activity className="w-4 h-4 mr-2" />
                Start Analysis
              </button>
            )}

            {currentStep !== UPLOAD_STEPS.FILE_UPLOAD && currentStep !== UPLOAD_STEPS.REVIEW && (
              <button
                onClick={goNext}
                disabled={!canGoNext()}
                className="btn btn-primary"
              >
                Next
                <ArrowRight className="w-4 h-4 ml-2" />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SampleUpload;
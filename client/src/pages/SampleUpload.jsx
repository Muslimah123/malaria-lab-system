//src/components/SampleUpload.jsx 
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  ArrowLeft, 
  ArrowRight, 
  Check, 
  AlertCircle, 
  Upload, 
  TestTube,
  Activity,
  X,
  Save
} from 'lucide-react';

// Redux Slices
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
  updateFileStatus,
  handleSocketUpdate
} from '../store/slices/uploadsSlice';

import {
  createPatient,
  updatePatient,
  fetchPatientById,
  clearSearchResults,
  selectCurrentPatient,
  selectPatientsLoading,
  selectPatientsError,
  selectIsCreatingPatient,
  selectIsUpdatingPatient
} from '../store/slices/patientsSlice';

import {
  createTest,
  fetchTestById,
  selectCurrentTest,
  selectTestsLoading,
  selectTestsError,
  selectIsCreatingTest
} from '../store/slices/testsSlice';

import { showSuccessToast, showErrorToast, showWarningToast, showInfoToast } from '../store/slices/notificationsSlice';
import { selectUser, selectHasPermission } from '../store/slices/authSlice';

// Components
import PatientForm from '../components/upload/PatientForm';
import DragDropZone from '../components/upload/DragDropZone';
import ImagePreview from '../components/upload/ImagePreview';
import ProcessingStatus from '../components/upload/ProcessingStatus';

import LoadingSpinner, { OverlayLoader } from '../components/common/LoadingSpinner';
import socketService from '../services/socketService';
import apiService from '../services/api';

import { ROUTES, UPLOAD_CONFIG, PERMISSIONS } from '../utils/constants';

// Debug component import (temporary)
import SocketDebugger from '../components/debug/SocketDebugger';

// Upload steps
const UPLOAD_STEPS = {
  PATIENT_INFO: 'patient',
  FILE_UPLOAD: 'upload', 
  PROCESSING: 'processing',
  COMPLETE: 'complete'
};

const SESSION_RECOVERY_KEY = 'malaria-lab-upload-session';

const SampleUpload = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  
  // Auth selectors
  const user = useSelector(selectUser);
  const canUpload = useSelector(selectHasPermission(PERMISSIONS.CAN_UPLOAD_SAMPLES));
  
  // Upload selectors
  const currentSession = useSelector(selectCurrentSession);
  const uploadProgress = useSelector(selectUploadProgress);
  const isUploading = useSelector(selectIsUploading);
  const isProcessing = useSelector(selectIsProcessing);
  const uploadError = useSelector(selectUploadError);
  
  // Patient selectors
  const currentPatient = useSelector(selectCurrentPatient);
  const patientsLoading = useSelector(selectPatientsLoading);
  const patientsError = useSelector(selectPatientsError);
  const isCreatingPatient = useSelector(selectIsCreatingPatient);
  const isUpdatingPatient = useSelector(selectIsUpdatingPatient);
  
  // Test selectors
  const currentTest = useSelector(selectCurrentTest);
  const testsLoading = useSelector(selectTestsLoading);
  const testsError = useSelector(selectTestsError);
  const isCreatingTest = useSelector(selectIsCreatingTest);

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
  const [uploadConfig] = useState(UPLOAD_CONFIG);
  const [errors, setErrors] = useState({});
  const [dragActive, setDragActive] = useState(false);
  const [sessionRecovered, setSessionRecovered] = useState(false);

  // Local session management
  const [localSession, setLocalSession] = useState(() => {
    const saved = sessionStorage.getItem('currentUploadSession');
    if (saved) {
      const session = JSON.parse(saved);
      return session;
    }
    return null;
  });
  const latestSessionRef = useRef(null);

  // Update ref when localSession changes
  useEffect(() => {
    latestSessionRef.current = localSession;
  }, [localSession]);

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

  // Session recovery on mount
  useEffect(() => {
    if (localSession && localSession.sessionId) {
      setSessionRecovered(true);
      dispatch(showInfoToast('Upload session recovered'));
    }
  }, [dispatch, localSession]);

  // Socket connection with authentication
  useEffect(() => {
    const connectSocket = async () => {
      try {
        const token = localStorage.getItem('authToken');
        if (!token) {
          return;
        }

        await socketService.connectWithRetry(token, 3);
        dispatch(showInfoToast('Real-time updates connected'));

      } catch (error) {
        // Socket failure is not critical for basic functionality
      }
    };

    connectSocket();

    // Cleanup on unmount
    return () => {
      socketService.disconnect();
    };
  }, [dispatch]);

  // Socket event listeners
  useEffect(() => {
    if (!socketService.isConnected()) {
      return;
    }

    // Set up listeners for upload events that dispatch Redux actions
    const handleProcessingProgress = (data) => {
      dispatch(handleSocketUpdate({
        type: 'upload:processingProgress',
        data
      }));
    };

    const handleProcessingCompleted = (data) => {
      dispatch(handleSocketUpdate({
        type: 'upload:processingCompleted',
        data
      }));
    };

    const handleProcessingFailed = (data) => {
      dispatch(handleSocketUpdate({
        type: 'upload:processingFailed',
        data
      }));
      dispatch(showErrorToast(data.error || 'Processing failed'));
    };

    const handleFileUploaded = (data) => {
      dispatch(handleSocketUpdate({
        type: 'upload:fileUploaded',
        data
      }));
    };

    const handleSessionUpdated = (data) => {
      dispatch(handleSocketUpdate({
        type: 'upload:sessionUpdated',
        data
      }));
    };

    // Register event listeners
    socketService.on('upload:processingProgress', handleProcessingProgress);
    socketService.on('upload:processingCompleted', handleProcessingCompleted);
    socketService.on('upload:processingFailed', handleProcessingFailed);
    socketService.on('upload:fileUploaded', handleFileUploaded);
    socketService.on('upload:sessionUpdated', handleSessionUpdated);

    // Cleanup function
    return () => {
      socketService.off('upload:processingProgress', handleProcessingProgress);
      socketService.off('upload:processingCompleted', handleProcessingCompleted);
      socketService.off('upload:processingFailed', handleProcessingFailed);
      socketService.off('upload:fileUploaded', handleFileUploaded);
      socketService.off('upload:sessionUpdated', handleSessionUpdated);
    };
  }, [dispatch]);

  // ✅ FIXED: Upload session subscription with proper callback handling
  useEffect(() => {
    const sessionId = localSession?.sessionId || currentSession?.sessionId;
    
    if (sessionId && socketService.isConnected()) {
      // ✅ ADD: Callback handler for socket events
      const handleSocketEvent = ({ type, data }) => {
        
        switch (type) {
          case 'upload:processingProgress':
            dispatch(handleSocketUpdate({
              type: 'upload:processingProgress',
              data
            }));
            break;
            
          case 'upload:processingCompleted':
            // ✅ CRITICAL: Update Redux state first
            dispatch(handleSocketUpdate({
              type: 'upload:processingCompleted',
              data: {
                ...data,
                stage: 'completed', // Ensure stage is set to completed
                overall: 100
              }
            }));
            
            // ✅ CRITICAL: Immediately transition to complete step
            setCurrentStep(UPLOAD_STEPS.COMPLETE);
            dispatch(showSuccessToast('Analysis completed successfully!'));
            
            // Cleanup local session
            setLocalSession(null);
            sessionStorage.removeItem('currentUploadSession');
            break;
            
          case 'upload:processingFailed':
            dispatch(handleSocketUpdate({
              type: 'upload:processingFailed',
              data
            }));
            dispatch(showErrorToast(data.error || 'Processing failed'));
            setErrors({ processing: data.error || 'Analysis failed. Please try again.' });
            break;
            
          case 'upload:fileUploaded':
            dispatch(handleSocketUpdate({
              type: 'upload:fileUploaded',
              data
            }));
            break;
            
          case 'upload:sessionUpdated':
            dispatch(handleSocketUpdate({
              type: 'upload:sessionUpdated',
              data
            }));
            break;
            
          case 'upload-session-joined':
            break;
            
          case 'upload-session-left':
            break;
            
          default:
            break;
        }
      };
      
      // ✅ PASS CALLBACK: Subscribe with callback handler
      socketService.subscribeToUploadSession(sessionId, handleSocketEvent);
      
      return () => {
        socketService.unsubscribeFromUploadSession(sessionId, handleSocketEvent);
      };
    } else if (sessionId && !socketService.isConnected()) {
      // Try to reconnect and then subscribe
      const reconnectAndSubscribe = async () => {
        try {
          const token = localStorage.getItem('authToken');
          if (token) {
            await socketService.connectWithRetry(token, 2);
            if (socketService.isConnected()) {
              // Re-run the subscription logic after reconnection
              // This will trigger this useEffect again
            }
          }
        } catch (error) {
          // Reconnection failed - not critical
        }
      };
      
      reconnectAndSubscribe();
    }
  }, [localSession?.sessionId, currentSession?.sessionId, dispatch]);

  // Save session state periodically
  useEffect(() => {
    if (patientData || selectedFiles.length > 0) {
      const sessionData = {
        patientData,
        testData,
        selectedFiles: selectedFiles.map(f => ({
          id: f.id,
          name: f.name,
          size: f.size,
          type: f.type,
          status: f.status
        })),
        currentStep,
        timestamp: Date.now()
      };
      
      localStorage.setItem(SESSION_RECOVERY_KEY, JSON.stringify(sessionData));
    }
  }, [patientData, testData, selectedFiles, currentStep]);

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

  // Persist session
  useEffect(() => {
    if (localSession) {
      sessionStorage.setItem('currentUploadSession', JSON.stringify(localSession));
    } else {
      sessionStorage.removeItem('currentUploadSession');
    }
  }, [localSession]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      
      if (currentStep === UPLOAD_STEPS.COMPLETE) {
        setLocalSession(null);
        sessionStorage.removeItem('currentUploadSession');
      }
    };
  }, [currentStep]);

  const fetchPatientData = async (patientId) => {
    try {
      const patient = await dispatch(fetchPatientById(patientId)).unwrap();
      setPatientData(patient);
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
    } catch (error) {
      dispatch(showErrorToast('Failed to load patient data'));
    }
  };

  const fetchTestData = async (testId) => {
    try {
      const test = await dispatch(fetchTestById(testId)).unwrap();
      
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
      
      // Check multiple possible ID fields
      const hasExistingId = data._id || data.patientId || data.id;
      
      // Create patient if new
      if (!hasExistingId) {
        patient = await dispatch(createPatient(data)).unwrap();
        dispatch(showSuccessToast('Patient created successfully'));
      } else {
        // If patientData is null, don't treat it as a change
        const shouldUpdate = patientData !== null && JSON.stringify(data) !== JSON.stringify(patientData);
        
        if (shouldUpdate) {
          const patientIdToUpdate = data.patientId || data._id || data.id;
          
          patient = await dispatch(updatePatient({ 
            patientId: patientIdToUpdate, 
            patientData: data 
          })).unwrap();
          
          dispatch(clearSearchResults());
          dispatch(showSuccessToast('Patient updated successfully'));
        } else {
          // If patientData is null, we still need the patient object
          if (patientData === null) {
            try {
              const patientIdToFetch = data.patientId || data._id || data.id;
              patient = await dispatch(fetchPatientById(patientIdToFetch)).unwrap();
              setPatientData(patient);
            } catch (fetchError) {
              // Fallback: use the form data
              patient = data;
            }
          }
        }
      }
      
      const patientIdToUse = patient.patientId || patient._id || patient.id;
      
      if (!patientIdToUse) {
        throw new Error('Patient ID is required but missing from Redux state. Please try again.');
      }
      
      // Transform clinical notes
      const transformedClinicalNotes = {
        symptoms: Array.isArray(testData.clinicalNotes?.symptoms) 
          ? testData.clinicalNotes.symptoms 
          : [],
        duration: testData.clinicalNotes?.duration || '',
        travelHistory: testData.clinicalNotes?.travelHistory || '',
        medications: testData.clinicalNotes?.medications || '',
        additionalNotes: testData.clinicalNotes?.additionalNotes || ''
      };
      
      // Create test via Redux thunk
      const testPayload = {
        patientId: patientIdToUse,
        priority: testData.priority || 'normal',
        sampleType: testData.sampleType || 'blood_smear',
        clinicalNotes: transformedClinicalNotes
      };
      
      const test = await dispatch(createTest(testPayload)).unwrap();
      
      if (!test || !test.testId) {
        throw new Error('Test creation failed - missing testId');
      }
      
      setTestData(prev => ({ ...prev, testId: test.testId }));
      setPatientData(patient);
      
      // Create session - Direct API call
      try {
        // Call API directly to get proper response structure
        const sessionResponse = await apiService.upload.createSession({
          testId: test.testId,
          maxFiles: uploadConfig.MAX_FILES,
          maxFileSize: uploadConfig.MAX_FILE_SIZE
        });
        
        // Extract session from response - handle different possible structures
        const session = sessionResponse?.data?.session || 
                       sessionResponse?.session || 
                       sessionResponse;
        
        if (!session || !session.sessionId) {
          throw new Error('Failed to create upload session - invalid response');
        }
        
        // Store session locally with the sessionId
        const sessionToStore = {
          ...session,
          testId: test.testId
        };
        
        setLocalSession(sessionToStore);
        latestSessionRef.current = sessionToStore;
        
        // Also dispatch to Redux for compatibility (non-critical)
        dispatch(createUploadSession({
          testId: test.testId,
          maxFiles: uploadConfig.MAX_FILES,
          maxFileSize: uploadConfig.MAX_FILE_SIZE
        })).catch(err => {
          // Redux dispatch error is non-critical
        });
        
      } catch (sessionError) {
        throw new Error('Failed to create upload session');
      }
      
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
      dispatch(showSuccessToast('Ready to upload samples'));
      
    } catch (error) {
      setErrors({ submit: error.message || 'An unexpected error occurred' });
      dispatch(showErrorToast(error.message || 'Failed to process patient data'));
    }
  };

  // File validation
  const validateFile = (file) => {
    const errors = [];
    
    if (!uploadConfig.ALLOWED_TYPES.includes(file.type)) {
      errors.push('Invalid file type. Please upload JPEG, PNG, or TIFF images.');
    }
    
    if (file.size > uploadConfig.MAX_FILE_SIZE) {
      errors.push(`File size exceeds ${(uploadConfig.MAX_FILE_SIZE / (1024 * 1024)).toFixed(1)}MB limit.`);
    }
    
    if (!file.type.startsWith('image/')) {
      errors.push('File must be an image.');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  };

  // File selection handler
  const handleFileSelection = useCallback(async (files) => {
    try {
      const fileArray = Array.from(files);
      
      // Check if adding these files would exceed the limit
      if (selectedFiles.length + fileArray.length > uploadConfig.MAX_FILES) {
        dispatch(showErrorToast(`Cannot exceed ${uploadConfig.MAX_FILES} files limit`));
        return;
      }
      
      // Client-side validation
      const validFiles = [];
      const invalidFiles = [];
      
      for (const file of fileArray) {
        // Check if file already exists
        const existingFile = selectedFiles.find(f => f.name === file.name && f.size === file.size);
        if (existingFile) {
          dispatch(showWarningToast(`File "${file.name}" already exists`));
          continue;
        }
        
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
      const validationResponse = await dispatch(validateFiles(validFiles.map(f => f.file))).unwrap();
      
      // Append new files instead of replacing
      setSelectedFiles(prev => [...prev, ...validFiles]);
      
      // Handle different possible validation response structures
      let processedValidationResponse;
      
      if (validationResponse.validFiles || validationResponse.invalidFiles) {
        processedValidationResponse = validationResponse;
      } else if (validationResponse.data) {
        processedValidationResponse = validationResponse.data;
      } else if (Array.isArray(validationResponse)) {
        processedValidationResponse = {
          validFiles: validationResponse,
          invalidFiles: []
        };
      } else {
        processedValidationResponse = {
          validFiles: validFiles.map(f => ({ name: f.name, size: f.size })),
          invalidFiles: []
        };
      }
      
      // Merge validation results instead of replacing
      setValidationResults(prevResults => {
        const newResults = {
          validFiles: [
            ...(prevResults?.validFiles || []), 
            ...(processedValidationResponse.validFiles || [])
          ],
          invalidFiles: [
            ...(prevResults?.invalidFiles || []), 
            ...(processedValidationResponse.invalidFiles || [])
          ]
        };
        
        return newResults;
      });
      
      const validCount = processedValidationResponse.validFiles?.length || 0;
      if (validCount > 0) {
        dispatch(showSuccessToast(`${validCount} files ready for upload`));
      }
      
    } catch (error) {
      dispatch(showErrorToast('File validation failed'));
    }
  }, [dispatch, uploadConfig, selectedFiles]);

  // Individual file retry
  const handleRetryFileUpload = async (file) => {
    try {
      if (!currentSession) {
        dispatch(showErrorToast('No active upload session'));
        return;
      }

      setSelectedFiles(prev => prev.map(f => 
        f.id === file.id ? { ...f, status: 'uploading', errorMessage: null } : f
      ));

      const formData = new FormData();
      formData.append('files', file.file);

      const response = await apiService.upload.uploadFiles(
        currentSession.sessionId,
        [file.file],
        (progress) => {
          setSelectedFiles(prev => prev.map(f => 
            f.id === file.id ? { ...f, progress } : f
          ));
        }
      );

      setSelectedFiles(prev => prev.map(f => 
        f.id === file.id ? { ...f, status: 'completed', progress: 100 } : f
      ));

      dispatch(showSuccessToast(`${file.name} uploaded successfully`));

    } catch (error) {
      setSelectedFiles(prev => prev.map(f => 
        f.id === file.id ? { 
          ...f, 
          status: 'failed', 
          errorMessage: apiService.formatError(error) 
        } : f
      ));

      dispatch(showErrorToast(`Failed to upload ${file.name}`));
    }
  };

  const handleUpload = async () => {
    // Use local session
    const sessionToUse = latestSessionRef.current || localSession || currentSession;
    
    try {
      if (!sessionToUse || !sessionToUse.sessionId) {
        dispatch(showErrorToast('No active upload session. Please start over.'));
        setCurrentStep(UPLOAD_STEPS.PATIENT_INFO);
        setLocalSession(null);
        sessionStorage.removeItem('currentUploadSession');
        return;
      }
      
      if (selectedFiles.length === 0) {
        dispatch(showErrorToast('Please select files to upload'));
        return;
      }
      
      setErrors({});
      abortControllerRef.current = new AbortController();
      
      const validFiles = selectedFiles.filter(f => f.status !== 'error' && f.status !== 'failed');
      const files = validFiles.map(f => f.file);
      
      await dispatch(uploadFiles({
        sessionId: sessionToUse.sessionId,
        files,
        onProgress: (progress) => {
          // Progress handled by Redux
        }
      })).unwrap();
      
      // Go directly to processing - no review step
      setCurrentStep(UPLOAD_STEPS.PROCESSING);
      handleProcessing(); // Start processing immediately
      
    } catch (error) {
      if (error.name === 'AbortError') {
        dispatch(showWarningToast('Upload cancelled'));
      } else {
        setErrors({ upload: apiService.formatError(error) });
        dispatch(showErrorToast('Upload failed'));
      }
    }
  };

  const handleProcessing = async () => {
    try {
      // Use local session
      const sessionToUse = latestSessionRef.current || localSession || currentSession;
      
      if (!sessionToUse || !sessionToUse.sessionId) {
        dispatch(showErrorToast('No active session for processing'));
        return;
      }
      
      setCurrentStep(UPLOAD_STEPS.PROCESSING);
      
      await dispatch(processFiles(sessionToUse.sessionId)).unwrap();
      
      dispatch(showSuccessToast('Processing started successfully'));
      
    } catch (error) {
      setErrors({ processing: apiService.formatError(error) });
      dispatch(showErrorToast('Failed to start processing'));
      setCurrentStep(UPLOAD_STEPS.FILE_UPLOAD);
    }
  };

  const handleCancel = async () => {
    try {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      
      // Use local session
      const sessionToUse = latestSessionRef.current || localSession || currentSession;
      
      if (sessionToUse?.sessionId) {
        await apiService.upload.cancelSession(sessionToUse.sessionId, 'User cancelled');
        dispatch(clearCurrentSession());
      }
      
      // Cleanup local session
      setLocalSession(null);
      sessionStorage.removeItem('currentUploadSession');
      
      navigate(ROUTES.DASHBOARD);
      
    } catch (error) {
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

  // File management
  const removeFile = (fileId) => {
    const fileToRemove = selectedFiles.find(f => f.id === fileId);
    
    // Remove from selectedFiles
    setSelectedFiles(prev => prev.filter(f => f.id !== fileId));
    
    // Update validation results
    if (fileToRemove && validationResults) {
      setValidationResults(prev => {
        if (!prev) return null;
        
        return {
          validFiles: prev.validFiles?.filter(vf => vf.name !== fileToRemove.name) || [],
          invalidFiles: prev.invalidFiles?.filter(ivf => ivf.name !== fileToRemove.name) || []
        };
      });
    }
    
    // Clean up preview URL
    if (fileToRemove?.preview) {
      URL.revokeObjectURL(fileToRemove.preview);
    }
  };

  const replaceFile = (fileId, newFile) => {
    const validation = validateFile(newFile);
    if (!validation.isValid) {
      dispatch(showErrorToast(validation.errors[0]));
      return;
    }
    
    const oldFile = selectedFiles.find(f => f.id === fileId);
    if (oldFile?.preview) {
      URL.revokeObjectURL(oldFile.preview);
    }
    
    setSelectedFiles(prev => prev.map(f => 
      f.id === fileId ? {
        ...f,
        file: newFile,
        name: newFile.name,
        size: newFile.size,
        preview: URL.createObjectURL(newFile),
        status: 'pending',
        errorMessage: null
      } : f
    ));
  };

  // Drag handlers
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

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  // Clean up preview URLs on unmount
  useEffect(() => {
    return () => {
      selectedFiles.forEach(file => {
        if (file.preview) {
          URL.revokeObjectURL(file.preview);
        }
      });
    };
  }, [selectedFiles]);

  // Navigation helpers
  const canGoNext = () => {
    switch (currentStep) {
      case UPLOAD_STEPS.PATIENT_INFO:
        return patientData !== null;
      case UPLOAD_STEPS.FILE_UPLOAD:
        const hasFiles = selectedFiles.length > 0;
        const hasValidFiles = validationResults?.validFiles?.length > 0;
        return hasFiles && hasValidFiles;
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

  const goToStep = (step) => {
    if (step === UPLOAD_STEPS.PROCESSING) return; 
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
  const sessionId = localSession?.sessionId || currentSession?.sessionId;
  const currentProgress = uploadProgress[sessionId];

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
      
      {/* ✅ ADD: Debug Panel (temporary - remove in production) */}
      {process.env.NODE_ENV === 'development' && (
        <SocketDebugger sessionId={localSession?.sessionId || currentSession?.sessionId} />
      )}

      {/* Processing Overlay */}
      <OverlayLoader 
        show={isProcessing && currentStep === UPLOAD_STEPS.PROCESSING}
        text={`Processing samples... ${currentProgress?.overall || 0}% complete`}
      />

      {/* Header */}
      <div className="mb-8">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-4 border border-white/30">
            <TestTube className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">Upload Blood Samples</h1>
          <p className="text-blue-200">Upload and analyze blood smear images for malaria detection</p>
        </div>

        {/* Session Recovery Indicator */}
        {sessionRecovered && (
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-3 mb-4">
            <div className="flex items-center justify-center text-green-400">
              <Save className="w-4 h-4 mr-2" />
              <span className="text-sm">Session recovered</span>
            </div>
          </div>
        )}

        {/* Progress Steps */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <nav aria-label="Progress">
            <ol className="flex items-center justify-center space-x-2 md:space-x-4">
              {Object.entries(UPLOAD_STEPS).map(([key, step], index) => {
                const isActive = currentStep === step;
                const isCompleted = getStepIndex(currentStep) > index;
                const isAccessible = getStepIndex(currentStep) >= index;
                
                const stepNames = {
                  [UPLOAD_STEPS.PATIENT_INFO]: 'Patient Info',
                  [UPLOAD_STEPS.FILE_UPLOAD]: 'Upload Files',
                  [UPLOAD_STEPS.PROCESSING]: 'Processing',
                  [UPLOAD_STEPS.COMPLETE]: 'Complete'
                };

                const stepIcons = {
                  [UPLOAD_STEPS.PATIENT_INFO]: '👤',
                  [UPLOAD_STEPS.FILE_UPLOAD]: '📁',
                  [UPLOAD_STEPS.PROCESSING]: '⚡',
                  [UPLOAD_STEPS.COMPLETE]: '✅'
                };

                return (
                  <React.Fragment key={step}>
                    <li className="relative flex flex-col items-center">
                      <button
                        className={`relative flex h-12 w-12 items-center justify-center rounded-full transition-all duration-300 transform ${
                          isCompleted 
                            ? 'bg-green-500 text-white shadow-lg scale-110' 
                            : isActive 
                              ? 'bg-white text-blue-600 shadow-lg scale-105' 
                              : 'bg-white/20 text-white/60 border border-white/30'
                        } ${isAccessible ? 'cursor-pointer hover:scale-105' : 'cursor-not-allowed'}`}
                        onClick={() => isAccessible && goToStep(step)}
                        disabled={!isAccessible}
                        title={stepNames[step]}
                      >
                        {isCompleted ? (
                          <Check className="h-6 w-6" />
                        ) : (
                          <span className="text-lg">{stepIcons[step]}</span>
                        )}
                      </button>
                      
                      {/* Step Label */}
                      <div className="mt-3 text-center">
                        <span className={`text-xs md:text-sm font-medium transition-colors ${
                          isActive ? 'text-white' : 'text-blue-200'
                        }`}>
                          {stepNames[step]}
                        </span>
                      </div>
                    </li>
                    
                    {/* Connector Line */}
                    {index !== Object.keys(UPLOAD_STEPS).length - 1 && (
                      <div className={`hidden md:block w-16 lg:w-24 h-0.5 transition-colors ${
                        isCompleted ? 'bg-green-400' : 'bg-white/20'
                      }`} />
                    )}
                  </React.Fragment>
                );
              })}
            </ol>
          </nav>
        </div>
      </div>

      {/* Main Content Card */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg shadow-xl overflow-hidden">
        
        {/* PATIENT_INFO Step */}
        {currentStep === UPLOAD_STEPS.PATIENT_INFO && (
          <div className="p-6">
            <PatientForm
              initialData={patientData}
              testData={testData}
              onSubmit={handlePatientSubmit}
              onTestDataChange={setTestData}
              onPatientSelect={(selectedPatient) => {
                setPatientData(selectedPatient);
              }}
              loading={isCreatingPatient || isUpdatingPatient || isCreatingTest}
              error={errors.submit || patientsError || testsError}
            />
          </div>
        )}

        {/* FILE_UPLOAD Step */}
        {currentStep === UPLOAD_STEPS.FILE_UPLOAD && (
          <div className="p-6">
            {/* Test ID Display */}
            <div className="text-center mb-6">
              <h2 className="text-2xl font-semibold text-white mb-4">Upload Blood Smear Images</h2>
              <div className="flex items-center justify-center space-x-4 text-sm">
                <span className="text-blue-200">Test ID:</span>
                <span className="font-mono bg-white/10 px-3 py-1 rounded-lg text-white border border-white/20">
                  {testData.testId || localSession?.testId || 'Generating...'}
                </span>
              </div>
            </div>

            {selectedFiles.length === 0 ? (
              <DragDropZone
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onBrowseClick={handleBrowseClick}
                dragActive={dragActive}
                maxFiles={uploadConfig.MAX_FILES}
                maxFileSize={uploadConfig.MAX_FILE_SIZE}
                acceptedTypes={uploadConfig.ALLOWED_TYPES}
                disabled={isUploading}
              />
            ) : (
              <div className="space-y-4">
                <ImagePreview
                  files={selectedFiles}
                  onRemove={removeFile}
                  onReplace={replaceFile}
                  onRetryUpload={handleRetryFileUpload}
                  validationResults={validationResults}
                  editable={true}
                />
                
                <div className="text-center">
                  <button
                    onClick={handleBrowseClick}
                    className="bg-white/10 hover:bg-white/20 border border-white/30 text-white px-4 py-2 rounded-lg transition-colors"
                    disabled={selectedFiles.length >= uploadConfig.MAX_FILES}
                  >
                    Add More Images
                  </button>
                </div>
              </div>
            )}

            {errors.upload && (
              <div className="mt-4 bg-red-500/20 border border-red-500/30 rounded-lg p-3">
                <div className="flex items-center text-red-200">
                  <AlertCircle className="w-5 h-5 mr-2" />
                  <span className="text-sm">{errors.upload}</span>
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

        {/* PROCESSING Step */}
        {currentStep === UPLOAD_STEPS.PROCESSING && (
          <div className="p-6">
            <ProcessingStatus
              session={localSession || currentSession}
              progress={currentProgress}
              error={errors.processing}
              onRetry={handleRetry}
              onCancel={handleCancel}
            />
          </div>
        )}

        {/* COMPLETE Step */}
        {currentStep === UPLOAD_STEPS.COMPLETE && (
          <div className="p-8 text-center">
            <div className="w-20 h-20 bg-green-500/20 border border-green-500/30 rounded-full flex items-center justify-center mx-auto mb-6">
              <Check className="w-10 h-10 text-green-400" />
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Analysis Complete!</h3>
            <p className="text-blue-200 mb-8">
              Your blood samples have been successfully analyzed. The results are now available.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                onClick={() => navigate(`/results/${testData.testId}`)}
                className="bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-colors"
              >
                View Results
              </button>
              <button
                onClick={() => {
                  dispatch(clearCurrentSession());
                  setLocalSession(null);
                  sessionStorage.removeItem('currentUploadSession');
                  navigate(ROUTES.UPLOAD);
                }}
                className="bg-white/10 hover:bg-white/20 border border-white/30 text-white px-6 py-3 rounded-lg transition-colors"
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
            className={`flex items-center px-6 py-3 rounded-lg transition-colors ${
              canGoBack() && !isUploading
                ? 'bg-white/10 hover:bg-white/20 border border-white/30 text-white'
                : 'bg-white/5 border border-white/10 text-white/40 cursor-not-allowed'
            }`}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </button>

          <div className="flex space-x-4">
            {currentStep === UPLOAD_STEPS.FILE_UPLOAD && selectedFiles.length > 0 && (
              <button
                onClick={handleUpload}
                disabled={!canGoNext() || isUploading}
                className="flex items-center bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-all hover:scale-105 disabled:opacity-50 disabled:hover:scale-100"
              >
                {isUploading ? (
                  <>
                    <LoadingSpinner size="sm" color="blue" />
                    <span className="ml-2">Uploading...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4 mr-2" />
                    Upload & Process ({(validationResults?.validFiles?.length || 0)} valid files)
                  </>
                )}
              </button>
            )}

            {currentStep !== UPLOAD_STEPS.FILE_UPLOAD && (
              <button
                onClick={goNext}
                disabled={!canGoNext()}
                className="flex items-center bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-all hover:scale-105 disabled:opacity-50"
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
// src/pages/PatientManagementPage.jsx - FIXED SPACING BETWEEN SIDEBAR AND CONTENT
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Search, 
  Plus, 
  Eye, 
  Edit, 
  MoreHorizontal,
  User,
  Calendar,
  Phone,
  Mail,
  MapPin,
  Activity,
  TestTube,
  Clock,
  Filter,
  Download,
  ArrowLeft,
  X,
  Save,
  AlertTriangle,
  CheckCircle,
  FileText,
  Heart,
  Users,
  TrendingUp,
  ChevronRight,
  ChevronLeft,
  ArrowUpDown,
  RefreshCw,
  AlertCircle,
  Sparkles,
  Badge,
  Stethoscope,
  Database
} from 'lucide-react';

// Redux
import {
  fetchPatients,
  createPatient,
  updatePatient,
  fetchPatientById,
  searchPatients,
  selectPatients,
  selectCurrentPatient,
  selectSearchResults,
  selectPatientsLoading,
  selectPatientsError,
  selectPatientsPagination,
  selectIsCreatingPatient,
  selectIsUpdatingPatient,
  selectIsSearchingPatients,
  clearError,
  clearCurrentPatient,
  clearSearchResults
} from '../store/slices/patientsSlice';

import {
  fetchTests,
  getTestsByPatient,
  selectTests
} from '../store/slices/testsSlice';

import { showSuccessToast, showErrorToast, showWarningToast } from '../store/slices/notificationsSlice';
import { selectUser } from '../store/slices/authSlice';

// Components
import AppLayout from '../components/layout/AppLayout';
import LoadingSpinner, { TableSkeletonLoader, CardLoader } from '../components/common/LoadingSpinner';

// Services
import diagnosisService from '../services/diagnosisService';

// Utils
import { USER_ROLES, TEST_STATUSES } from '../utils/constants';

const patientsPerPage = 12;

const PatientManagementPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  
  // Redux state
  const patients = useSelector(selectPatients);
  const currentPatient = useSelector(selectCurrentPatient);
  const searchResults = useSelector(selectSearchResults);
  const isLoading = useSelector(selectPatientsLoading);
  const error = useSelector(selectPatientsError);
  const pagination = useSelector(selectPatientsPagination);
  const isCreating = useSelector(selectIsCreatingPatient);
  const isUpdating = useSelector(selectIsUpdatingPatient);
  const isSearching = useSelector(selectIsSearchingPatients);
  const user = useSelector(selectUser);
  const tests = useSelector(selectTests);

  // Local state
  const [searchTerm, setSearchTerm] = useState(searchParams.get('search') || '');
  const [currentView, setCurrentView] = useState(searchParams.get('view') || 'list');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [currentPage, setCurrentPage] = useState(parseInt(searchParams.get('page')) || 1);
  const [sortField, setSortField] = useState(searchParams.get('sort') || 'firstName');
  const [sortDirection, setSortDirection] = useState(searchParams.get('order') || 'asc');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [patientTests, setPatientTests] = useState([]);
  const [loadingTests, setLoadingTests] = useState(false);
  const [diagnosisData, setDiagnosisData] = useState({});
  const [loadingDiagnosis, setLoadingDiagnosis] = useState(false);

  // Form state for create/edit
  const [patientForm, setPatientForm] = useState({
    firstName: '',
    lastName: '',
    dateOfBirth: '',
    gender: '',
    bloodType: '',
    phoneNumber: '',
    email: '',
    address: '',
    emergencyContact: '',
    medicalHistory: '',
    allergies: ''
  });

  // Utility functions
  const safeRenderField = (field, fallback = 'Not provided') => {
    if (!field) return fallback;
    if (typeof field === 'string') return field;
    if (typeof field === 'object') {
      return JSON.stringify(field);
    }
    return String(field);
  };

  const formatAddress = (addr) => {
    if (!addr) return 'Not provided';
    if (typeof addr === 'string') return addr;
    if (typeof addr === 'object') {
      const parts = [
        addr.street,
        addr.city,
        addr.state,
        addr.zipCode,
        addr.country
      ].filter(Boolean);
      return parts.length > 0 ? parts.join(', ') : 'Not provided';
    }
    return 'Not provided';
  };

  const formatEmergencyContact = (contact) => {
    if (!contact) return 'Not provided';
    if (typeof contact === 'string') return contact;
    if (typeof contact === 'object') {
      const name = contact.name || '';
      const relationship = contact.relationship ? ` (${contact.relationship})` : '';
      const phone = contact.phoneNumber || contact.phone || '';
      return `${name}${relationship}${phone ? ` - ${phone}` : ''}`.trim() || 'Not provided';
    }
    return 'Not provided';
  };

  const loadDiagnosisData = useCallback(async (tests) => {
    if (!tests || tests.length === 0) return;
    
    console.log('🔍 Loading diagnosis data for patient tests:', tests.length);
    setLoadingDiagnosis(true);
    
    const testsToCheck = tests.filter(test => 
      test.status === TEST_STATUSES.COMPLETED || 
      test.status === 'completed' || 
      test.status === TEST_STATUSES.REVIEW ||
      test.status === 'review' ||
      test.status === 'processed'
    );
    
    console.log('🔍 Patient tests to check for diagnosis:', testsToCheck.length);
    
    if (testsToCheck.length === 0) {
      setLoadingDiagnosis(false);
      return;
    }

    try {
      const diagnosisPromises = testsToCheck.map(async (test) => {
        const testId = test.testId || test._id;
        try {
          console.log(`🔬 Fetching diagnosis for patient test: ${testId}`);
          const response = await diagnosisService.getByTestId(testId);
          console.log(`✅ Raw diagnosis response for patient test ${testId}:`, response);
          
          let diagnosisResult = null;
          
          if (response.success && response.data && response.data.result) {
            diagnosisResult = response.data.result;
            console.log(`✅ Found diagnosis in response.data.result:`, diagnosisResult);
          }
          else if (response.success && response.data) {
            diagnosisResult = response.data;
            console.log(`✅ Found diagnosis in response.data:`, diagnosisResult);
          }
          else if (response.data) {
            diagnosisResult = response.data;
            console.log(`✅ Found diagnosis in data:`, diagnosisResult);
          }
          else if (response) {
            diagnosisResult = response;
            console.log(`✅ Using response as diagnosis:`, diagnosisResult);
          }
          
          console.log(`📊 Final processed diagnosis for patient test ${testId}:`, diagnosisResult);
          
          return {
            testId,
            data: diagnosisResult
          };
        } catch (error) {
          console.warn(`❌ Failed to fetch diagnosis for patient test ${testId}:`, error.message);
          return {
            testId,
            data: null,
            error: error.message
          };
        }
      });

      const diagnosisResults = await Promise.all(diagnosisPromises);
      console.log('📊 All patient diagnosis results:', diagnosisResults);
      
      const diagnosisMap = {};
      diagnosisResults.forEach(({ testId, data, error }) => {
        if (data) {
          diagnosisMap[testId] = data;
        }
        if (error) {
          console.warn(`⚠️ Error for patient test ${testId}:`, error);
        }
      });
      
      console.log('📋 Final patient diagnosis map:', diagnosisMap);
      setDiagnosisData(diagnosisMap);
    } catch (error) {
      console.error('💥 Error loading patient diagnosis data:', error);
    } finally {
      setLoadingDiagnosis(false);
    }
  }, []);

  // Load patients on mount and when filters change
  useEffect(() => {
    loadPatients();
  }, [currentPage, sortField, sortDirection]);

  // Handle search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchTerm.trim()) {
        handleSearch();
      } else {
        dispatch(clearSearchResults());
        loadPatients();
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Update URL when params change
  useEffect(() => {
    const params = new URLSearchParams();
    if (searchTerm) params.set('search', searchTerm);
    if (currentView !== 'list') params.set('view', currentView);
    if (sortField !== 'firstName') params.set('sort', sortField);
    if (sortDirection !== 'asc') params.set('order', sortDirection);
    if (currentPage !== 1) params.set('page', currentPage.toString());
    if (patientsPerPage !== 12) params.set('limit', patientsPerPage.toString());
    
    setSearchParams(params);
  }, [searchTerm, currentView, sortField, sortDirection, currentPage, patientsPerPage, setSearchParams]);

  // Clear diagnosis data when switching patients or views
  useEffect(() => {
    if (currentView === 'list' || !currentPatient) {
      setDiagnosisData({});
      setLoadingDiagnosis(false);
    }
  }, [currentView, currentPatient]);

  const loadPatients = useCallback(async () => {
    const params = {
      page: currentPage,
      limit: patientsPerPage,
      sort: sortField,
      order: sortDirection
    };

    try {
      await dispatch(fetchPatients(params)).unwrap();
    } catch (error) {
      console.error('Failed to load patients:', error);
    }
  }, [dispatch, currentPage, patientsPerPage, sortField, sortDirection]);

  const handleSearch = useCallback(async () => {
    if (!searchTerm.trim()) return;
    
    try {
      await dispatch(searchPatients(searchTerm.trim())).unwrap();
    } catch (error) {
      dispatch(showErrorToast('Search failed'));
    }
  }, [dispatch, searchTerm]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await loadPatients();
    setIsRefreshing(false);
    dispatch(showSuccessToast('Patients refreshed'));
  };

  const handleCreatePatient = async () => {
    try {
      const patientData = {
        ...patientForm,
        phoneNumber: patientForm.phoneNumber || patientForm.phone
      };

      const newPatient = await dispatch(createPatient(patientData)).unwrap();
      dispatch(showSuccessToast('Patient created successfully'));
      setShowCreateModal(false);
      resetForm();
      
      await dispatch(fetchPatientById(newPatient.patientId || newPatient._id));
      setCurrentView('details');
    } catch (error) {
      dispatch(showErrorToast(error.message || 'Failed to create patient'));
    }
  };

  const handleUpdatePatient = async () => {
    if (!currentPatient) return;

    try {
      const patientId = currentPatient.patientId || currentPatient._id;
      const updatedPatient = await dispatch(updatePatient({ 
        patientId, 
        patientData: patientForm 
      })).unwrap();
      
      dispatch(showSuccessToast('Patient updated successfully'));
      setShowEditModal(false);
      resetForm();
    } catch (error) {
      dispatch(showErrorToast(error.message || 'Failed to update patient'));
    }
  };

  const handleViewPatient = async (patient) => {
    try {
      const patientId = patient.patientId || patient._id;
      const fullPatient = await dispatch(fetchPatientById(patientId)).unwrap();
      
      setCurrentView('details');
      loadPatientTests(patientId);
    } catch (error) {
      dispatch(showErrorToast('Failed to load patient details'));
    }
  };

  const loadPatientTests = async (patientId) => {
    setLoadingTests(true);
    try {
      const response = await dispatch(getTestsByPatient({ patientId })).unwrap();
      const tests = response.tests || response || [];
      setPatientTests(tests);
      
      console.log('🔄 Loading diagnosis data for patient tests:', tests.length);
      await loadDiagnosisData(tests);
    } catch (error) {
      console.error('Failed to load patient tests:', error);
      setPatientTests([]);
    } finally {
      setLoadingTests(false);
    }
  };

  const resetForm = () => {
    setPatientForm({
      firstName: '',
      lastName: '',
      dateOfBirth: '',
      gender: '',
      bloodType: '',
      phoneNumber: '',
      email: '',
      address: '',
      emergencyContact: '',
      medicalHistory: '',
      allergies: ''
    });
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const calculateAge = (dateOfBirth) => {
    if (!dateOfBirth) return 'N/A';
    const today = new Date();
    const birth = new Date(dateOfBirth);
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age--;
    }
    
    return age;
  };

  const getRiskLevel = (patient) => {
    const positiveTests = patient.positiveTests || 0;
    const totalTests = patient.totalTests || patient.testHistory?.length || 0;
    
    if (totalTests === 0) return { level: 'Unknown', color: 'bg-gray-100 text-gray-800 border-gray-200' };
    
    const riskScore = positiveTests / totalTests;
    if (riskScore >= 0.5) return { level: 'High', color: 'bg-red-500/10 text-red-400 border-red-500/20' };
    if (riskScore >= 0.25) return { level: 'Medium', color: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' };
    return { level: 'Low', color: 'bg-green-500/10 text-green-400 border-green-500/20' };
  };

  const getResultBadge = (test) => {
    const testId = test.testId || test._id;
    const diagnosis = diagnosisData[testId];
    
    console.log(`🎯 Getting result for patient test ${testId}:`, { status: test.status, diagnosis });
    
    if (!diagnosis) {
      if (test.status === TEST_STATUSES.COMPLETED || test.status === 'completed') {
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-yellow-500/10 text-yellow-400 border-yellow-500/20 animate-pulse">
            <Clock className="w-3 h-3 mr-1" />
            Loading...
          </span>
        );
      }
      return (
        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-blue-500/10 text-blue-400 border-blue-500/20">
          <Clock className="w-3 h-3 mr-1" />
          PENDING
        </span>
      );
    }

    let malariaResult = null;
    
    console.log(`🔍 Available diagnosis fields for patient test ${testId}:`, diagnosis ? Object.keys(diagnosis) : 'none');
    
    if (diagnosis && typeof diagnosis.status === 'string') {
      malariaResult = diagnosis.status;
      console.log(`✅ Found status field for patient test:`, malariaResult);
    }
    else if (diagnosis && diagnosis.result && typeof diagnosis.result.status === 'string') {
      malariaResult = diagnosis.result.status;
      console.log(`✅ Found nested result.status for patient test:`, malariaResult);
    }
    else if (diagnosis && diagnosis.apiResponse?.rawResponse?.status && typeof diagnosis.apiResponse.rawResponse.status === 'string') {
      malariaResult = diagnosis.apiResponse.rawResponse.status;
      console.log(`✅ Found API response status for patient test:`, malariaResult);
    }
    else if (diagnosis && diagnosis.finalStatus && typeof diagnosis.finalStatus === 'string') {
      malariaResult = diagnosis.finalStatus;
      console.log(`✅ Found finalStatus field for patient test:`, malariaResult);
    }
    
    console.log(`🔍 Final malaria result for patient test ${testId}:`, malariaResult);
    
    if (malariaResult) {
      const resultStr = String(malariaResult).toUpperCase();
      
      if (resultStr === 'POS' || resultStr === 'POSITIVE') {
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-red-500/10 text-red-400 border-red-500/20">
            <AlertTriangle className="w-3 h-3 mr-1" />
            POSITIVE
          </span>
        );
      }
      
      if (resultStr === 'NEG' || resultStr === 'NEGATIVE') {
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-green-500/10 text-green-400 border-green-500/20">
            <CheckCircle className="w-3 h-3 mr-1" />
            NEGATIVE
          </span>
        );
      }
      
      return (
        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
          <Database className="w-3 h-3 mr-1" />
          {resultStr}
        </span>
      );
    }
    
    return (
      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border bg-blue-500/10 text-blue-400 border-blue-500/20">
        <Clock className="w-3 h-3 mr-1" />
        PENDING
      </span>
    );
  };

  // Use search results if searching, otherwise use regular patients
  const displayPatients = searchTerm.trim() ? searchResults : patients;
  const totalPages = searchTerm.trim() ? Math.ceil(searchResults.length / patientsPerPage) : pagination.pages;

  const PatientDetailsView = ({ patient }) => (
    <div className="space-y-6">
      {/* Patient Header */}
      <div className="bg-gradient-to-r from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-xl">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-4">
            <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-3 rounded-xl shadow-lg">
              <User className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                {patient.firstName} {patient.lastName}
                <Badge className="w-4 h-4 text-blue-300" />
              </h2>
              <p className="text-blue-200 font-medium">{patient.patientId}</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => {
                setPatientForm({
                  firstName: patient.firstName || '',
                  lastName: patient.lastName || '',
                  dateOfBirth: patient.dateOfBirth ? patient.dateOfBirth.split('T')[0] : '',
                  gender: patient.gender || '',
                  bloodType: patient.bloodType || '',
                  phoneNumber: patient.phoneNumber || patient.phone || '',
                  email: patient.email || '',
                  address: formatAddress(patient.address),
                  emergencyContact: formatEmergencyContact(patient.emergencyContact),
                  medicalHistory: patient.medicalHistory || '',
                  allergies: patient.allergies || ''
                });
                setShowEditModal(true);
              }}
              className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105"
            >
              <Edit className="h-4 w-4" />
              <span>Edit</span>
            </button>
            <button 
              onClick={() => navigate(`/upload?patientId=${patient.patientId}`)}
              className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white transition-all duration-200 hover:scale-105 shadow-lg"
            >
              <TestTube className="h-4 w-4" />
              <span>New Test</span>
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gradient-to-br from-green-500/10 to-green-600/5 border border-green-500/20 rounded-xl p-4 hover:bg-green-500/20 transition-all duration-300">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <Activity className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-green-200 text-sm font-medium">Total Tests</p>
                <p className="text-white font-bold text-xl">{patient.totalTests || patientTests.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border border-orange-500/20 rounded-xl p-4 hover:bg-orange-500/20 transition-all duration-300">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-orange-500/20 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-orange-200 text-sm font-medium">Positive Tests</p>
                <p className="text-white font-bold text-xl">{patient.positiveTests || 0}</p>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border border-blue-500/20 rounded-xl p-4 hover:bg-blue-500/20 transition-all duration-300">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <TrendingUp className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-blue-200 text-sm font-medium">Risk Level</p>
                <span className={`inline-flex items-center px-2 py-1 rounded-lg text-xs font-medium border ${getRiskLevel(patient).color}`}>
                  <Sparkles className="w-3 h-3 mr-1" />
                  {getRiskLevel(patient).level}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Patient Information */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <User className="w-5 h-5 text-blue-400" />
            Personal Information
          </h3>
          <div className="space-y-4">
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <Calendar className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Date of Birth</p>
                <p className="text-white">
                  {formatDate(patient.dateOfBirth)} ({calculateAge(patient.dateOfBirth)} years old)
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <User className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Gender</p>
                <p className="text-white">{patient.gender || 'Not specified'}</p>
              </div>
            </div>
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <Heart className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Blood Type</p>
                <p className="text-white">{patient.bloodType || 'Not specified'}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Phone className="w-5 h-5 text-blue-400" />
            Contact Information
          </h3>
          <div className="space-y-4">
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <Phone className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Phone</p>
                <p className="text-white">{patient.phoneNumber || patient.phone || 'Not provided'}</p>
              </div>
            </div>
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <Mail className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Email</p>
                <p className="text-white">{patient.email || 'Not provided'}</p>
              </div>
            </div>
            <div className="flex items-start space-x-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
              <MapPin className="h-4 w-4 text-blue-400 mt-1" />
              <div>
                <p className="text-blue-200 text-sm font-medium">Address</p>
                <p className="text-white">{formatAddress(patient.address)}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Stethoscope className="w-5 h-5 text-blue-400" />
            Medical Information
          </h3>
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-white/5">
              <p className="text-blue-200 text-sm mb-1 font-medium">Medical History</p>
              <p className="text-white text-sm">{safeRenderField(patient.medicalHistory, 'No significant medical history')}</p>
            </div>
            <div className="p-3 rounded-lg bg-white/5">
              <p className="text-blue-200 text-sm mb-1 font-medium">Allergies</p>
              <p className="text-white text-sm">{safeRenderField(patient.allergies, 'None known')}</p>
            </div>
            <div className="p-3 rounded-lg bg-white/5">
              <p className="text-blue-200 text-sm mb-1 font-medium">Emergency Contact</p>
              <p className="text-white text-sm">{formatEmergencyContact(patient.emergencyContact)}</p>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <TestTube className="w-5 h-5 text-blue-400" />
            Recent Test History
          </h3>
          
          {loadingDiagnosis && (
            <div className="mb-3 text-blue-300 text-sm flex items-center p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <LoadingSpinner size="xs" color="white" />
              <span className="ml-2">Loading diagnosis results...</span>
            </div>
          )}
          
          {loadingTests ? (
            <div className="space-y-3">
              <LoadingSpinner size="sm" text="Loading test history..." />
            </div>
          ) : (
            <div className="space-y-3">
              {patientTests.slice(0, 3).map((test) => (
                <div key={test.testId} className="flex items-center justify-between p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-colors border border-white/10">
                  <div>
                    <p className="text-white text-sm font-medium">{test.testId}</p>
                    <p className="text-blue-300 text-xs">{formatDate(test.createdAt)}</p>
                  </div>
                  <div className="text-right">
                    {getResultBadge(test)}
                  </div>
                </div>
              ))}
              {patientTests.length === 0 && (
                <p className="text-blue-300 text-sm text-center py-4">No test history available</p>
              )}
              {patientTests.length > 3 && (
                <button
                  onClick={() => setCurrentView('history')}
                  className="w-full text-blue-300 hover:text-white text-sm py-2 border border-white/20 rounded-lg hover:bg-white/5 transition-all duration-200"
                >
                  View Full History ({patientTests.length} tests)
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const PatientHistoryView = ({ patient }) => (
    <div className="space-y-6">
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <TestTube className="w-5 h-5 text-blue-400" />
          Test History for {patient.firstName} {patient.lastName}
        </h3>
        
        {loadingDiagnosis && (
          <div className="mb-4 text-blue-300 text-sm flex items-center p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
            <LoadingSpinner size="xs" color="white" />
            <span className="ml-2">Loading diagnosis results...</span>
          </div>
        )}
        
        {loadingTests ? (
          <TableSkeletonLoader rows={5} columns={4} />
        ) : (
          <div className="space-y-4">
            {patientTests.map((test) => (
              <div key={test.testId} className="flex items-center justify-between p-4 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-all duration-200">
                <div className="flex-1">
                  <div className="flex items-center space-x-4 mb-2">
                    <p className="text-white font-medium">{test.testId}</p>
                    {getResultBadge(test)}
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-blue-300">
                    <span>{formatDate(test.createdAt)}</span>
                    <span>•</span>
                    <span>Status: {test.status}</span>
                    {test.technician && (
                      <>
                        <span>•</span>
                        <span>by {test.technician.firstName} {test.technician.lastName}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button 
                    onClick={() => navigate(`/results/${test.testId}`)}
                    className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                  >
                    <Eye className="h-4 w-4" />
                  </button>
                  <button className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                    <FileText className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
            {patientTests.length === 0 && (
              <div className="text-center py-8">
                <TestTube className="h-12 w-12 text-blue-400 mx-auto mb-4" />
                <p className="text-white font-medium mb-2">No test history</p>
                <p className="text-blue-300 text-sm mb-4">This patient hasn't had any tests yet.</p>
                <button 
                  onClick={() => navigate(`/upload?patientId=${patient.patientId}`)}
                  className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
                >
                  Create First Test
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );

  const PatientFormModal = ({ isEdit = false }) => (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-white/20 rounded-xl p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white flex items-center gap-2">
            <User className="w-5 h-5 text-blue-400" />
            {isEdit ? 'Edit Patient' : 'Create New Patient'}
          </h3>
          <button
            onClick={() => {
              isEdit ? setShowEditModal(false) : setShowCreateModal(false);
              resetForm();
            }}
            className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">First Name *</label>
              <input
                type="text"
                value={patientForm.firstName}
                onChange={(e) => setPatientForm({...patientForm, firstName: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="Enter first name"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Last Name *</label>
              <input
                type="text"
                value={patientForm.lastName}
                onChange={(e) => setPatientForm({...patientForm, lastName: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="Enter last name"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Date of Birth *</label>
              <input
                type="date"
                value={patientForm.dateOfBirth}
                onChange={(e) => setPatientForm({...patientForm, dateOfBirth: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Gender *</label>
              <select
                value={patientForm.gender}
                onChange={(e) => setPatientForm({...patientForm, gender: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              >
                <option value="">Select gender</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Blood Type</label>
              <select
                value={patientForm.bloodType}
                onChange={(e) => setPatientForm({...patientForm, bloodType: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              >
                <option value="">Select blood type</option>
                <option value="A+">A+</option>
                <option value="A-">A-</option>
                <option value="B+">B+</option>
                <option value="B-">B-</option>
                <option value="AB+">AB+</option>
                <option value="AB-">AB-</option>
                <option value="O+">O+</option>
                <option value="O-">O-</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Phone Number *</label>
              <input
                type="tel"
                value={patientForm.phoneNumber}
                onChange={(e) => setPatientForm({...patientForm, phoneNumber: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="+250 788 123 456"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Email</label>
              <input
                type="email"
                value={patientForm.email}
                onChange={(e) => setPatientForm({...patientForm, email: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="patient@email.com"
              />
            </div>
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Address</label>
            <input
              type="text"
              value={patientForm.address}
              onChange={(e) => setPatientForm({...patientForm, address: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              placeholder="City, Country"
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Emergency Contact</label>
            <input
              type="text"
              value={patientForm.emergencyContact}
              onChange={(e) => setPatientForm({...patientForm, emergencyContact: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              placeholder="Name - Phone number"
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Medical History</label>
            <textarea
              value={patientForm.medicalHistory}
              onChange={(e) => setPatientForm({...patientForm, medicalHistory: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              rows={3}
              placeholder="Previous conditions, surgeries, etc."
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Allergies</label>
            <input
              type="text"
              value={patientForm.allergies}
              onChange={(e) => setPatientForm({...patientForm, allergies: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
              placeholder="Known allergies or 'None known'"
            />
          </div>

          <div className="flex items-center justify-end space-x-3 pt-6 border-t border-white/20">
            <button
              onClick={() => {
                isEdit ? setShowEditModal(false) : setShowCreateModal(false);
                resetForm();
              }}
              className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={isEdit ? handleUpdatePatient : handleCreatePatient}
              disabled={isEdit ? isUpdating : isCreating}
              className="flex items-center space-x-2 px-6 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg transition-all duration-200 disabled:opacity-50 hover:scale-105 shadow-lg"
            >
              {(isEdit ? isUpdating : isCreating) ? (
                <LoadingSpinner size="sm" color="white" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              <span>{isEdit ? 'Update Patient' : 'Create Patient'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  if (error) {
    return (
      <AppLayout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Error Loading Patients</h2>
            <p className="text-blue-200 mb-4">{error}</p>
            <button
              onClick={handleRefresh}
              className="bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      {/* ✨ Enhanced Header */}
      <div className="bg-gradient-to-r from-white/10 to-white/5 backdrop-blur-md border-b border-white/20 mb-6 shadow-lg">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {currentView !== 'list' && (
                <button
                  onClick={() => {
                    setCurrentView('list');
                    dispatch(clearCurrentPatient());
                    setPatientTests([]);
                  }}
                  className="mr-2 p-2 text-blue-200 hover:text-white hover:bg-white/10 rounded-lg transition-all duration-200 hover:scale-105"
                >
                  <ArrowLeft className="h-5 w-5" />
                </button>
              )}
              <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-2 rounded-xl shadow-lg">
                <Users className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white flex items-center gap-2">
                  {currentView === 'list' ? 'Patient Management' : 
                   currentView === 'details' ? 'Patient Details' : 'Test History'}
                  <Sparkles className="w-4 h-4 text-blue-300" />
                </h1>
                <p className="text-blue-200 text-sm">
                  {currentView === 'list' ? 'Manage patient records and medical history' :
                   currentPatient ? `${currentPatient.firstName} ${currentPatient.lastName} • ${currentPatient.patientId}` : ''}
                </p>
              </div>
            </div>

            {currentView === 'list' && (
              <div className="flex items-center space-x-3">
                <button
                  onClick={handleRefresh}
                  disabled={isLoading || isRefreshing}
                  className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105"
                >
                  <RefreshCw className={`h-4 w-4 ${(isLoading || isRefreshing) ? 'animate-spin' : ''}`} />
                  <span>Refresh</span>
                </button>
                <button className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105">
                  <Download className="h-4 w-4" />
                  <span>Export</span>
                </button>
                {(user?.role === USER_ROLES.ADMIN || user?.role === USER_ROLES.SUPERVISOR) && (
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white transition-all duration-200 hover:scale-105 shadow-lg"
                  >
                    <Plus className="h-4 w-4" />
                    <span>New Patient</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ✅ FIXED: Main Content Area with proper spacing */}
      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 overflow-y-auto">
        <div className="max-w-7xl mx-auto">
          <div className="space-y-6">
            
            {currentView === 'list' && (
              <>
                {/* ✨ Enhanced Search and Filters */}
                <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg">
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
                    <div className="relative flex-1 max-w-md">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
                      <input
                        type="text"
                        placeholder="Search patients by name, ID, phone..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                      />
                      {isSearching && (
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                          <LoadingSpinner size="xs" color="white" />
                        </div>
                      )}
                    </div>

                    <div className="flex items-center space-x-4 text-blue-200 text-sm">
                      <span className="flex items-center gap-1">
                        <Database className="w-4 h-4" />
                        Showing {displayPatients.length} of {searchTerm.trim() ? searchResults.length : pagination.total} patients
                      </span>
                    </div>
                  </div>
                </div>

                {/* ✨ Enhanced Patients Grid */}
                {isLoading ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    {Array.from({ length: 8 }).map((_, i) => (
                      <CardLoader key={i} />
                    ))}
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    {displayPatients.map((patient) => (
                      <div key={patient.patientId || patient._id} className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:bg-white/15 transition-all duration-300 hover:scale-105 shadow-lg hover:shadow-xl">
                        <div className="flex items-center justify-between mb-4">
                          <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-2 rounded-xl shadow-lg">
                            <User className="h-5 w-5 text-white" />
                          </div>
                          <button className="text-blue-300 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors">
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                        </div>

                        <div className="mb-4">
                          <h3 className="text-white font-medium mb-1 flex items-center gap-1">
                            {patient.firstName} {patient.lastName}
                            <Badge className="w-3 h-3 text-blue-300" />
                          </h3>
                          <p className="text-blue-300 text-sm font-medium">{patient.patientId}</p>
                          <p className="text-blue-200 text-sm">
                            {calculateAge(patient.dateOfBirth)} years • {patient.gender || 'Unknown'}
                          </p>
                        </div>

                        <div className="flex items-center justify-between mb-4">
                          <div className="text-center">
                            <p className="text-white font-bold">{patient.totalTests || 0}</p>
                            <p className="text-blue-300 text-xs">Tests</p>
                          </div>
                          <div className="text-center">
                            <p className="text-white font-bold">{patient.positiveTests || 0}</p>
                            <p className="text-blue-300 text-xs">Positive</p>
                          </div>
                          <div className="text-center">
                            <span className={`px-2 py-1 rounded-lg text-xs font-medium border ${getRiskLevel(patient).color} flex items-center gap-1`}>
                              <TrendingUp className="w-3 h-3" />
                              {getRiskLevel(patient).level}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleViewPatient(patient)}
                            className="flex-1 flex items-center justify-center space-x-2 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg text-sm transition-all duration-200 hover:scale-105 shadow-lg"
                          >
                            <Eye className="h-3 w-3" />
                            <span>View</span>
                          </button>
                          <button 
                            onClick={() => navigate(`/upload?patientId=${patient.patientId}`)}
                            className="flex items-center justify-center py-2 px-3 bg-white/10 hover:bg-white/20 border border-white/20 text-white rounded-lg text-sm transition-all duration-200 hover:scale-105"
                          >
                            <TestTube className="h-3 w-3" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ✨ Enhanced Empty State */}
                {!isLoading && displayPatients.length === 0 && (
                  <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-12 text-center shadow-lg">
                    <Users className="h-12 w-12 text-blue-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-white mb-2">No patients found</h3>
                    <p className="text-blue-200 mb-6">
                      {searchTerm
                        ? 'Try adjusting your search criteria.'
                        : 'No patients have been registered yet.'}
                    </p>
                    {(user?.role === USER_ROLES.ADMIN || user?.role === USER_ROLES.SUPERVISOR) && (
                      <button
                        onClick={() => setShowCreateModal(true)}
                        className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg transition-all duration-200 hover:scale-105 shadow-lg"
                      >
                        Create First Patient
                      </button>
                    )}
                  </div>
                )}

                {/* ✨ Enhanced Pagination */}
                {!searchTerm.trim() && totalPages > 1 && (
                  <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-4 shadow-lg">
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-blue-200">
                        Showing {((pagination.page - 1) * patientsPerPage) + 1} to {Math.min(pagination.page * patientsPerPage, pagination.total)} of {pagination.total} results
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                          disabled={currentPage === 1}
                          className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                        >
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                        
                        <div className="flex items-center space-x-1">
                          {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                            const page = i + 1;
                            return (
                              <button
                                key={page}
                                onClick={() => setCurrentPage(page)}
                                className={`px-3 py-1 rounded-lg text-sm transition-all duration-200 ${
                                  currentPage === page
                                    ? 'bg-gradient-to-r from-blue-500 to-blue-600 text-white shadow-lg'
                                    : 'text-blue-300 hover:text-white hover:bg-white/10'
                                }`}
                              >
                                {page}
                              </button>
                            );
                          })}
                        </div>

                        <button
                          onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                          disabled={currentPage === totalPages}
                          className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                        >
                          <ChevronRight className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}

            {currentView === 'details' && currentPatient && (
              <PatientDetailsView patient={currentPatient} />
            )}

            {currentView === 'history' && currentPatient && (
              <PatientHistoryView patient={currentPatient} />
            )}
          </div>
        </div>
      </main>

      {/* Modals */}
      {showCreateModal && <PatientFormModal />}
      {showEditModal && <PatientFormModal isEdit={true} />}
    </AppLayout>
  );
};

export default PatientManagementPage;
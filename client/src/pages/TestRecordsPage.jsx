// src/pages/TestRecordsPage.jsx 
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  Download, 
  Eye, 
  MoreHorizontal,
  Calendar,
  User,
  TestTube,
  Clock,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Loader,
  RefreshCw,
  Plus,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  FileText,
  Trash2,
  AlertCircle,
  Image,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Zap
} from 'lucide-react';

// Redux
import {
  fetchTests,
  selectTests,
  selectTestsLoading,
  selectTestsError,
  selectTestsPagination,
  clearTestsError
} from '../store/slices/testsSlice';
import { showSuccessToast, showErrorToast, showInfoToast } from '../store/slices/notificationsSlice';
import { selectUser } from '../store/slices/authSlice';

// Components
import AppLayout from '../components/layout/AppLayout';
import LoadingSpinner, { TableSkeletonLoader } from '../components/common/LoadingSpinner';

// Utils
import { 
  TEST_STATUSES, 
  TEST_PRIORITIES, 
  TEST_RESULTS,
  USER_ROLES 
} from '../utils/constants';
import apiService from '../services/api';
import diagnosisService from '../services/diagnosisService';

// Helper function to safely extract user names
const getUserDisplayName = (user) => {
  if (!user) return 'N/A';
  if (typeof user === 'string') return user;
  
  const fullName = `${user.firstName || ''} ${user.lastName || ''}`.trim();
  return fullName || user.username || user.name || 'Unknown';
};

const TestRecordsPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  
  // Redux state
  const tests = useSelector(selectTests);
  const isLoading = useSelector(selectTestsLoading);
  const error = useSelector(selectTestsError);
  const pagination = useSelector(selectTestsPagination);
  const user = useSelector(selectUser);

  // Local state
  const [searchTerm, setSearchTerm] = useState(searchParams.get('search') || '');
  const [sortField, setSortField] = useState(searchParams.get('sort') || 'createdAt');
  const [sortDirection, setSortDirection] = useState(searchParams.get('order') || 'desc');
  const [currentPage, setCurrentPage] = useState(parseInt(searchParams.get('page')) || 1);
  const [filters, setFilters] = useState({
    status: searchParams.get('status') || 'all',
    result: searchParams.get('result') || 'all',
    priority: searchParams.get('priority') || 'all',
    dateRange: searchParams.get('dateRange') || '7days',
    technician: searchParams.get('technician') || 'all'
  });
  const [selectedTests, setSelectedTests] = useState([]);
  const [showFilters, setShowFilters] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // ✅ SIMPLIFIED: State to store diagnosis data for each test
  const [diagnosisData, setDiagnosisData] = useState({});
  const [loadingDiagnosis, setLoadingDiagnosis] = useState(false);

  const testsPerPage = parseInt(searchParams.get('limit')) || 10;

  // ✅ FIXED: Function to fetch diagnosis data with correct backend structure handling
  const loadDiagnosisData = useCallback(async (tests) => {
    if (!tests || tests.length === 0) return;
    
    console.log('🔍 Loading diagnosis data for tests:', tests.length);
    setLoadingDiagnosis(true);
    
    // Filter tests that might have diagnosis results
    const testsToCheck = tests.filter(test => 
      test.status === TEST_STATUSES.COMPLETED || 
      test.status === 'completed' || 
      test.status === TEST_STATUSES.REVIEW ||
      test.status === 'review' ||
      test.status === 'processed' // Sometimes status might be 'processed'
    );
    
    console.log('🔍 Tests to check for diagnosis:', testsToCheck.length);
    
    if (testsToCheck.length === 0) {
      setLoadingDiagnosis(false);
      return;
    }

    try {
      // ✅ FIXED: Process diagnosis requests with correct backend structure handling
      const diagnosisPromises = testsToCheck.map(async (test) => {
        const testId = test.testId || test._id;
        try {
          console.log(`🔬 Fetching diagnosis for test: ${testId}`);
          const response = await diagnosisService.getByTestId(testId);
          console.log(`✅ Raw diagnosis response for ${testId}:`, response);
          
          // ✅ BACKEND SPECIFIC: Handle your backend's response structure
          let diagnosisResult = null;
          
          // Your backend returns: { success: true, data: { result: DiagnosisResult } }
          if (response.success && response.data && response.data.result) {
            diagnosisResult = response.data.result;
            console.log(`✅ Found diagnosis in response.data.result:`, diagnosisResult);
          }
          // Fallback: Maybe it's directly in data
          else if (response.success && response.data) {
            diagnosisResult = response.data;
            console.log(`✅ Found diagnosis in response.data:`, diagnosisResult);
          }
          // Fallback: Direct response
          else if (response.data) {
            diagnosisResult = response.data;
            console.log(`✅ Found diagnosis in data:`, diagnosisResult);
          }
          // Fallback: Response is the data
          else if (response) {
            diagnosisResult = response;
            console.log(`✅ Using response as diagnosis:`, diagnosisResult);
          }
          
          console.log(`📊 Final processed diagnosis for ${testId}:`, diagnosisResult);
          
          return {
            testId,
            data: diagnosisResult
          };
        } catch (error) {
          console.warn(`❌ Failed to fetch diagnosis for test ${testId}:`, error.message);
          return {
            testId,
            data: null,
            error: error.message
          };
        }
      });

      const diagnosisResults = await Promise.all(diagnosisPromises);
      console.log('📊 All diagnosis results:', diagnosisResults);
      
      // Convert to object for easy lookup
      const diagnosisMap = {};
      diagnosisResults.forEach(({ testId, data, error }) => {
        if (data) {
          diagnosisMap[testId] = data;
        }
        if (error) {
          console.warn(`⚠️ Error for test ${testId}:`, error);
        }
      });
      
      console.log('📋 Final diagnosis map:', diagnosisMap);
      setDiagnosisData(diagnosisMap);
    } catch (error) {
      console.error('💥 Error loading diagnosis data:', error);
    } finally {
      setLoadingDiagnosis(false);
    }
  }, []);

  // Load tests on mount and when filters change
  useEffect(() => {
    loadTests();
  }, [currentPage, sortField, sortDirection, searchTerm, filters]);

  const loadTests = useCallback(async () => {
    const params = {
      page: currentPage,
      limit: testsPerPage,
      sort: sortField,
      order: sortDirection
    };

    // Add search
    if (searchTerm.trim()) {
      params.search = searchTerm.trim();
    }

    // Add filters
    if (filters.status !== 'all') params.status = filters.status;
    if (filters.result !== 'all') params.result = filters.result;
    if (filters.priority !== 'all') params.priority = filters.priority;
    if (filters.technician !== 'all') params.technician = filters.technician;

    // Date range filter
    if (filters.dateRange !== 'all') {
      const now = new Date();
      const days = {
        '7days': 7,
        '30days': 30,
        '90days': 90
      };
      
      if (days[filters.dateRange]) {
        const fromDate = new Date(now - days[filters.dateRange] * 24 * 60 * 60 * 1000);
        params.dateFrom = fromDate.toISOString().split('T')[0];
      }
    }

    console.log('🔄 Loading tests with params:', params);
    
    try {
      const response = await dispatch(fetchTests(params));
      console.log('📋 fetchTests response:', response);
      
      // Load diagnosis data for completed tests
      if (response.payload && Array.isArray(response.payload.tests)) {
        console.log('📊 Loading diagnosis for tests from response.payload.tests');
        await loadDiagnosisData(response.payload.tests);
      } else if (response.payload && Array.isArray(response.payload)) {
        console.log('📊 Loading diagnosis for tests from response.payload');
        await loadDiagnosisData(response.payload);
      }
    } catch (error) {
      console.error('💥 Error in loadTests:', error);
    }
  }, [dispatch, currentPage, testsPerPage, sortField, sortDirection, searchTerm, filters, loadDiagnosisData]);

  // Load diagnosis data when tests change in Redux state
  useEffect(() => {
    if (tests && tests.length > 0) {
      console.log('🔄 Tests changed in Redux, loading diagnosis data:', tests.length);
      loadDiagnosisData(tests);
    }
  }, [tests, loadDiagnosisData]);

  // Update URL when filters change
  useEffect(() => {
    const params = new URLSearchParams();
    if (searchTerm) params.set('search', searchTerm);
    if (filters.status !== 'all') params.set('status', filters.status);
    if (filters.result !== 'all') params.set('result', filters.result);
    if (filters.priority !== 'all') params.set('priority', filters.priority);
    if (filters.technician !== 'all') params.set('technician', filters.technician);
    if (filters.dateRange !== '7days') params.set('dateRange', filters.dateRange);
    if (sortField !== 'createdAt') params.set('sort', sortField);
    if (sortDirection !== 'desc') params.set('order', sortDirection);
    if (currentPage !== 1) params.set('page', currentPage.toString());
    if (testsPerPage !== 10) params.set('limit', testsPerPage.toString());
    
    setSearchParams(params);
  }, [searchTerm, filters, sortField, sortDirection, currentPage, testsPerPage, setSearchParams]);

  // Handle search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (currentPage !== 1) {
        setCurrentPage(1); // Reset to first page on search
      } else {
        loadTests();
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // ✅ REDESIGNED: Status badge component with better contrast and icons
  const getStatusBadge = (status) => {
    const statusConfig = {
      [TEST_STATUSES.COMPLETED]: { 
        bg: "bg-emerald-500/20", 
        text: "text-emerald-200", 
        border: "border-emerald-400/30", 
        icon: CheckCircle,
        label: "COMPLETED"
      },
      [TEST_STATUSES.PROCESSING]: { 
        bg: "bg-amber-500/20", 
        text: "text-amber-200", 
        border: "border-amber-400/30", 
        icon: Loader,
        label: "PROCESSING"
      },
      [TEST_STATUSES.PENDING]: { 
        bg: "bg-sky-500/20", 
        text: "text-sky-200", 
        border: "border-sky-400/30", 
        icon: Clock,
        label: "PENDING"
      },
      [TEST_STATUSES.FAILED]: { 
        bg: "bg-rose-500/20", 
        text: "text-rose-200", 
        border: "border-rose-400/30", 
        icon: XCircle,
        label: "FAILED"
      },
      [TEST_STATUSES.REVIEW]: { 
        bg: "bg-orange-500/20", 
        text: "text-orange-200", 
        border: "border-orange-400/30", 
        icon: AlertTriangle,
        label: "REVIEW"
      }
    };
    
    const config = statusConfig[status] || statusConfig[TEST_STATUSES.PENDING];
    const IconComponent = config.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border ${config.bg} ${config.text} ${config.border}`}>
        <IconComponent className={`h-3.5 w-3.5 ${status === TEST_STATUSES.PROCESSING ? 'animate-spin' : ''}`} />
        <span>{config.label}</span>
      </span>
    );
  };

  // ✅ REDESIGNED: Result badge with high contrast and proper icons
  const getResultBadge = (test) => {
    const testId = test.testId || test._id;
    const diagnosis = diagnosisData[testId];
    
    console.log(`🎯 Getting result for test ${testId}:`, { status: test.status, diagnosis });
    

    if (!diagnosis) {
      if (test.status === TEST_STATUSES.COMPLETED || test.status === 'completed') {
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/20 text-amber-200 border border-amber-400/30">
            <Activity className="h-3.5 w-3.5 animate-pulse" />
            <span>Loading...</span>
          </span>
        );
      }
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/20 text-slate-200 border border-slate-400/30">
          <Clock className="h-3.5 w-3.5" />
          <span>Pending Analysis</span>
        </span>
      );
    }

    
    let malariaResult = null;
    

    console.log(`🔍 Available diagnosis fields for ${testId}:`, diagnosis ? Object.keys(diagnosis) : 'none');
    
    // Your backend's DiagnosisResult model uses 'status: POS|NEG'
    if (diagnosis && typeof diagnosis.status === 'string') {
      malariaResult = diagnosis.status;
      console.log(`✅ Found status field:`, malariaResult);
    }
    // Check if diagnosis is nested further (double nesting)
    else if (diagnosis && diagnosis.result && typeof diagnosis.result.status === 'string') {
      malariaResult = diagnosis.result.status;
      console.log(`✅ Found nested result.status:`, malariaResult);
    }
    // Check API response nested structure  
    else if (diagnosis && diagnosis.apiResponse?.rawResponse?.status && typeof diagnosis.apiResponse.rawResponse.status === 'string') {
      malariaResult = diagnosis.apiResponse.rawResponse.status;
      console.log(`✅ Found API response status:`, malariaResult);
    }
    // Fallback to other possible fields
    else if (diagnosis && diagnosis.finalStatus && typeof diagnosis.finalStatus === 'string') {
      malariaResult = diagnosis.finalStatus;
      console.log(`✅ Found finalStatus field:`, malariaResult);
    }
    
    // Debug: Log what we're actually checking
    console.log(`🔍 Checking fields for ${testId}:`, {
      'diagnosis.status': diagnosis?.status,
      'diagnosis.result?.status': diagnosis?.result?.status,
      'diagnosis.finalStatus': diagnosis?.finalStatus,
      'diagnosis.apiResponse?.rawResponse?.status': diagnosis?.apiResponse?.rawResponse?.status
    });
    
    console.log(`🔍 Final malaria result for ${testId}:`, malariaResult);
    
    // ✅ REDESIGNED: Better visibility with high contrast colors
    if (malariaResult) {
      const resultStr = String(malariaResult).toUpperCase();
      
      // POSITIVE - High visibility red/pink with white text
      if (resultStr === 'POS' || resultStr === 'POSITIVE') {
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border-2 bg-rose-600/30 text-rose-100 border-rose-400/50 shadow-sm">
            <ShieldAlert className="h-4 w-4" />
            <span>POSITIVE</span>
          </span>
        );
      }
      
      // NEGATIVE - High visibility green with white text
      if (resultStr === 'NEG' || resultStr === 'NEGATIVE') {
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border-2 bg-emerald-600/30 text-emerald-100 border-emerald-400/50 shadow-sm">
            <ShieldCheck className="h-4 w-4" />
            <span>NEGATIVE</span>
          </span>
        );
      }
      
      // Unknown result
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border bg-amber-500/20 text-amber-200 border-amber-400/30">
          <Activity className="h-3.5 w-3.5" />
          <span>{resultStr}</span>
        </span>
      );
    }
    
    return (
      <span className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/20 text-slate-200 border border-slate-400/30">
        <Activity className="h-3.5 w-3.5 animate-pulse" />
        <span>Processing...</span>
      </span>
    );
  };

  // ✅ FIXED: Image count based on your API structure  
  const getImageCount = (test) => {
    const testId = test.testId || test._id;
    const diagnosis = diagnosisData[testId];
    
    console.log(`📷 Getting image count for test ${testId}:`, diagnosis);
    
    let imageCount = 0;
    
    if (diagnosis) {
      // ✅ BACKEND SPECIFIC: Your DiagnosisResult model uses these exact field names
      console.log(`🔍 Available diagnosis fields for ${testId}:`, Object.keys(diagnosis));
      console.log(`🔍 Checking image fields for ${testId}:`, {
        'totalImagesAttempted': diagnosis.totalImagesAttempted,
        'detections.length': diagnosis.detections?.length,
        'result.totalImagesAttempted': diagnosis.result?.totalImagesAttempted,
        'apiResponse.total_images_attempted': diagnosis.apiResponse?.rawResponse?.total_images_attempted
      });
      
      // Direct field from your DiagnosisResult model
      if (typeof diagnosis.totalImagesAttempted === 'number') {
        imageCount = diagnosis.totalImagesAttempted;
        console.log(`✅ Found totalImagesAttempted:`, imageCount);
      }
      // Check if diagnosis is nested further (double nesting)
      else if (diagnosis.result && typeof diagnosis.result.totalImagesAttempted === 'number') {
        imageCount = diagnosis.result.totalImagesAttempted;
        console.log(`✅ Found nested result.totalImagesAttempted:`, imageCount);
      }
      // Check detections array length (your model has this)
      else if (Array.isArray(diagnosis.detections) && diagnosis.detections.length > 0) {
        imageCount = diagnosis.detections.length;
        console.log(`✅ Found detections array length:`, imageCount);
      }
      // Check nested detections
      else if (diagnosis.result && Array.isArray(diagnosis.result.detections) && diagnosis.result.detections.length > 0) {
        imageCount = diagnosis.result.detections.length;
        console.log(`✅ Found nested detections array length:`, imageCount);
      }
      // Check nested API response
      else if (typeof diagnosis.apiResponse?.rawResponse?.total_images_attempted === 'number') {
        imageCount = diagnosis.apiResponse.rawResponse.total_images_attempted;
        console.log(`✅ Found API total_images_attempted:`, imageCount);
      }
      // Other possible fields
      else if (typeof diagnosis.imageCount === 'number') {
        imageCount = diagnosis.imageCount;
        console.log(`✅ Found imageCount:`, imageCount);
      }
      else if (Array.isArray(diagnosis.images) && diagnosis.images.length > 0) {
        imageCount = diagnosis.images.length;
        console.log(`✅ Found images array length:`, imageCount);
      }
    }
    
    // ✅ IMPROVED: Fallback to test data with multiple possible fields
    if (imageCount === 0) {
      imageCount = test.images?.length || 
                  test.imageCount || 
                  test.sampleImages?.length || 
                  test.uploadedImages?.length ||
                  test.files?.length ||
                  0;
      
      if (imageCount > 0) {
        console.log(`✅ Found image count from test data:`, imageCount);
      }
    }
    
    console.log(`📷 Final image count for ${testId}:`, imageCount);
    return imageCount;
  };

  // ✅ REDESIGNED: Priority badge with better visibility
  const getPriorityBadge = (priority) => {
    const priorityConfig = {
      [TEST_PRIORITIES.LOW]: {
        bg: "bg-slate-500/20",
        text: "text-slate-200",
        border: "border-slate-400/30",
        icon: null,
        label: "LOW"
      },
      [TEST_PRIORITIES.NORMAL]: {
        bg: "bg-blue-500/20",
        text: "text-blue-200",
        border: "border-blue-400/30",
        icon: null,
        label: "NORMAL"
      },
      [TEST_PRIORITIES.HIGH]: {
        bg: "bg-orange-500/20",
        text: "text-orange-200",
        border: "border-orange-400/30",
        icon: AlertTriangle,
        label: "HIGH"
      },
      [TEST_PRIORITIES.URGENT]: {
        bg: "bg-rose-600/30",
        text: "text-rose-100",
        border: "border-rose-400/50",
        icon: Zap,
        label: "URGENT"
      }
    };
    
    const config = priorityConfig[priority] || priorityConfig[TEST_PRIORITIES.NORMAL];
    const IconComponent = config.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border ${config.bg} ${config.text} ${config.border} ${priority === TEST_PRIORITIES.URGENT ? 'border-2 shadow-sm' : ''}`}>
        {IconComponent && <IconComponent className="h-3.5 w-3.5" />}
        <span>{config.label}</span>
      </span>
    );
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getSortIcon = (field) => {
    if (sortField !== field) return <ArrowUpDown className="h-4 w-4" />;
    return sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />;
  };

  const handleTestSelection = (testId) => {
    setSelectedTests(prev => 
      prev.includes(testId) 
        ? prev.filter(id => id !== testId)
        : [...prev, testId]
    );
  };

  const handleSelectAll = () => {
    if (selectedTests.length === tests.length) {
      setSelectedTests([]);
    } else {
      setSelectedTests(tests.map(test => test.testId || test._id));
    }
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    setDiagnosisData({}); 
    await loadTests();
    setIsRefreshing(false);
    dispatch(showInfoToast('Test records refreshed'));
  };

  const handleExportSelected = async () => {
    if (selectedTests.length === 0) {
      dispatch(showErrorToast('Please select tests to export'));
      return;
    }

    try {
      // TODO: Implement batch export
      dispatch(showInfoToast(`Exporting ${selectedTests.length} test(s)...`));
    } catch (error) {
      dispatch(showErrorToast('Export failed'));
    }
  };

  const clearAllFilters = () => {
    setFilters({
      status: 'all',
      result: 'all',
      priority: 'all',
      dateRange: '7days',
      technician: 'all'
    });
    setSearchTerm('');
    setCurrentPage(1);
  };

  if (error) {
    return (
      <AppLayout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Error Loading Test Records</h2>
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
      {/* Header */}
      <div className="bg-white/10 backdrop-blur-md border-b border-white/20 mb-6">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-blue-500 p-2 rounded-lg">
                <TestTube className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white">Test Records</h1>
                <p className="text-blue-200 text-sm">View test results and manage laboratory records</p>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleRefresh}
                disabled={isLoading || isRefreshing}
                className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors"
              >
                <RefreshCw className={`h-4 w-4 ${(isLoading || isRefreshing) ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={`flex items-center space-x-2 px-4 py-2 border border-white/20 rounded-lg transition-colors ${
                  showFilters ? 'bg-blue-500 text-white' : 'bg-white/10 hover:bg-white/20 text-white'
                }`}
              >
                <Filter className="h-4 w-4" />
                <span>Filters</span>
              </button>
              <button 
                onClick={handleExportSelected}
                disabled={selectedTests.length === 0}
                className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors disabled:opacity-50"
              >
                <Download className="h-4 w-4" />
                <span>Export</span>
              </button>
              {(user?.role === USER_ROLES.ADMIN || user?.role === USER_ROLES.SUPERVISOR) && (
                <button 
                  onClick={() => navigate('/upload')}
                  className="flex items-center space-x-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-white transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  <span>New Test</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-6">

        {/* Search and Filters */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
              <input
                type="text"
                placeholder="Search tests, patients, technicians..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            </div>

            {/* Results Summary */}
            <div className="flex items-center space-x-4 text-blue-200 text-sm">
              <span>
                Showing {tests.length} of {pagination.total} tests
              </span>
              {selectedTests.length > 0 && (
                <span className="text-blue-300">
                  {selectedTests.length} selected
                </span>
              )}
            </div>
          </div>

          {/* Expanded Filters */}
          {showFilters && (
            <div className="mt-6 pt-6 border-t border-white/20">
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Status</label>
                  <select
                    value={filters.status}
                    onChange={(e) => setFilters({...filters, status: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All</option>
                    <option value={TEST_STATUSES.PENDING}>Pending</option>
                    <option value={TEST_STATUSES.PROCESSING}>Processing</option>
                    <option value={TEST_STATUSES.COMPLETED}>Completed</option>
                    <option value={TEST_STATUSES.FAILED}>Failed</option>
                    <option value={TEST_STATUSES.REVIEW}>Review</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Result</label>
                  <select
                    value={filters.result}
                    onChange={(e) => setFilters({...filters, result: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All</option>
                    <option value="positive">Positive</option>
                    <option value="negative">Negative</option>
                    <option value="pending">Pending</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Priority</label>
                  <select
                    value={filters.priority}
                    onChange={(e) => setFilters({...filters, priority: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All</option>
                    <option value={TEST_PRIORITIES.LOW}>Low</option>
                    <option value={TEST_PRIORITIES.NORMAL}>Normal</option>
                    <option value={TEST_PRIORITIES.HIGH}>High</option>
                    <option value={TEST_PRIORITIES.URGENT}>Urgent</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Date Range</label>
                  <select
                    value={filters.dateRange}
                    onChange={(e) => setFilters({...filters, dateRange: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All Time</option>
                    <option value="7days">Last 7 Days</option>
                    <option value="30days">Last 30 Days</option>
                    <option value="90days">Last 90 Days</option>
                  </select>
                </div>

                <div className="flex items-end">
                  <button
                    onClick={clearAllFilters}
                    className="w-full px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors"
                  >
                    Clear Filters
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Test Records Table */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg overflow-hidden">
          {isLoading && !isRefreshing ? (
            <TableSkeletonLoader />
          ) : tests.length === 0 ? (
            <div className="text-center py-12">
              <TestTube className="w-16 h-16 text-blue-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No Test Records Found</h3>
              <p className="text-blue-200 mb-4">Try adjusting your search or filters</p>
              <button
                onClick={clearAllFilters}
                className="text-blue-400 hover:text-blue-300"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5 border-b border-white/20">
                  <tr>
                    <th className="px-6 py-3">
                      <input
                        type="checkbox"
                        checked={selectedTests.length === tests.length && tests.length > 0}
                        onChange={handleSelectAll}
                        className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500"
                      />
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('testId')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Test ID</span>
                        {getSortIcon('testId')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('patient.firstName')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Patient</span>
                        {getSortIcon('patient.firstName')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('status')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Status</span>
                        {getSortIcon('status')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      Malaria Result
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('priority')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Priority</span>
                        {getSortIcon('priority')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('technician.firstName')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Technician</span>
                        {getSortIcon('technician.firstName')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      <button
                        onClick={() => handleSort('createdAt')}
                        className="flex items-center space-x-1 hover:text-white transition-colors"
                      >
                        <span>Created</span>
                        {getSortIcon('createdAt')}
                      </button>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {tests.map((test) => (
                    <tr key={test.testId || test._id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <input
                          type="checkbox"
                          checked={selectedTests.includes(test.testId || test._id)}
                          onChange={() => handleTestSelection(test.testId || test._id)}
                          className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500"
                        />
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="font-medium text-white">{test.testId}</div>
                        <div className="flex items-center space-x-1 text-blue-300 text-xs mt-1">
                          <Image className="h-3 w-3" />
                          <span>{getImageCount(test)} images</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="font-medium text-white">
                          {getUserDisplayName(test.patient) !== 'N/A' 
                            ? getUserDisplayName(test.patient) 
                            : 'Unknown Patient'
                          }
                        </div>
                        <div className="text-blue-300 text-xs">{test.patient?.patientId || 'N/A'}</div>
                      </td>
                      <td className="px-6 py-4">
                        {getStatusBadge(test.status)}
                      </td>
                      <td className="px-6 py-4">
                        {getResultBadge(test)}
                      </td>
                      <td className="px-6 py-4">
                        {getPriorityBadge(test.priority)}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="text-white">{getUserDisplayName(test.technician)}</div>
                        {test.reviewedBy && (
                          <div className="text-blue-300 text-xs">
                            Reviewed by {getUserDisplayName(test.reviewedBy)}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-blue-200">
                        {formatDate(test.createdAt)}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <div className="flex items-center space-x-2">
                          <button 
                            onClick={() => navigate(`/results/${test.testId || test._id}`)}
                            className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                            title="View Clinical Results"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                          <button 
                            className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                            title="Download Test Record"
                          >
                            <FileText className="h-4 w-4" />
                          </button>
                          <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {pagination.pages > 1 && (
            <div className="bg-white/5 px-6 py-3 border-t border-white/20">
              <div className="flex items-center justify-between">
                <div className="text-sm text-blue-200">
                  Showing {((pagination.page - 1) * testsPerPage) + 1} to {Math.min(pagination.page * testsPerPage, pagination.total)} of {pagination.total} results
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                    className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  
                  <div className="flex items-center space-x-1">
                    {Array.from({ length: Math.min(5, pagination.pages) }, (_, i) => {
                      const page = i + 1;
                      return (
                        <button
                          key={page}
                          onClick={() => setCurrentPage(page)}
                          className={`px-3 py-1 rounded text-sm transition-colors ${
                            currentPage === page
                              ? 'bg-blue-500 text-white'
                              : 'text-blue-300 hover:text-white hover:bg-white/10'
                          }`}
                        >
                          {page}
                        </button>
                      );
                    })}
                  </div>

                  <button
                    onClick={() => setCurrentPage(Math.min(pagination.pages, currentPage + 1))}
                    disabled={currentPage === pagination.pages}
                    className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
};

export default TestRecordsPage;
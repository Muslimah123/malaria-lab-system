//src/pages/TestResultsList.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  ChevronDown,
  ChevronUp,
  Eye,
  Download,
  Calendar,
  User,
  TestTube,
  AlertCircle,
  CheckCircle,
  Clock,
  XCircle,
  RefreshCw,
  FileText,
  ChevronLeft,
  ChevronRight
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
import { showSuccessToast, showErrorToast } from '../store/slices/notificationsSlice';

// Components
import AppLayout from '../components/layout/AppLayout';
import LoadingSpinner, { TableSkeletonLoader } from '../components/common/LoadingSpinner';
import { useModal } from '../components/common/Modal';

// Utils
import { 
  TEST_STATUSES, 
  TEST_PRIORITIES, 
  SAMPLE_TYPES, 
  TEST_RESULTS,
  DATE_FORMATS 
} from '../utils/constants';

// Date formatting utility
const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

// Status badge component
const StatusBadge = ({ status }) => {
  const getStatusConfig = (status) => {
    switch (status) {
      case TEST_STATUSES.COMPLETED:
        return { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20' };
      case TEST_STATUSES.PROCESSING:
      case TEST_STATUSES.IN_PROGRESS:
        return { icon: Clock, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' };
      case TEST_STATUSES.PENDING:
        return { icon: Clock, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' };
      case TEST_STATUSES.FAILED:
      case TEST_STATUSES.ERROR:
        return { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' };
      case TEST_STATUSES.REVIEW:
        return { icon: AlertCircle, color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' };
      default:
        return { icon: Clock, color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20' };
    }
  };

  const config = getStatusConfig(status);
  const Icon = config.icon;

  return (
    <span className={`inline-flex items-center px-2 py-1 rounded-lg text-xs font-medium border ${config.bg} ${config.border} ${config.color}`}>
      <Icon className="w-3 h-3 mr-1" />
      {status?.replace('_', ' ').toUpperCase()}
    </span>
  );
};

// Priority badge component
const PriorityBadge = ({ priority }) => {
  const getPriorityConfig = (priority) => {
    switch (priority) {
      case TEST_PRIORITIES.URGENT:
        return { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' };
      case TEST_PRIORITIES.HIGH:
        return { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' };
      case TEST_PRIORITIES.NORMAL:
        return { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' };
      case TEST_PRIORITIES.LOW:
        return { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20' };
      default:
        return { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20' };
    }
  };

  const config = getPriorityConfig(priority);

  return (
    <span className={`inline-flex items-center px-2 py-1 rounded-lg text-xs font-medium border ${config.bg} ${config.border} ${config.color}`}>
      {priority?.toUpperCase()}
    </span>
  );
};

const TestResultsList = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  
  // Redux state
  const tests = useSelector(selectTests);
  const isLoading = useSelector(selectTestsLoading);
  const error = useSelector(selectTestsError);
  const pagination = useSelector(selectTestsPagination);

  // Local state
  const [searchTerm, setSearchTerm] = useState(searchParams.get('search') || '');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');
  const [priorityFilter, setPriorityFilter] = useState(searchParams.get('priority') || '');
  const [dateRange, setDateRange] = useState({
    from: searchParams.get('dateFrom') || '',
    to: searchParams.get('dateTo') || ''
  });
  const [sortField, setSortField] = useState(searchParams.get('sort') || 'createdAt');
  const [sortOrder, setSortOrder] = useState(searchParams.get('order') || 'desc');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedTests, setSelectedTests] = useState([]);

  // Pagination
  const currentPage = parseInt(searchParams.get('page')) || 1;
  const pageSize = parseInt(searchParams.get('limit')) || 20;

  // Load tests on mount and when filters change
  useEffect(() => {
    const params = {
      page: currentPage,
      limit: pageSize,
      sort: sortField,
      order: sortOrder
    };

    // Add filters if present
    if (searchTerm) params.search = searchTerm;
    if (statusFilter) params.status = statusFilter;
    if (priorityFilter) params.priority = priorityFilter;
    if (dateRange.from) params.dateFrom = dateRange.from;
    if (dateRange.to) params.dateTo = dateRange.to;

    dispatch(fetchTests(params));
  }, [dispatch, currentPage, pageSize, sortField, sortOrder, searchTerm, statusFilter, priorityFilter, dateRange]);

  // Update URL params when filters change
  const updateUrlParams = useCallback(() => {
    const params = new URLSearchParams();
    if (searchTerm) params.set('search', searchTerm);
    if (statusFilter) params.set('status', statusFilter);
    if (priorityFilter) params.set('priority', priorityFilter);
    if (dateRange.from) params.set('dateFrom', dateRange.from);
    if (dateRange.to) params.set('dateTo', dateRange.to);
    if (sortField !== 'createdAt') params.set('sort', sortField);
    if (sortOrder !== 'desc') params.set('order', sortOrder);
    if (currentPage !== 1) params.set('page', currentPage.toString());
    if (pageSize !== 20) params.set('limit', pageSize.toString());
    
    setSearchParams(params);
  }, [searchTerm, statusFilter, priorityFilter, dateRange, sortField, sortOrder, currentPage, pageSize, setSearchParams]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      updateUrlParams();
    }, 500);
    return () => clearTimeout(timer);
  }, [updateUrlParams]);

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  // Handle sorting
  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  // Handle row click
  const handleRowClick = (testId) => {
    navigate(`/results/${testId}`);
  };

  // Clear filters
  const clearFilters = () => {
    setSearchTerm('');
    setStatusFilter('');
    setPriorityFilter('');
    setDateRange({ from: '', to: '' });
    setSortField('createdAt');
    setSortOrder('desc');
    setSearchParams({});
  };

  // Refresh data
  const handleRefresh = () => {
    dispatch(fetchTests({
      page: currentPage,
      limit: pageSize,
      sort: sortField,
      order: sortOrder,
      search: searchTerm,
      status: statusFilter,
      priority: priorityFilter,
      dateFrom: dateRange.from,
      dateTo: dateRange.to
    }));
  };

  // Handle pagination
  const handlePageChange = (newPage) => {
    const params = new URLSearchParams(searchParams);
    params.set('page', newPage.toString());
    setSearchParams(params);
  };

  // Generate page numbers for pagination
  const getPageNumbers = () => {
    const totalPages = pagination.pages;
    const current = currentPage;
    const pages = [];
    
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      if (current <= 4) {
        for (let i = 1; i <= 5; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      } else if (current >= totalPages - 3) {
        pages.push(1);
        pages.push('...');
        for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i);
      } else {
        pages.push(1);
        pages.push('...');
        for (let i = current - 1; i <= current + 1; i++) pages.push(i);
        pages.push('...');
        pages.push(totalPages);
      }
    }
    
    return pages;
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) return null;
    return sortOrder === 'asc' ? 
      <ChevronUp className="w-4 h-4 ml-1" /> : 
      <ChevronDown className="w-4 h-4 ml-1" />;
  };

  if (error) {
    return (
      <AppLayout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Error Loading Results</h2>
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
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Test Results</h1>
            <p className="text-blue-200">View and manage all laboratory test results</p>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={handleRefresh}
              disabled={isLoading}
              className="bg-white/10 hover:bg-white/20 border border-white/30 text-white px-4 py-2 rounded-lg transition-colors flex items-center"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Search */}
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-5 w-5" />
                <input
                  type="text"
                  placeholder="Search by test ID, patient name, or technician..."
                  value={searchTerm}
                  onChange={handleSearch}
                  className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-3 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
                />
              </div>
            </div>

            {/* Filter Toggle */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="bg-white/10 hover:bg-white/20 border border-white/30 text-white px-4 py-3 rounded-lg transition-colors flex items-center"
            >
              <Filter className="w-4 h-4 mr-2" />
              Filters
              {showFilters ? <ChevronUp className="w-4 h-4 ml-2" /> : <ChevronDown className="w-4 h-4 ml-2" />}
            </button>
          </div>

          {/* Expanded Filters */}
          {showFilters && (
            <div className="mt-4 pt-4 border-t border-white/20">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Status Filter */}
                <div>
                  <label className="block text-sm font-medium text-blue-200 mb-2">Status</label>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="">All Statuses</option>
                    <option value={TEST_STATUSES.PENDING}>Pending</option>
                    <option value={TEST_STATUSES.PROCESSING}>Processing</option>
                    <option value={TEST_STATUSES.COMPLETED}>Completed</option>
                    <option value={TEST_STATUSES.REVIEW}>Review</option>
                    <option value={TEST_STATUSES.FAILED}>Failed</option>
                  </select>
                </div>

                {/* Priority Filter */}
                <div>
                  <label className="block text-sm font-medium text-blue-200 mb-2">Priority</label>
                  <select
                    value={priorityFilter}
                    onChange={(e) => setPriorityFilter(e.target.value)}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="">All Priorities</option>
                    <option value={TEST_PRIORITIES.URGENT}>Urgent</option>
                    <option value={TEST_PRIORITIES.HIGH}>High</option>
                    <option value={TEST_PRIORITIES.NORMAL}>Normal</option>
                    <option value={TEST_PRIORITIES.LOW}>Low</option>
                  </select>
                </div>

                {/* Date From */}
                <div>
                  <label className="block text-sm font-medium text-blue-200 mb-2">Date From</label>
                  <input
                    type="date"
                    value={dateRange.from}
                    onChange={(e) => setDateRange(prev => ({ ...prev, from: e.target.value }))}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  />
                </div>

                {/* Date To */}
                <div>
                  <label className="block text-sm font-medium text-blue-200 mb-2">Date To</label>
                  <input
                    type="date"
                    value={dateRange.to}
                    onChange={(e) => setDateRange(prev => ({ ...prev, to: e.target.value }))}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  />
                </div>
              </div>

              {/* Clear Filters */}
              <div className="mt-4 flex justify-end">
                <button
                  onClick={clearFilters}
                  className="text-blue-300 hover:text-white transition-colors flex items-center"
                >
                  <XCircle className="w-4 h-4 mr-1" />
                  Clear Filters
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Results Table */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg overflow-hidden">
          {/* Table Header */}
          <div className="px-6 py-4 border-b border-white/20">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium text-white">
                {pagination.total} Results Found
              </h3>
              {tests.length > 0 && (
                <div className="text-sm text-blue-200">
                  Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, pagination.total)} of {pagination.total}
                </div>
              )}
            </div>
          </div>

          {/* Table Content */}
          {isLoading ? (
            <div className="p-6">
              <TableSkeletonLoader rows={pageSize} columns={7} />
            </div>
          ) : tests.length === 0 ? (
            <div className="text-center py-12">
              <TestTube className="w-16 h-16 text-blue-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No Test Results Found</h3>
              <p className="text-blue-200">Try adjusting your search criteria or filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-white/5 border-b border-white/20">
                  <tr>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('testId')}
                    >
                      <div className="flex items-center">
                        Test ID
                        <SortIcon field="testId" />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('patient.name')}
                    >
                      <div className="flex items-center">
                        Patient
                        <SortIcon field="patient.name" />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('status')}
                    >
                      <div className="flex items-center">
                        Status
                        <SortIcon field="status" />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('priority')}
                    >
                      <div className="flex items-center">
                        Priority
                        <SortIcon field="priority" />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('createdAt')}
                    >
                      <div className="flex items-center">
                        Created
                        <SortIcon field="createdAt" />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider cursor-pointer hover:text-white transition-colors"
                      onClick={() => handleSort('completedAt')}
                    >
                      <div className="flex items-center">
                        Completed
                        <SortIcon field="completedAt" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-blue-200 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {tests.map((test) => (
                    <tr 
                      key={test.testId || test._id}
                      className="hover:bg-white/5 cursor-pointer transition-colors"
                      onClick={() => handleRowClick(test.testId || test._id)}
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-white">{test.testId}</div>
                        <div className="text-sm text-blue-300">{test.sampleType}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="bg-blue-500 w-8 h-8 rounded-full flex items-center justify-center mr-3">
                            <span className="text-white text-xs font-medium">
                              {test.patient?.firstName?.[0]}{test.patient?.lastName?.[0]}
                            </span>
                          </div>
                          <div>
                            <div className="text-sm font-medium text-white">
                              {test.patient?.firstName} {test.patient?.lastName}
                            </div>
                            <div className="text-sm text-blue-300">{test.patient?.patientId}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <StatusBadge status={test.status} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <PriorityBadge priority={test.priority} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-white">{formatDate(test.createdAt)}</div>
                        <div className="text-sm text-blue-300">by {test.technician?.name || 'N/A'}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-white">{formatDate(test.completedAt)}</div>
                        {test.diagnosisResult && (
                          <div className={`text-sm ${test.diagnosisResult === 'POSITIVE' ? 'text-red-300' : 'text-green-300'}`}>
                            {test.diagnosisResult}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRowClick(test.testId || test._id);
                            }}
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                            title="View Details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              // Handle download/export
                            }}
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                            title="Download Report"
                          >
                            <Download className="w-4 h-4" />
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
            <div className="px-6 py-4 border-t border-white/20">
              <div className="flex items-center justify-between">
                <div className="text-sm text-blue-200">
                  Page {currentPage} of {pagination.pages}
                </div>
                
                <nav className="flex items-center space-x-2">
                  {/* Previous */}
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      currentPage === 1 
                        ? 'text-gray-500 cursor-not-allowed' 
                        : 'text-blue-300 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>

                  {/* Page Numbers */}
                  {getPageNumbers().map((page, index) => (
                    <React.Fragment key={index}>
                      {page === '...' ? (
                        <span className="px-3 py-2 text-blue-300">...</span>
                      ) : (
                        <button
                          onClick={() => handlePageChange(page)}
                          className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                            currentPage === page
                              ? 'bg-blue-500 text-white'
                              : 'text-blue-300 hover:text-white hover:bg-white/10'
                          }`}
                        >
                          {page}
                        </button>
                      )}
                    </React.Fragment>
                  ))}

                  {/* Next */}
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === pagination.pages}
                    className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      currentPage === pagination.pages 
                        ? 'text-gray-500 cursor-not-allowed' 
                        : 'text-blue-300 hover:text-white hover:bg-white/10'
                    }`}
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </nav>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
};

export default TestResultsList;
import React, { useState } from 'react';
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
  Trash2
} from 'lucide-react';

const TestRecordsPage = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState('processedAt');
  const [sortDirection, setSortDirection] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState({
    status: 'all',
    result: 'all',
    priority: 'all',
    dateRange: '7days',
    technician: 'all'
  });
  const [selectedTests, setSelectedTests] = useState([]);
  const [showFilters, setShowFilters] = useState(false);

  const testsPerPage = 10;

  // Mock test data
  const allTests = [
    {
      id: 'TEST-20250711-045',
      patientId: 'PAT-20250711-012',
      patientName: 'John Doe',
      status: 'completed',
      result: 'positive',
      severity: 'moderate',
      parasiteType: 'PF',
      priority: 'normal',
      technician: 'Maria Garcia',
      processedAt: '2025-07-11T14:32:18Z',
      reviewedBy: 'Dr. Sarah Johnson',
      images: 3
    },
    {
      id: 'TEST-20250711-044',
      patientId: 'PAT-20250710-089',
      patientName: 'Alice Smith',
      status: 'processing',
      result: null,
      severity: null,
      parasiteType: null,
      priority: 'high',
      technician: 'James Wilson',
      processedAt: '2025-07-11T13:45:22Z',
      reviewedBy: null,
      images: 2
    },
    {
      id: 'TEST-20250711-043',
      patientId: 'PAT-20250711-009',
      patientName: 'Robert Brown',
      status: 'completed',
      result: 'negative',
      severity: 'negative',
      parasiteType: null,
      priority: 'normal',
      technician: 'Sarah Chen',
      processedAt: '2025-07-11T12:18:45Z',
      reviewedBy: 'Dr. Michael Lee',
      images: 4
    },
    {
      id: 'TEST-20250711-042',
      patientId: 'PAT-20250710-087',
      patientName: 'Emma Wilson',
      status: 'completed',
      result: 'positive',
      severity: 'severe',
      parasiteType: 'PF',
      priority: 'urgent',
      technician: 'Maria Garcia',
      processedAt: '2025-07-11T11:22:33Z',
      reviewedBy: 'Dr. Sarah Johnson',
      images: 5
    },
    {
      id: 'TEST-20250711-041',
      patientId: 'PAT-20250710-085',
      patientName: 'Michael Johnson',
      status: 'pending',
      result: null,
      severity: null,
      parasiteType: null,
      priority: 'normal',
      technician: 'James Wilson',
      processedAt: '2025-07-11T10:15:12Z',
      reviewedBy: null,
      images: 3
    },
    {
      id: 'TEST-20250710-040',
      patientId: 'PAT-20250710-083',
      patientName: 'Lisa Anderson',
      status: 'completed',
      result: 'positive',
      severity: 'mild',
      parasiteType: 'PV',
      priority: 'normal',
      technician: 'Sarah Chen',
      processedAt: '2025-07-10T16:45:28Z',
      reviewedBy: 'Dr. Michael Lee',
      images: 2
    },
    {
      id: 'TEST-20250710-039',
      patientId: 'PAT-20250710-082',
      patientName: 'David Taylor',
      status: 'failed',
      result: null,
      severity: null,
      parasiteType: null,
      priority: 'normal',
      technician: 'Maria Garcia',
      processedAt: '2025-07-10T15:30:14Z',
      reviewedBy: null,
      images: 1
    },
    {
      id: 'TEST-20250710-038',
      patientId: 'PAT-20250710-081',
      patientName: 'Jennifer White',
      status: 'completed',
      result: 'negative',
      severity: 'negative',
      parasiteType: null,
      priority: 'normal',
      technician: 'James Wilson',
      processedAt: '2025-07-10T14:12:56Z',
      reviewedBy: 'Dr. Sarah Johnson',
      images: 3
    }
  ];

  const getStatusBadge = (status) => {
    const statusStyles = {
      completed: { bg: "bg-green-100", text: "text-green-800", border: "border-green-200", icon: CheckCircle },
      processing: { bg: "bg-yellow-100", text: "text-yellow-800", border: "border-yellow-200", icon: Loader },
      pending: { bg: "bg-gray-100", text: "text-gray-800", border: "border-gray-200", icon: Clock },
      failed: { bg: "bg-red-100", text: "text-red-800", border: "border-red-200", icon: XCircle }
    };
    
    const style = statusStyles[status] || statusStyles.pending;
    const IconComponent = style.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium border ${style.bg} ${style.text} ${style.border}`}>
        <IconComponent className="h-3 w-3" />
        <span>{status}</span>
      </span>
    );
  };

  const getResultBadge = (result, severity, parasiteType) => {
    if (result === 'positive') {
      const severityStyles = {
        mild: "bg-yellow-100 text-yellow-800 border-yellow-200",
        moderate: "bg-orange-100 text-orange-800 border-orange-200",
        severe: "bg-red-100 text-red-800 border-red-200"
      };
      return (
        <span className={`px-2 py-1 rounded-full text-xs font-medium border ${severityStyles[severity]}`}>
          {result} ({parasiteType})
        </span>
      );
    } else if (result === 'negative') {
      return (
        <span className="px-2 py-1 rounded-full text-xs font-medium border bg-green-100 text-green-800 border-green-200">
          negative
        </span>
      );
    }
    return <span className="text-gray-400 text-xs">-</span>;
  };

  const getPriorityBadge = (priority) => {
    const priorityStyles = {
      low: "bg-blue-100 text-blue-800 border-blue-200",
      normal: "bg-gray-100 text-gray-800 border-gray-200", 
      high: "bg-orange-100 text-orange-800 border-orange-200",
      urgent: "bg-red-100 text-red-800 border-red-200"
    };
    return `px-2 py-1 rounded text-xs font-medium border ${priorityStyles[priority]}`;
  };

  const formatDate = (dateString) => {
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
      setSortDirection('asc');
    }
  };

  const getSortIcon = (field) => {
    if (sortField !== field) return <ArrowUpDown className="h-4 w-4" />;
    return sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />;
  };

  const filteredTests = allTests.filter(test => {
    // Search filter
    if (searchTerm) {
      const searchFields = [
        test.id,
        test.patientId,
        test.patientName,
        test.technician
      ].join(' ').toLowerCase();
      
      if (!searchFields.includes(searchTerm.toLowerCase())) {
        return false;
      }
    }

    // Status filter
    if (filters.status !== 'all' && test.status !== filters.status) {
      return false;
    }

    // Result filter
    if (filters.result !== 'all' && test.result !== filters.result) {
      return false;
    }

    // Priority filter
    if (filters.priority !== 'all' && test.priority !== filters.priority) {
      return false;
    }

    // Technician filter
    if (filters.technician !== 'all' && test.technician !== filters.technician) {
      return false;
    }

    return true;
  });

  const sortedTests = [...filteredTests].sort((a, b) => {
    let aValue = a[sortField];
    let bValue = b[sortField];

    if (sortField === 'processedAt') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    }

    if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.ceil(sortedTests.length / testsPerPage);
  const startIndex = (currentPage - 1) * testsPerPage;
  const paginatedTests = sortedTests.slice(startIndex, startIndex + testsPerPage);

  const handleTestSelection = (testId) => {
    setSelectedTests(prev => 
      prev.includes(testId) 
        ? prev.filter(id => id !== testId)
        : [...prev, testId]
    );
  };

  const handleSelectAll = () => {
    if (selectedTests.length === paginatedTests.length) {
      setSelectedTests([]);
    } else {
      setSelectedTests(paginatedTests.map(test => test.id));
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900">
      {/* Header */}
      <header className="bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between py-4">
            <div className="flex items-center space-x-4">
              <div className="bg-blue-500 p-2 rounded-lg">
                <TestTube className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white">Test Records</h1>
                <p className="text-blue-200 text-sm">Manage and review all laboratory tests</p>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={() => setShowFilters(!showFilters)}
                className={`flex items-center space-x-2 px-4 py-2 border border-white/20 rounded-lg transition-colors ${
                  showFilters ? 'bg-blue-500 text-white' : 'bg-white/10 hover:bg-white/20 text-white'
                }`}
              >
                <Filter className="h-4 w-4" />
                <span>Filters</span>
              </button>
              <button className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors">
                <Download className="h-4 w-4" />
                <span>Export</span>
              </button>
              <button className="flex items-center space-x-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-white transition-colors">
                <Plus className="h-4 w-4" />
                <span>New Test</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Search and Filters */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 mb-6">
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
                Showing {paginatedTests.length} of {filteredTests.length} tests
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
                    <option value="all">All Status</option>
                    <option value="completed">Completed</option>
                    <option value="processing">Processing</option>
                    <option value="pending">Pending</option>
                    <option value="failed">Failed</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Result</label>
                  <select
                    value={filters.result}
                    onChange={(e) => setFilters({...filters, result: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All Results</option>
                    <option value="positive">Positive</option>
                    <option value="negative">Negative</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Priority</label>
                  <select
                    value={filters.priority}
                    onChange={(e) => setFilters({...filters, priority: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All Priorities</option>
                    <option value="urgent">Urgent</option>
                    <option value="high">High</option>
                    <option value="normal">Normal</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Date Range</label>
                  <select
                    value={filters.dateRange}
                    onChange={(e) => setFilters({...filters, dateRange: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="7days">Last 7 days</option>
                    <option value="30days">Last 30 days</option>
                    <option value="90days">Last 90 days</option>
                    <option value="all">All time</option>
                  </select>
                </div>

                <div>
                  <label className="block text-blue-200 text-sm font-medium mb-2">Technician</label>
                  <select
                    value={filters.technician}
                    onChange={(e) => setFilters({...filters, technician: e.target.value})}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                  >
                    <option value="all">All Technicians</option>
                    <option value="Maria Garcia">Maria Garcia</option>
                    <option value="James Wilson">James Wilson</option>
                    <option value="Sarah Chen">Sarah Chen</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end mt-4">
                <button
                  onClick={() => setFilters({
                    status: 'all',
                    result: 'all',
                    priority: 'all',
                    dateRange: '7days',
                    technician: 'all'
                  })}
                  className="px-4 py-2 text-blue-300 hover:text-white text-sm"
                >
                  Clear Filters
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Selected Actions */}
        {selectedTests.length > 0 && (
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 mb-6">
            <div className="flex items-center justify-between">
              <span className="text-blue-200 text-sm">
                {selectedTests.length} test(s) selected
              </span>
              <div className="flex items-center space-x-2">
                <button className="flex items-center space-x-2 px-3 py-1 bg-white/10 hover:bg-white/20 border border-white/20 rounded text-white text-sm transition-colors">
                  <Download className="h-3 w-3" />
                  <span>Export Selected</span>
                </button>
                <button className="flex items-center space-x-2 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded text-red-300 text-sm transition-colors">
                  <Trash2 className="h-3 w-3" />
                  <span>Delete</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Tests Table */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5 border-b border-white/20">
                <tr>
                  <th className="px-6 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedTests.length === paginatedTests.length && paginatedTests.length > 0}
                      onChange={handleSelectAll}
                      className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500"
                    />
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('id')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Test ID</span>
                      {getSortIcon('id')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('patientName')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Patient</span>
                      {getSortIcon('patientName')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('status')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Status</span>
                      {getSortIcon('status')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Result
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('priority')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Priority</span>
                      {getSortIcon('priority')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('technician')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Technician</span>
                      {getSortIcon('technician')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    <button
                      onClick={() => handleSort('processedAt')}
                      className="flex items-center space-x-1 hover:text-white"
                    >
                      <span>Processed</span>
                      {getSortIcon('processedAt')}
                    </button>
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {paginatedTests.map((test) => (
                  <tr key={test.id} className="hover:bg-white/5 transition-colors">
                    <td className="px-6 py-4">
                      <input
                        type="checkbox"
                        checked={selectedTests.includes(test.id)}
                        onChange={() => handleTestSelection(test.id)}
                        className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500"
                      />
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <div className="font-medium text-white">{test.id}</div>
                      <div className="text-blue-300 text-xs">{test.images} images</div>
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <div className="font-medium text-white">{test.patientName}</div>
                      <div className="text-blue-300 text-xs">{test.patientId}</div>
                    </td>
                    <td className="px-6 py-4">
                      {getStatusBadge(test.status)}
                    </td>
                    <td className="px-6 py-4">
                      {getResultBadge(test.result, test.severity, test.parasiteType)}
                    </td>
                    <td className="px-6 py-4">
                      <span className={getPriorityBadge(test.priority)}>
                        {test.priority}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <div className="text-white">{test.technician}</div>
                      {test.reviewedBy && (
                        <div className="text-blue-300 text-xs">Reviewed by {test.reviewedBy}</div>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-blue-200">
                      {formatDate(test.processedAt)}
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <div className="flex items-center space-x-2">
                        <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                          <Eye className="h-4 w-4" />
                        </button>
                        <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
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

          {/* Pagination */}
          <div className="bg-white/5 px-6 py-3 border-t border-white/20">
            <div className="flex items-center justify-between">
              <div className="text-sm text-blue-200">
                Showing {startIndex + 1} to {Math.min(startIndex + testsPerPage, filteredTests.length)} of {filteredTests.length} results
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
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
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
                  onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                  className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Empty State */}
        {filteredTests.length === 0 && (
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-12 text-center">
            <TestTube className="h-12 w-12 text-blue-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No tests found</h3>
            <p className="text-blue-200 mb-6">
              {searchTerm || Object.values(filters).some(f => f !== 'all')
                ? 'Try adjusting your search or filter criteria.'
                : 'No tests have been processed yet.'}
            </p>
            <button className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors">
              Create New Test
            </button>
          </div>
        )}
      </main>
    </div>
  );
};

export default TestRecordsPage;
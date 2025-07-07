import React from 'react';
import { TestTube, User, Clock, AlertTriangle, CheckCircle, Eye } from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';

const TestSummary = ({ tests = [], loading = false, onViewAll, onTestClick }) => {
  // Sample data if none provided
  const sampleTests = [
    {
      testId: 'MT-2024-001',
      patient: { firstName: 'John', lastName: 'Doe', patientId: 'P12345' },
      status: 'completed',
      result: 'positive',
      createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      priority: 'urgent',
      sampleType: 'blood_smear'
    },
    {
      testId: 'MT-2024-002',
      patient: { firstName: 'Jane', lastName: 'Smith', patientId: 'P12346' },
      status: 'processing',
      result: null,
      createdAt: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
      priority: 'normal',
      sampleType: 'blood_smear'
    },
    {
      testId: 'MT-2024-003',
      patient: { firstName: 'Bob', lastName: 'Johnson', patientId: 'P12347' },
      status: 'completed',
      result: 'negative',
      createdAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      priority: 'normal',
      sampleType: 'blood_smear'
    }
  ];

  const displayTests = tests.length > 0 ? tests : sampleTests;

  const getStatusIcon = (status, result) => {
    switch (status) {
      case 'completed':
        return result === 'positive' ? 
          <AlertTriangle className="w-4 h-4 text-red-500" /> :
          <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'processing':
        return <LoadingSpinner size="sm" />;
      case 'pending':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      default:
        return <TestTube className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status, result, priority) => {
    if (status === 'completed') {
      return (
        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
          result === 'positive' 
            ? 'bg-red-100 text-red-800' 
            : 'bg-green-100 text-green-800'
        }`}>
          {result?.toUpperCase()}
        </span>
      );
    }
    
    let badgeColor = 'bg-gray-100 text-gray-800';
    if (status === 'processing') badgeColor = 'bg-blue-100 text-blue-800';
    if (status === 'pending') badgeColor = 'bg-yellow-100 text-yellow-800';
    
    return (
      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${badgeColor}`}>
        {status.toUpperCase()}
      </span>
    );
  };

  const getPriorityIndicator = (priority) => {
    if (priority === 'urgent') {
      return <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />;
    }
    if (priority === 'high') {
      return <div className="w-2 h-2 bg-orange-500 rounded-full" />;
    }
    return null;
  };

  const formatTimeAgo = (timestamp) => {
    const now = new Date();
    const testTime = new Date(timestamp);
    const diffInMinutes = Math.floor((now - testTime) / (1000 * 60));

    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return testTime.toLocaleDateString();
  };

  return (
    <div className="bg-white rounded-lg shadow-medical p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900">Recent Tests</h3>
        <button
          onClick={onViewAll}
          className="text-sm text-primary-600 hover:text-primary-700 font-medium flex items-center space-x-1"
        >
          <span>View All</span>
          <Eye className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center py-8">
          <LoadingSpinner size="md" />
        </div>
      ) : (
        <div className="space-y-4">
          {displayTests.length === 0 ? (
            <div className="text-center py-8">
              <TestTube className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No recent tests</p>
            </div>
          ) : (
            displayTests.slice(0, 5).map((test) => (
              <div
                key={test.testId}
                className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                onClick={() => onTestClick && onTestClick(test)}
              >
                <div className="flex items-center space-x-3">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(test.status, test.result)}
                    {getPriorityIndicator(test.priority)}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="font-medium text-gray-900">{test.testId}</span>
                      {getStatusBadge(test.status, test.result, test.priority)}
                    </div>
                    <p className="text-sm text-gray-600">
                      {test.patient.firstName} {test.patient.lastName} ({test.patient.patientId})
                    </p>
                    <p className="text-xs text-gray-500">
                      {formatTimeAgo(test.createdAt)} • {test.sampleType.replace('_', ' ')}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <Eye className="w-4 h-4 text-gray-400" />
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {displayTests.length > 5 && (
        <div className="mt-4 pt-4 border-t border-gray-200 text-center">
          <button
            onClick={onViewAll}
            className="text-sm text-primary-600 hover:text-primary-700 font-medium"
          >
            View {displayTests.length - 5} more tests
          </button>
        </div>
      )}
    </div>
  );
};

export default TestSummary;
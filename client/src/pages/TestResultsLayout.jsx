//src/components/pages/TestResultsLayout.jsx
import React, { useState } from 'react';
import { useParams } from 'react-router-dom'; // ✅ Import this
import Header from '../components/common/Header';
import Sidebar from '../components/common/Sidebar';
import TestResultsPage from './TestResultsPage';
import socketService from '../services/socketService';

const TestResultsLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const socketConnected = socketService.isConnected();

  const { testId } = useParams(); // ✅ Extract from route params

  const handleRefresh = () => {
    window.location.reload();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        onClose={() => setSidebarOpen(false)} 
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <Header
          title="Test Results"
          subtitle="View and analyze test results for malaria detection"
          onMenuClick={() => setSidebarOpen(true)}
          onRefresh={handleRefresh}
          socketConnected={socketConnected}
          showSearch={true}
          showNotifications={true}
        />

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          <TestResultsPage testId={testId} /> {/* ✅ Works now */}
        </main>
      </div>
    </div>
  );
};

export default TestResultsLayout;

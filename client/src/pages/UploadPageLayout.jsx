// src/pages/UploadPageLayout.jsx
// Simple version copying your exact dashboard structure
import React, { useState } from 'react';
import Header from '../components/common/Header';
import Sidebar from '../components/common/Sidebar';
import SampleUpload from './SampleUpload';
import socketService from '../services/socketService';

const UploadPageLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const socketConnected = socketService.isConnected();

  const handleRefresh = () => {
    window.location.reload();
  };

  return (
    <>
      {/* Use the exact same structure as your dashboard */}
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
            title="Upload Blood Samples"
            subtitle="Upload and analyze blood smear images for malaria detection"
            onMenuClick={() => setSidebarOpen(true)}
            onRefresh={handleRefresh}
            socketConnected={socketConnected}
            showSearch={true}
            showNotifications={true}
          />

          {/* Page Content */}
          <main className="flex-1 overflow-y-auto p-6">
            <SampleUpload />
          </main>
        </div>
      </div>
    </>
  );
};

export default UploadPageLayout;
// 📁 src/components/debug/SocketDebugger.jsx - TEMPORARY DEBUG COMPONENT
import React, { useState, useEffect } from 'react';
import socketService from '../../services/socketService';
import { useSelector, useDispatch } from 'react-redux';
import { selectUploadProgress } from '../../store/slices/uploadsSlice';

const SocketDebugger = ({ sessionId }) => {
  const [logs, setLogs] = useState([]);
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState('disconnected');
  const uploadProgress = useSelector(selectUploadProgress);
  const dispatch = useDispatch();

  const addLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev.slice(-20), { timestamp, message, type }]);
    console.log(`[SocketDebug] ${timestamp}: ${message}`);
  };

  const addEvent = (eventName, data) => {
    const timestamp = new Date().toLocaleTimeString();
    setEvents(prev => [...prev.slice(-10), { timestamp, eventName, data }]);
    addLog(`Event: ${eventName}`, 'success');
  };

  useEffect(() => {
    // Monitor socket status
    const checkStatus = () => {
      const connected = socketService.isConnected();
      setStatus(connected ? 'connected' : 'disconnected');
    };

    checkStatus();
    const interval = setInterval(checkStatus, 2000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Monitor all upload events
    const eventNames = [
      'upload:processingProgress',
      'upload:processingCompleted',
      'upload:processingFailed',
      'upload:fileUploaded',
      'upload:sessionUpdated',
      'upload-session-joined',
      'upload-session-left'
    ];

    const handleEvent = (eventName) => (data) => {
      addEvent(eventName, data);
    };

    eventNames.forEach(eventName => {
      socketService.on(eventName, handleEvent(eventName));
    });

    return () => {
      eventNames.forEach(eventName => {
        socketService.off(eventName);
      });
    };
  }, []);

  const handleConnect = async () => {
    try {
      addLog('Manual connection attempt...', 'info');
      const token = localStorage.getItem('authToken');
      await socketService.connectWithRetry(token);
      addLog('Manual connection successful', 'success');
    } catch (error) {
      addLog(`Manual connection failed: ${error.message}`, 'error');
    }
  };

  const handleJoinSession = () => {
    if (sessionId && socketService.isConnected()) {
      addLog(`Joining session: ${sessionId}`, 'info');
      socketService.subscribeToUploadSession(sessionId);
    } else {
      addLog('Cannot join session - missing sessionId or not connected', 'error');
    }
  };

  const handleTestPing = () => {
    if (socketService.isConnected()) {
      socketService.emit('ping');
      addLog('Sent ping', 'info');
    } else {
      addLog('Cannot ping - not connected', 'error');
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'connected': return 'bg-green-100 text-green-800';
      case 'error': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 mb-4 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Socket Debug Panel</h3>
        <div className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor()}`}>
          {status}
        </div>
      </div>

      {/* Connection Info */}
      <div className="mb-4 p-3 bg-gray-50 rounded-lg">
        <h4 className="font-medium text-gray-900 mb-2">Connection Info</h4>
        <div className="text-sm text-gray-600 space-y-1">
          <div>Status: {status}</div>
          <div>Session ID: {sessionId || 'None'}</div>
          <div>Socket ID: {socketService.socket?.id || 'None'}</div>
          <div>Auth Token: {localStorage.getItem('authToken') ? 'Present' : 'Missing'}</div>
        </div>
      </div>

      {/* Redux Progress State */}
      <div className="mb-4 p-3 bg-blue-50 rounded-lg">
        <h4 className="font-medium text-gray-900 mb-2">Redux Progress State</h4>
        <pre className="text-xs text-gray-600 overflow-auto max-h-20">
          {JSON.stringify(uploadProgress, null, 2)}
        </pre>
      </div>

      {/* Control Buttons */}
      <div className="grid grid-cols-3 gap-2 mb-4">
        <button 
          onClick={handleConnect}
          className="bg-blue-500 text-white px-3 py-2 rounded text-sm hover:bg-blue-600 transition-colors"
        >
          Connect
        </button>
        <button 
          onClick={handleJoinSession}
          disabled={!sessionId}
          className="bg-green-500 text-white px-3 py-2 rounded text-sm hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Join Session
        </button>
        <button 
          onClick={handleTestPing}
          className="bg-purple-500 text-white px-3 py-2 rounded text-sm hover:bg-purple-600 transition-colors"
        >
          Test Ping
        </button>
      </div>

      {/* Logs and Events */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <h4 className="font-medium text-gray-900 mb-2">Connection Logs</h4>
          <div className="h-32 overflow-y-auto bg-gray-50 p-2 rounded text-xs space-y-1">
            {logs.map((log, i) => (
              <div key={i} className={`${
                log.type === 'error' ? 'text-red-600' : 
                log.type === 'success' ? 'text-green-600' : 
                log.type === 'warning' ? 'text-yellow-600' : 'text-gray-600'
              }`}>
                <span className="text-gray-400">{log.timestamp}</span> {log.message}
              </div>
            ))}
            {logs.length === 0 && (
              <div className="text-gray-400 italic">No logs yet...</div>
            )}
          </div>
        </div>

        <div>
          <h4 className="font-medium text-gray-900 mb-2">Events Received</h4>
          <div className="h-32 overflow-y-auto bg-gray-50 p-2 rounded text-xs space-y-1">
            {events.map((event, i) => (
              <div key={i}>
                <div className="text-blue-600 font-medium">
                  <span className="text-gray-400">{event.timestamp}</span> {event.eventName}
                </div>
                {event.data && (
                  <div className="text-gray-500 ml-2 truncate">
                    {JSON.stringify(event.data).slice(0, 60)}...
                  </div>
                )}
              </div>
            ))}
            {events.length === 0 && (
              <div className="text-gray-400 italic">No events yet...</div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-3 text-xs text-gray-500 text-center">
        🔧 Debug panel - Remove in production
      </div>
    </div>
  );
};

export default SocketDebugger;
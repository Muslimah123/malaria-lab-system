// export default TestResultsPage;
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Download, 
  Printer, 
  ArrowLeft,
  User,
  TestTube,
  Calendar,
  Clock,
  FileText,
  AlertTriangle,
  RefreshCw,
  XCircle,
  Activity,
  Target,
  Shield
} from 'lucide-react';

// Components
import DiagnosisCard from '../components/results/DiagnosisCard';
import ImageAnnotation from '../components/results/ImageAnnotation';
import SeverityBadge from '../components/results/SeverityBadge';

import { PageLoader } from '../components/common/LoadingSpinner';

// Services and utilities
import diagnosisService from '../services/diagnosisService';

const TestResultsPage = () => {
  // Extract testId from URL params using React Router
  const { testId } = useParams();
  const navigate = useNavigate();
  
  // State management
  const [testResult, setTestResult] = useState(null);
  const [images, setImages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [dataFound, setDataFound] = useState(true);

  // Fetch test result data on component mount
  useEffect(() => {
    const fetchTestData = async () => {
      if (!testId) {
        setError('Test ID is required');
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setError(null);

        // Fetch diagnosis result
        console.log('Fetching diagnosis for testId:', testId);
        const diagnosisResponse = await diagnosisService.getByTestId(testId);
        
        console.log('Diagnosis response:', diagnosisResponse);
        
        if (!diagnosisResponse.success || !diagnosisResponse.data?.result) {
          setDataFound(false);
          setLoading(false);
          return;
        }

        const result = diagnosisResponse.data.result;
        
  
        if (result.mostProbableParasite?.confidence !== undefined) {
  // Use mostProbableParasite confidence as the primary confidence
  result.confidence = result.mostProbableParasite.confidence > 1 
    ? result.mostProbableParasite.confidence 
    : result.mostProbableParasite.confidence * 100;
} else if (result.confidence !== undefined && result.confidence <= 1) {
  // Fallback to regular confidence if no parasite confidence
  result.confidence = result.confidence * 100;
}
        
        // Ensure mostProbableParasite confidence is also normalized
        if (result.mostProbableParasite?.confidence !== undefined && result.mostProbableParasite.confidence <= 1) {
          result.mostProbableParasite.confidence = result.mostProbableParasite.confidence * 100;
        }
        
        setTestResult(result);

        // Fetch images with annotations
        try {
          console.log('Fetching images for testId:', testId);
          const imagesResponse = await diagnosisService.getImages(testId);
          console.log('Images response:', imagesResponse);
          
          if (imagesResponse.success && imagesResponse.data?.images) {
            console.log('First image annotations:', imagesResponse.data.images[0]?.annotations);
            console.log('First image data:', imagesResponse.data.images[0]);
            console.log('Images array length:', imagesResponse.data.images.length);
            setImages(imagesResponse.data.images);
          }
        } catch (imageError) {
          console.warn('Failed to fetch images:', imageError);
          // Images are optional, don't fail the whole page
          setImages([]);
        }

      } catch (err) {
        console.error('Failed to fetch test result:', err);
        setError(err.message || 'Failed to load test result');
      } finally {
        setLoading(false);
      }
    };

    fetchTestData();
  }, [testId]);

  // Export PDF report
  const handleExportPDF = async () => {
    try {
      setExporting(true);
      const pdfBlob = await diagnosisService.exportReport(testId, 'pdf');
      
      // Create download link
      const url = window.URL.createObjectURL(pdfBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `malaria-test-${testId}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      console.log('Report exported successfully');
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export report. Please try again.');
    } finally {
      setExporting(false);
    }
  };

  // Handle print
  const handlePrint = () => {
    window.print();
  };

  // Handle refresh
  const handleRefresh = () => {
    window.location.reload();
  };

  // Navigation handlers
  const handleBackToResults = () => {
    navigate('/results');
  };

  // Helper functions
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };


  // Loading state
  if (loading) {
    return <PageLoader text="Loading test results..." />;
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center">
        <div className="text-center bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-8 max-w-md">
          <XCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Error Loading Results</h2>
          <p className="text-blue-200 mb-6">{error}</p>
          <div className="flex space-x-4 justify-center">
            <button
              onClick={handleBackToResults}
              className="px-4 py-2 bg-white text-blue-600 rounded-lg hover:bg-blue-50 transition-colors"
            >
              Back to Results
            </button>
            <button
              onClick={handleRefresh}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/30 text-white rounded-lg transition-colors flex items-center"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  // No data state - Results not available
  if (!dataFound || !testResult) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center">
        <div className="text-center bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-8 max-w-md">
          <div className="relative">
            <TestTube className="w-16 h-16 text-blue-400 mx-auto mb-4" />
            <Activity className="w-6 h-6 text-yellow-400 absolute -bottom-1 -right-1 animate-pulse" />
          </div>
          <h2 className="text-xl font-semibold text-white mb-2">Results Not Available</h2>
          <p className="text-blue-200 mb-2">
            Test result for ID <span className="font-mono bg-white/10 px-2 py-1 rounded">{testId}</span> is not ready yet.
          </p>
          <p className="text-blue-300 text-sm mb-6">
            Results typically become available within 10-15 minutes after sample upload.
          </p>
          <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-4 mb-6">
            <div className="flex items-start">
              <AlertTriangle className="w-5 h-5 text-blue-400 mr-3 mt-0.5 flex-shrink-0" />
              <div className="text-left">
                <p className="text-blue-100 text-sm mb-2">Possible reasons:</p>
                <ul className="text-blue-200 text-sm space-y-1">
                  <li>• Analysis is still in progress</li>
                  <li>• Test has not been processed yet</li>
                  <li>• Sample images are being analyzed</li>
                </ul>
              </div>
            </div>
          </div>
          <div className="flex space-x-4 justify-center">
            <button
              onClick={handleBackToResults}
              className="px-4 py-2 bg-white text-blue-600 rounded-lg hover:bg-blue-50 transition-colors"
            >
              Back to Results
            </button>
            <button
              onClick={handleRefresh}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/30 text-white rounded-lg transition-colors flex items-center"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Check Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Extract data from API response
  const patient = testResult.test?.patient;
  const technician = testResult.test?.technician;
  
  // Debug: Log the actual status value
  console.log('🔍 TestResult status:', testResult.status);
  console.log('🔍 TestResult data:', testResult);
  
  // Check if parasites are actually detected and override status if needed
  const actualParasiteCount = testResult.totalParasites || images.reduce((sum, img) => sum + (img.annotations?.parasites?.length || 0), 0) || 0;
  console.log('🔍 Actual parasite count:', actualParasiteCount);
  
  // If parasites are detected but status is negative, there's a backend logic error
  const hasBackendError = actualParasiteCount > 0 && (testResult.status === 'NEG' || testResult.status === 'NEGATIVE');
  if (hasBackendError) {
    console.warn('⚠️ Backend logic error: Parasites detected but status is negative');
  }
  
  const isPositive = testResult.status === 'POS' || testResult.status === 'POSITIVE' || actualParasiteCount > 0;
  const parasiteType = testResult.mostProbableParasite?.type;
  const severity = testResult.severity?.level;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900">
      {/* Action Bar */}
      <div className="bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex justify-between items-center">
            <button 
              onClick={handleBackToResults}
              className="flex items-center px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/30 text-white rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Results
            </button>
            
            <div className="flex space-x-3">
              <button 
                onClick={handleExportPDF}
                disabled={exporting}
                className="flex items-center px-4 py-2 bg-white text-blue-600 rounded-lg hover:bg-blue-50 transition-all hover:scale-105 font-medium disabled:opacity-50"
              >
                <Download className="w-4 h-4 mr-2" />
                {exporting ? 'Exporting...' : 'Export PDF'}
              </button>
              <button 
                onClick={handlePrint}
                className="flex items-center px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/30 text-white rounded-lg transition-colors"
              >
                <Printer className="w-4 h-4 mr-2" />
                Print
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column - Patient & Test Info */}
          <div className="lg:col-span-1 space-y-6">
            
                         {/* Diagnosis Card Component */}
             <DiagnosisCard result={testResult} images={images} />
             
             {/* Backend Logic Error Warning */}
             {hasBackendError && (
               <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-xl p-4">
                 <div className="flex items-start">
                   <AlertTriangle className="w-5 h-5 text-yellow-400 mr-3 mt-0.5 flex-shrink-0" />
                   <div>
                     <p className="text-yellow-100 font-medium">Backend Logic Error Detected</p>
                     <p className="text-yellow-200 text-sm mt-1">
                       The system detected {actualParasiteCount} parasites but the backend marked this as negative. 
                       This indicates a potential issue with the backend analysis logic.
                     </p>
                   </div>
                 </div>
               </div>
             )}

            {/* Patient Information */}
            {patient && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <User className="w-5 h-5 mr-2 text-blue-400" />
                  Patient Information
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-blue-200">Name:</span>
                    <span className="font-medium text-white">
                      {patient.firstName} {patient.lastName}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-blue-200">Patient ID:</span>
                    <span className="font-mono text-sm text-white bg-white/10 px-2 py-1 rounded">
                      {patient.patientId}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-blue-200">Age:</span>
                    <span className="text-white">{patient.age} years</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-blue-200">Gender:</span>
                    <span className="text-white capitalize">{patient.gender}</span>
                  </div>
                  {patient.phoneNumber && (
                    <div className="flex justify-between">
                      <span className="text-blue-200">Phone:</span>
                      <span className="text-white">{patient.phoneNumber}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Test Information */}
            <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                <TestTube className="w-5 h-5 mr-2 text-blue-400" />
                Test Information
              </h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-blue-200">Date & Time:</span>
                  <span className="text-white flex items-center text-sm">
                    <Calendar className="w-3 h-3 mr-1 text-blue-400" />
                    {formatDate(testResult.createdAt)}
                  </span>
                </div>
                {technician && (
                  <div className="flex justify-between">
                    <span className="text-blue-200">Technician:</span>
                    <span className="text-white">
                      {technician.firstName} {technician.lastName}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-blue-200">Priority:</span>
                  <span className="text-white capitalize">
                    {testResult.test?.priority || 'Normal'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-blue-200">Sample Type:</span>
                  <span className="text-white">Blood Smear</span>
                </div>
                {testResult.apiResponse?.processingTime && (
                  <div className="flex justify-between">
                    <span className="text-blue-200">Processing Time:</span>
                    <span className="text-white flex items-center">
                      <Clock className="w-3 h-3 mr-1 text-blue-400" />
                      {testResult.apiResponse.processingTime}s
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* AI Analysis Quality */}
            {testResult.analysisQuality && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Shield className="w-5 h-5 mr-2 text-blue-400" />
                  Analysis Quality
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-blue-200">Quality Score:</span>
                    <div className="flex items-center">
                      <div className="w-32 bg-white/20 rounded-full h-2 mr-3">
                        <div 
                          className="bg-green-400 h-2 rounded-full transition-all duration-500"
                          style={{ width: `${testResult.analysisQuality.overallScore || 0}%` }}
                        />
                      </div>
                      <span className="text-white font-medium">
                        {testResult.analysisQuality.overallScore || 0}%
                      </span>
                    </div>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-blue-200">Confidence Level:</span>
                    <span className={`text-sm font-medium ${
                      testResult.analysisQuality.confidenceLevel === 'high' 
                        ? 'text-green-300' 
                        : testResult.analysisQuality.confidenceLevel === 'medium'
                        ? 'text-yellow-300'
                        : 'text-red-300'
                    }`}>
                      {testResult.analysisQuality.confidenceLevel?.toUpperCase() || 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* Right Column - Analysis Results */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* ✅ ENHANCED: Image Analysis Component */}
            <ImageAnnotation 
              images={images} 
              resultId={testResult._id}
              testId={testId}
            />

            {/* Detection Features Information */}
            <div className="bg-gradient-to-br from-blue-500/10 via-blue-500/5 to-transparent border border-blue-500/30 rounded-xl shadow-xl p-6 backdrop-blur-sm">
              <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
                <div className="p-3 bg-gradient-to-br from-blue-500/20 to-blue-600/30 rounded-xl border border-blue-500/40 backdrop-blur-sm mr-4">
                  <Target className="w-6 h-6 text-blue-400" />
                </div>
                Detection Features
              </h3>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex items-center space-x-2 text-green-300">
                  <div className="w-2 h-2 bg-green-400 rounded-full" />
                  <span>Parasite Detection</span>
                </div>
                <div className="flex items-center space-x-2 text-blue-300">
                  <div className="w-2 h-2 bg-blue-400 rounded-full" />
                  <span>WBC Detection</span>
                </div>
                <div className="flex items-center space-x-2 text-purple-300">
                  <div className="w-2 h-2 bg-purple-400 rounded-full" />
                  <span>Bounding Boxes</span>
                </div>
                <div className="flex items-center space-x-2 text-yellow-300">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                  <span>Confidence Scoring</span>
                </div>
              </div>
            </div>



            {/* Medical Recommendations */}
            {isPositive && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2 text-yellow-400" />
                  Medical Recommendations
                </h3>
                <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-4">
                  <div className="flex items-start">
                    <AlertTriangle className="w-5 h-5 text-yellow-400 mr-3 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-yellow-100 font-medium mb-2">
                        Immediate treatment required for malaria infection.
                      </p>
                      <p className="text-yellow-200 text-sm">
                        Please consult with a healthcare provider immediately for proper treatment protocol.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Manual Review Notes */}
            {testResult.manualReview?.isReviewed && testResult.manualReview.reviewNotes && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <FileText className="w-5 h-5 mr-2 text-purple-400" />
                  Review Notes
                </h3>
                <div className="bg-purple-500/20 border border-purple-500/30 rounded-lg p-4">
                  <p className="text-purple-100">{testResult.manualReview.reviewNotes}</p>
                  {testResult.manualReview.overriddenStatus && (
                    <div className="mt-3 flex items-center space-x-2">
                      <span className="text-purple-200 text-sm">Final Status: </span>
                      <SeverityBadge severity={testResult.manualReview.overriddenStatus} size="sm" />
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Technical Information */}
            <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
                <FileText className="w-5 h-5 mr-2 text-blue-400" />
                Technical Information
              </h3>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-blue-200">Analysis Method:</span>
                  <span className="text-white ml-2">AI-Powered Microscopy</span>
                </div>
                <div>
                  <span className="text-blue-200">Images Processed:</span>
                  <span className="text-white ml-2">{images.length || 0}</span>
                </div>
                <div>
                  <span className="text-blue-200">Quality Score:</span>
                  <span className="text-green-300 ml-2">
                    {testResult.analysisQuality?.overallScore ? 
                      `${testResult.analysisQuality.overallScore.toFixed(0)}%` : 
                      'Excellent'
                    }
                  </span>
                </div>
                <div>
                  <span className="text-blue-200">Reviewed By:</span>
                  <span className="text-white ml-2">
                    {technician ? `${technician.firstName} ${technician.lastName}` : 'AI System'}
                  </span>
                </div>
                <div>
                  <span className="text-blue-200">Processing Mode:</span>
                  <span className="text-blue-300 ml-2 font-medium">Basic Detection</span>
                </div>
                <div>
                  <span className="text-blue-200">Model Version:</span>
                  <span className="text-white ml-2 font-medium">V12.pt</span>
                </div>
                <div>
                  <span className="text-blue-200">Confidence Threshold:</span>
                  <span className="text-white ml-2 font-medium">26%</span>
                </div>
                <div>
                  <span className="text-blue-200">API Version:</span>
                  <span className="text-white ml-2 font-medium">1.0.0</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    </div>
  );
};

export default TestResultsPage;
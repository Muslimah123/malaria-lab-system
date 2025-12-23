
// src/components/results/DiagnosisCard.jsx
import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, Target, Activity, TrendingUp, Brain } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const DiagnosisCard = ({ result, images = [] }) => {
  if (!result) return null;

  // Debug: Log the result data
  console.log('🔍 DiagnosisCard result:', result);
  console.log('🔍 DiagnosisCard result.status:', result.status);
  console.log('🔍 DiagnosisCard images:', images);

  // Fix: Check for both POS and POSITIVE status values, and also check actual parasite count
  const actualParasiteCount = result.totalParasites || images.reduce((sum, img) => sum + (img.annotations?.parasites?.length || 0), 0) || 0;
  const actualWbcCount = result.totalWBC || images.reduce((sum, img) => sum + (img.annotations?.wbcs?.length || 0), 0) || 0;
  const isPositive = result.status === 'POS' || result.status === 'POSITIVE' || actualParasiteCount > 0;
  let confidence = result.mostProbableParasite?.confidence || result.confidence || 0;
  confidence = confidence <= 1 ? confidence * 100 : confidence;

  const parasiteType = result.mostProbableParasite?.type;
  const severity = result.severity?.level;
  const parasiteConfidence = result.mostProbableParasite?.confidence || 0;

  const getStatusColor = (status) => {
    switch (status?.toUpperCase()) {
      case 'POS': 
      case 'POSITIVE':
        return 'text-rose-200 bg-rose-500/20 border-rose-500/30';
      case 'NEG':
      case 'NEGATIVE':
        return 'text-green-300 bg-green-500/20 border-green-500/30';
      default: 
        return 'text-blue-300 bg-blue-500/20 border-blue-500/30';
    }
  };

  const getParasiteFullName = (type) => {
    const names = {
      'PF': 'Plasmodium Falciparum',
      'PM': 'Plasmodium Malariae', 
      'PO': 'Plasmodium Ovale',
      'PV': 'Plasmodium Vivax'
    };
    return names[type] || type;
  };

  const getParasiteInfo = (type) => {
    const info = {
      'PF': {
        severity: 'Most severe form',
        color: 'text-rose-300'
      },
      'PM': {
        severity: 'Moderate severity',
        color: 'text-rose-400'
      },
      'PO': {
        severity: 'Mild to moderate',
        color: 'text-yellow-400'
      },
      'PV': {
        severity: 'Mild to moderate'
      }
    };
    return info[type] || { severity: 'Unknown', description: '', color: 'text-gray-400' };
  };

  return (
    <div className="space-y-6">
      {/* Enhanced Test Status Card */}
      <div className="relative bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl shadow-2xl p-8 overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5" />
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-white/10 to-transparent rounded-full blur-2xl" />
        <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-blue-500/10 to-transparent rounded-full blur-xl" />
        
        <div className="relative text-center">
          {/* Enhanced Status Icon */}
          <div className="relative mx-auto mb-6">
            <div className={`w-20 h-20 rounded-full flex items-center justify-center mx-auto border-2 backdrop-blur-md transition-all duration-500 hover:scale-110 ${
              isPositive 
                ? 'bg-gradient-to-br from-rose-500/20 to-rose-600/30 border-rose-400/50' 
                : 'bg-gradient-to-br from-green-500/20 to-green-600/30 border-green-400/50'
            }`}>
              {isPositive ? (
                <XCircle className="w-10 h-10 text-rose-300 drop-shadow-lg" />
              ) : (
                <CheckCircle className="w-10 h-10 text-green-400 drop-shadow-lg" />
              )}
            </div>
            {/* Animated Ring */}
            {isPositive && (
              <div className="absolute inset-0 rounded-full border-2 border-rose-400/30 animate-ping" />
            )}
            {/* Pulse Indicator */}
            {isPositive && (
              <Activity className="w-6 h-6 text-rose-300 absolute -bottom-1 -right-1 animate-pulse drop-shadow-md" />
            )}
          </div>

          {/* Enhanced Status Badge */}
          <div className={`inline-flex items-center px-6 py-3 rounded-2xl text-xl font-bold border-2 backdrop-blur-md transition-all duration-300 hover:scale-105 ${getStatusColor(result.status)}`}>
            <div className={`w-3 h-3 rounded-full mr-3 animate-pulse ${isPositive ? 'bg-rose-400' : 'bg-green-400'}`} />
            {isPositive ? 'POSITIVE' : 'NEGATIVE'}
          </div>

          {/* Enhanced Confidence Display */}
          <div className="mt-6 space-y-4">
            <div className="flex items-center justify-center space-x-3">
              <Brain className="w-5 h-5 text-blue-400" />
              <p className="text-blue-200 font-medium text-lg">
                {confidence.toFixed(1)}% AI Confidence
              </p>
            </div>
            
            {/* Advanced Confidence Meter */}
            <div className="relative w-48 mx-auto">
              <div className="w-full bg-gradient-to-r from-white/10 to-white/20 rounded-full h-3 backdrop-blur-sm border border-white/20">
                <div 
                  className={`h-3 rounded-full transition-all duration-1000 ease-out relative overflow-hidden ${
                    confidence >= 90 ? 'bg-gradient-to-r from-green-400 to-green-500' : 
                    confidence >= 70 ? 'bg-gradient-to-r from-yellow-400 to-orange-500' : 
                    'bg-gradient-to-r from-rose-400 to-rose-500'
                  }`}
                  style={{ width: `${Math.min(100, confidence)}%` }}
                >
                  {/* Shimmer effect */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-pulse" />
                </div>
              </div>
              {/* Confidence Labels */}
              <div className="flex justify-between text-xs text-blue-300 mt-2">
                <span>Low</span>
                <span>Medium</span>
                <span>High</span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Enhanced Positive Detection Card */}
        {isPositive && parasiteType && (
          <div className="mt-8 relative bg-gradient-to-br from-rose-500/15 via-rose-500/10 to-rose-600/5 border border-rose-500/40 rounded-xl p-6 backdrop-blur-md">
            {/* Warning Pattern */}
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-bl from-rose-500/10 to-transparent rounded-full blur-xl" />
            
            <div className="relative">
              <div className="flex items-center mb-4">
                <div className="p-2 bg-rose-500/20 rounded-lg mr-3 border border-rose-500/30">
                  <AlertTriangle className="w-5 h-5 text-rose-300" />
                </div>
                <span className="font-semibold text-rose-200 text-lg">Malaria Detected</span>
              </div>
              
              <div className="space-y-4">
                <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg p-4">
                  <p className="text-rose-100 font-semibold text-lg mb-2">
                    {getParasiteFullName(parasiteType)}
                  </p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className={`text-sm font-medium ${getParasiteInfo(parasiteType).color}`}>
                        {getParasiteInfo(parasiteType).severity}
                      </span>
                      {parasiteConfidence > 0 && (
                        <div className="flex items-center space-x-1">
                          <div className="w-2 h-2 bg-rose-400 rounded-full animate-pulse" />
                          <span className="text-rose-200 text-sm font-medium">
                            {(parasiteConfidence <= 1 ? parasiteConfidence * 100 : parasiteConfidence).toFixed(0)}% match
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                {severity && (
                  <div className="pt-3 border-t border-rose-500/20">
                    <div className="flex items-center justify-between">
                      <span className="text-rose-200 text-sm font-medium">Infection Severity:</span>
                      <SeverityBadge severity={severity} size="sm" />
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Enhanced Result Display */}
        {!isPositive ? (
          // Negative Result
          <div className="mt-8 bg-gradient-to-br from-green-500/15 via-green-500/10 to-green-600/5 border border-green-500/40 rounded-xl p-6 backdrop-blur-md">
            <div className="flex items-center">
              <div className="p-2 bg-green-500/20 rounded-lg mr-3 border border-green-500/30">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <span className="font-semibold text-green-300 text-lg">No Malaria Detected</span>
                <p className="text-green-200 text-sm mt-1">
                  Analysis found no malaria parasites in the blood sample
                </p>
              </div>
            </div>
          </div>
        ) : (
          // Positive Result - Show actual detection info
          <div className="mt-8 bg-gradient-to-br from-rose-500/15 via-rose-500/10 to-rose-600/5 border border-rose-500/40 rounded-xl p-6 backdrop-blur-md">
            <div className="flex items-center">
              <div className="p-2 bg-rose-500/20 rounded-lg mr-3 border border-rose-500/30">
                <AlertTriangle className="w-5 h-5 text-rose-300" />
              </div>
              <div>
                <span className="font-semibold text-rose-200 text-lg">Malaria Detected</span>
                <p className="text-rose-100 text-sm mt-1">
                  Analysis found {result.totalParasites || 0} malaria parasites in the blood sample
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Enhanced Analysis Summary */}
      <div className="bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl shadow-2xl p-6 overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/3 via-purple-500/3 to-indigo-500/3" />
        
        <div className="relative">
          <h3 className="text-xl font-bold text-white mb-6 flex items-center">
            <div className="p-2 bg-blue-500/20 rounded-lg mr-3 border border-blue-500/30">
              <Target className="w-5 h-5 text-blue-400" />
            </div>
            Analysis Summary
          </h3>
          
          {/* Enhanced Metrics Grid */}
          <div className="grid grid-cols-2 gap-4">
            {/* Parasites Card */}
            <div className="group relative bg-gradient-to-br from-rose-500/10 via-rose-500/5 to-transparent border border-rose-500/20 rounded-xl p-4 hover:bg-rose-500/15 transition-all duration-300 hover:scale-105 hover:shadow-lg backdrop-blur-sm">
              <div className="flex items-center justify-between">
                <div>
                  <div className={`text-2xl font-bold transition-colors duration-300 ${isPositive ? 'text-rose-300 group-hover:text-rose-200' : 'text-green-400'}`}>
                    {actualParasiteCount}
                  </div>
                  <div className="text-xs text-rose-200 font-medium">Parasites</div>
                </div>
                {isPositive && actualParasiteCount > 0 && (
                  <TrendingUp className="w-5 h-5 text-rose-300 opacity-50 group-hover:opacity-100 transition-opacity" />
                )}
              </div>
            </div>

            {/* WBCs Card */}
            <div className="group relative bg-gradient-to-br from-blue-500/10 via-blue-500/5 to-transparent border border-blue-500/20 rounded-xl p-4 hover:bg-blue-500/15 transition-all duration-300 hover:scale-105 hover:shadow-lg backdrop-blur-sm">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-bold text-blue-400 group-hover:text-blue-300 transition-colors duration-300">
                    {actualWbcCount}
                  </div>
                  <div className="text-xs text-blue-200 font-medium">WBCs</div>
                </div>
                <Activity className="w-5 h-5 text-blue-400 opacity-50 group-hover:opacity-100 transition-opacity" />
              </div>
            </div>

            {/* Images Card */}
            <div className="group relative bg-gradient-to-br from-purple-500/10 via-purple-500/5 to-transparent border border-purple-500/20 rounded-xl p-4 hover:bg-purple-500/15 transition-all duration-300 hover:scale-105 hover:shadow-lg backdrop-blur-sm">
              <div className="text-2xl font-bold text-purple-400 group-hover:text-purple-300 transition-colors duration-300">
                {images.length || result.totalImagesAttempted || 0}
              </div>
              <div className="text-xs text-purple-200 font-medium">Images</div>
            </div>

            {/* Ratio Card */}
            <div className="group relative bg-gradient-to-br from-orange-500/10 via-orange-500/5 to-transparent border border-orange-500/20 rounded-xl p-4 hover:bg-orange-500/15 transition-all duration-300 hover:scale-105 hover:shadow-lg backdrop-blur-sm">
              <div className={`text-2xl font-bold transition-colors duration-300 ${
                result.parasiteWbcRatio >= 10 ? 'text-rose-300 group-hover:text-rose-200' :
                result.parasiteWbcRatio >= 5 ? 'text-rose-400 group-hover:text-rose-300' :
                result.parasiteWbcRatio >= 1 ? 'text-yellow-400 group-hover:text-yellow-300' :
                'text-green-400 group-hover:text-green-300'
              }`}>
                {(result.parasiteWbcRatio || 0).toFixed(1)}
              </div>
              <div className="text-xs text-orange-200 font-medium">P/WBC Ratio</div>
            </div>
          </div>
          
          {/* Enhanced Ratio Interpretation */}
          {result.parasiteWbcRatio > 0 && (
            <div className="mt-6 p-4 bg-gradient-to-r from-white/5 via-white/10 to-white/5 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-blue-200 font-medium">Parasite Density Assessment:</span>
                <span className={`text-sm font-bold px-3 py-1 rounded-full border backdrop-blur-sm ${
                  result.parasiteWbcRatio >= 10 ? 'text-rose-200 bg-rose-500/20 border-rose-500/30' :
                  result.parasiteWbcRatio >= 5 ? 'text-rose-300 bg-rose-500/20 border-rose-500/30' :
                  result.parasiteWbcRatio >= 1 ? 'text-yellow-300 bg-yellow-500/20 border-yellow-500/30' :
                  'text-green-300 bg-green-500/20 border-green-500/30'
                }`}>
                  {result.parasiteWbcRatio >= 10 ? 'High Density' :
                   result.parasiteWbcRatio >= 5 ? 'Moderate' :
                   result.parasiteWbcRatio >= 1 ? 'Low' :
                   'Very Low'}
                </span>
              </div>
              
              {/* Advanced Progress Bar */}
              <div className="relative w-full bg-gradient-to-r from-white/10 to-white/20 rounded-full h-2 backdrop-blur-sm border border-white/20">
                <div 
                  className={`h-2 rounded-full transition-all duration-1000 ease-out relative overflow-hidden ${
                    result.parasiteWbcRatio >= 10 ? 'bg-gradient-to-r from-rose-400 to-rose-600' :
                    result.parasiteWbcRatio >= 5 ? 'bg-gradient-to-r from-rose-400 to-rose-600' :
                    result.parasiteWbcRatio >= 1 ? 'bg-gradient-to-r from-yellow-400 to-yellow-600' :
                    'bg-gradient-to-r from-green-400 to-green-600'
                  }`}
                  style={{ width: `${Math.min(100, result.parasiteWbcRatio * 10)}%` }}
                >
                  {/* Animated shine effect */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent animate-pulse" />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DiagnosisCard;
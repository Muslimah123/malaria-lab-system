
// src/components/results/DiagnosisCard.jsx
import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, Target, Activity } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const DiagnosisCard = ({ result }) => {
  if (!result) return null;

  const isPositive = result.status === 'POS';
  // Ensure confidence is a percentage (0-100)
//   let confidence = result.confidence || 0;
//   if (confidence <= 1) {
//     confidence = confidence * 100;
//   }
let confidence = result.mostProbableParasite?.confidence || result.confidence || 0;
// Convert to percentage if needed (handles both 0.83 and 83 formats)
confidence = confidence <= 1 ? confidence * 100 : confidence;

  
  const parasiteType = result.mostProbableParasite?.type;
  const severity = result.severity?.level;
  const parasiteConfidence = result.mostProbableParasite?.confidence || 0;

  const getStatusColor = (status) => {
    switch (status?.toUpperCase()) {
      case 'POS': 
        return 'text-red-300 bg-red-500/20 border-red-500/30';
      case 'NEG':
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
        description: 'Can cause cerebral malaria and organ failure',
        color: 'text-red-400'
      },
      'PM': {
        severity: 'Moderate severity',
        description: 'Can cause chronic infection',
        color: 'text-orange-400'
      },
      'PO': {
        severity: 'Mild to moderate',
        description: 'Can remain dormant in liver',
        color: 'text-yellow-400'
      },
      'PV': {
        severity: 'Mild to moderate',
        description: 'Most widespread, can relapse',
        color: 'text-green-400'
      }
    };
    return info[type] || { severity: 'Unknown', description: '', color: 'text-gray-400' };
  };

  return (
    <div className="space-y-6">
      {/* Test Status Card */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-4 border border-white/30 relative">
            {isPositive ? (
              <>
                <XCircle className="w-8 h-8 text-red-400" />
                <Activity className="w-4 h-4 text-red-400 absolute -bottom-1 -right-1 animate-pulse" />
              </>
            ) : (
              <CheckCircle className="w-8 h-8 text-green-400" />
            )}
          </div>
          <div className={`inline-flex items-center px-4 py-2 rounded-full text-lg font-bold border ${getStatusColor(result.status)}`}>
            {isPositive ? 'POSITIVE' : 'NEGATIVE'}
          </div>
          <div className="mt-3 space-y-1">
            <p className="text-blue-200 font-medium">{confidence.toFixed(1)}% Confidence</p>
            {/* Confidence meter */}
            <div className="w-32 mx-auto bg-white/20 rounded-full h-2">
              <div 
                className={`h-2 rounded-full transition-all duration-500 ${
                  confidence >= 90 ? 'bg-green-400' : 
                  confidence >= 70 ? 'bg-yellow-400' : 
                  'bg-red-400'
                }`}
                // style={{ width: `${confidence}%` }}
                style={{ width: `${Math.min(100, confidence)}%` }}
              />
            </div>
          </div>
        </div>
        
        {isPositive && parasiteType && (
          <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-center mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400 mr-2" />
              <span className="font-medium text-red-300">Malaria Detected</span>
            </div>
            <div className="space-y-2">
              <p className="text-red-200 font-medium">
                {getParasiteFullName(parasiteType)}
              </p>
              <div className="flex items-center space-x-2">
                <span className={`text-sm ${getParasiteInfo(parasiteType).color}`}>
                  {getParasiteInfo(parasiteType).severity}
                </span>
                {parasiteConfidence > 0 && (
                  <span className="text-red-300 text-sm">
                    • {(parasiteConfidence <= 1 ? parasiteConfidence * 100 : parasiteConfidence).toFixed(0)}% match
                  </span>
                )}
              </div>
              <p className="text-red-200/80 text-xs">
                {getParasiteInfo(parasiteType).description}
              </p>
              {severity && (
                <div className="mt-3 pt-3 border-t border-red-500/20">
                  <span className="text-red-300 text-sm">Infection Severity: </span>
                  <SeverityBadge severity={severity} size="sm" />
                </div>
              )}
            </div>
          </div>
        )}

        {!isPositive && (
          <div className="bg-green-500/20 border border-green-500/30 rounded-lg p-4">
            <div className="flex items-center">
              <CheckCircle className="w-5 h-5 text-green-400 mr-2" />
              <span className="font-medium text-green-300">No Malaria Detected</span>
            </div>
            <p className="text-green-200 text-sm mt-1">
              Analysis found no malaria parasites in the blood sample
            </p>
          </div>
        )}
      </div>

      {/* Quick Metrics */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Target className="w-5 h-5 mr-2 text-blue-400" />
          Analysis Summary
        </h3>
        <div className="grid grid-cols-2 gap-4">
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20 hover:bg-white/20 transition-colors">
            <div className={`text-2xl font-bold ${isPositive ? 'text-red-400' : 'text-green-400'}`}>
              {result.totalParasitesDetected || 0}
            </div>
            <div className="text-xs text-blue-200">Parasites</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20 hover:bg-white/20 transition-colors">
            <div className="text-2xl font-bold text-blue-400">
              {result.totalWbcDetected || 0}
            </div>
            <div className="text-xs text-blue-200">WBCs</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20 hover:bg-white/20 transition-colors">
            <div className="text-2xl font-bold text-purple-400">
              {result.totalImagesAnalyzed || 0}
            </div>
            <div className="text-xs text-blue-200">Images</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20 hover:bg-white/20 transition-colors">
            <div className={`text-2xl font-bold ${
              result.parasiteWbcRatio >= 10 ? 'text-red-400' :
              result.parasiteWbcRatio >= 5 ? 'text-orange-400' :
              result.parasiteWbcRatio >= 1 ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {(result.parasiteWbcRatio || 0).toFixed(1)}
            </div>
            <div className="text-xs text-blue-200">P/WBC Ratio</div>
          </div>
        </div>
        
        {/* Ratio Interpretation */}
        {result.parasiteWbcRatio > 0 && (
          <div className="mt-4 p-3 bg-white/5 rounded-lg border border-white/10">
            <div className="flex items-center justify-between">
              <span className="text-sm text-blue-200">Parasite Density:</span>
              <span className={`text-sm font-medium ${
                result.parasiteWbcRatio >= 10 ? 'text-red-300' :
                result.parasiteWbcRatio >= 5 ? 'text-orange-300' :
                result.parasiteWbcRatio >= 1 ? 'text-yellow-300' :
                'text-green-300'
              }`}>
                {result.parasiteWbcRatio >= 10 ? 'High' :
                 result.parasiteWbcRatio >= 5 ? 'Moderate' :
                 result.parasiteWbcRatio >= 1 ? 'Low' :
                 'Very Low'}
              </span>
            </div>
            <div className="mt-2 w-full bg-white/20 rounded-full h-1.5">
              <div 
                className={`h-1.5 rounded-full transition-all duration-500 ${
                  result.parasiteWbcRatio >= 10 ? 'bg-red-400' :
                  result.parasiteWbcRatio >= 5 ? 'bg-orange-400' :
                  result.parasiteWbcRatio >= 1 ? 'bg-yellow-400' :
                  'bg-green-400'
                }`}
                style={{ width: `${Math.min(100, result.parasiteWbcRatio * 10)}%` }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DiagnosisCard;
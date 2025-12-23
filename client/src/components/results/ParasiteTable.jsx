
// src/components/results/ParasiteTable.jsx
import React from 'react';
import { Camera, TrendingUp, Activity, AlertCircle, Target, Brain, Microscope, Sparkles } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const ParasiteTable = ({ detections = [], showImageColumn = true, showIndividualRows = true }) => {
  if (!detections || detections.length === 0) {
    return (
      <div className="bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl p-8">
        <div className="text-center py-12">
          <div className="relative">
            <Microscope className="w-16 h-16 text-blue-300 mx-auto mb-4 drop-shadow-lg" />
            <Sparkles className="w-6 h-6 text-blue-400 absolute top-0 right-2 animate-pulse" />
          </div>
          <h3 className="text-white font-bold text-xl mb-2">No Detection Data</h3>
          <p className="text-blue-200">Analysis results will appear here once processing is complete</p>
        </div>
      </div>
    );
  }

  const getParasiteTypeColor = (type) => {
    const colors = {
      'PF': 'text-rose-200 bg-gradient-to-r from-rose-500/20 to-rose-600/30 border-rose-500/40',
      'PM': 'text-rose-300 bg-gradient-to-r from-rose-500/20 to-rose-600/30 border-rose-500/40',
      'PO': 'text-yellow-300 bg-gradient-to-r from-yellow-500/20 to-yellow-600/30 border-yellow-500/40',
      'PV': 'text-green-300 bg-gradient-to-r from-green-500/20 to-green-600/30 border-green-500/40',
    };
    return colors[type] || 'text-blue-300 bg-gradient-to-r from-blue-500/20 to-blue-600/30 border-blue-500/40';
  };

  const getParasiteFullName = (type) => {
    const names = {
      'PF': 'P. Falciparum',
      'PM': 'P. Malariae',
      'PO': 'P. Ovale',
      'PV': 'P. Vivax'
    };
    return names[type] || type;
  };

  const getRatioSeverity = (ratio) => {
    if (ratio >= 10) return 'severe';
    if (ratio >= 5) return 'moderate';
    if (ratio >= 1) return 'mild';
    return 'negative';
  };

  const getRatioInterpretation = (ratio) => {
    if (ratio >= 10) return { text: 'High Density', color: 'text-rose-200' };
    if (ratio >= 5) return { text: 'Moderate Density', color: 'text-rose-300' };
    if (ratio >= 1) return { text: 'Low Density', color: 'text-yellow-300' };
    if (ratio > 0) return { text: 'Very Low', color: 'text-green-300' };
    return { text: 'None', color: 'text-gray-400' };
  };

  // Calculate totals
  const totals = detections.reduce((acc, d) => ({
    parasites: acc.parasites + (d.parasiteCount || 0),
    wbc: acc.wbc + (d.whiteBloodCellsDetected || 0),
    ratioSum: acc.ratioSum + (d.parasiteWbcRatio || 0)
  }), { parasites: 0, wbc: 0, ratioSum: 0 });

  const avgRatio = detections.length > 0 ? totals.ratioSum / detections.length : 0;

  return (
    <div className="bg-gradient-to-br from-white/15 via-white/10 to-white/5 backdrop-blur-xl border border-white/30 rounded-2xl shadow-2xl p-6 overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/3 via-purple-500/3 to-indigo-500/3" />
      <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-bl from-white/5 to-transparent rounded-full blur-3xl" />
      
      <div className="relative">
        {/* Enhanced Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-4">
            <div className="p-3 bg-gradient-to-br from-purple-500/20 to-purple-600/30 rounded-xl border border-purple-500/40 backdrop-blur-sm shadow-lg">
              <TrendingUp className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">Detection Analysis</h3>
              <p className="text-blue-200 text-sm">
                Comprehensive analysis of {detections.length} microscopic images
              </p>
            </div>
          </div>
          
          {/* Stats Badge */}
          <div className="flex items-center space-x-3">
            <div className="px-4 py-2 bg-gradient-to-r from-blue-500/20 to-purple-500/20 rounded-xl border border-blue-500/30 backdrop-blur-sm">
              <div className="flex items-center space-x-2">
                <Brain className="w-4 h-4 text-blue-400" />
                <span className="text-blue-200 text-sm font-medium">AI Analysis Complete</span>
              </div>
            </div>
          </div>
        </div>

        {/* Enhanced Table - Individual Image Analysis */}
        {showIndividualRows && (
          <div className="overflow-x-auto">
            <div className="bg-gradient-to-br from-white/5 to-white/10 rounded-xl border border-white/20 backdrop-blur-sm shadow-lg">
              <table className="w-full">
                <thead className="bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-blue-500/10 border-b border-white/20">
                  <tr>
                    {showImageColumn && (
                      <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">
                        <div className="flex items-center space-x-2">
                          <Camera className="w-4 h-4" />
                          <span>Sample Image</span>
                        </div>
                      </th>
                    )}
                    <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">
                      <div className="flex items-center space-x-2">
                        <Target className="w-4 h-4 text-rose-300" />
                        <span>Parasites</span>
                      </div>
                    </th>
                    <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">
                      <div className="flex items-center space-x-2">
                        <Activity className="w-4 h-4 text-blue-400" />
                        <span>WBCs</span>
                      </div>
                    </th>
                    <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">P/WBC Ratio</th>
                    <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">Dominant Type</th>
                    <th className="text-left py-4 px-6 text-blue-200 font-bold text-sm">Density Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {detections.map((detection, index) => {
                    const parasiteCount = detection.parasiteCount || 0;
                    const wbcCount = detection.whiteBloodCellsDetected || 0;
                    const ratio = detection.parasiteWbcRatio || 0;
                    const dominantParasite = detection.parasitesDetected?.[0];
                    const ratioSeverity = getRatioSeverity(ratio);
                    const interpretation = getRatioInterpretation(ratio);

                    return (
                      <tr key={detection.imageId || index} className="border-b border-white/10 hover:bg-gradient-to-r hover:from-white/5 hover:to-white/10 transition-all duration-300 group">
                        {showImageColumn && (
                          <td className="py-5 px-6">
                            <div className="flex items-center space-x-4">
                              <div className="relative">
                                <div className="w-12 h-12 bg-gradient-to-br from-blue-500/20 to-blue-600/30 rounded-xl flex items-center justify-center border border-blue-500/30 shadow-lg group-hover:scale-110 transition-transform duration-200">
                                  <Camera className="w-5 h-5 text-blue-300" />
                                </div>
                                {parasiteCount > 0 && (
                                  <div className="absolute -top-1 -right-1 w-4 h-4 bg-rose-500 rounded-full flex items-center justify-center">
                                    <span className="text-white text-xs font-bold">{parasiteCount}</span>
                                  </div>
                                )}
                              </div>
                              <div>
                                <div className="text-white text-sm font-bold group-hover:text-blue-200 transition-colors">
                                  {detection.originalFilename || `Sample ${index + 1}`}
                                </div>
                                <div className="text-blue-300 text-xs">
                                  ID: {detection.imageId?.substring(0, 8) || `img${index + 1}`}
                                </div>
                              </div>
                            </div>
                          </td>
                        )}
                        
                        <td className="py-5 px-6">
                          <div className="flex items-center space-x-3">
                            <span className={`text-xl font-bold transition-colors duration-200 ${
                              parasiteCount > 0 ? 'text-rose-200 group-hover:text-rose-100' : 'text-gray-400'
                            }`}>
                              {parasiteCount}
                            </span>
                            {parasiteCount > 10 && (
                              <div className="p-1 bg-rose-500/20 rounded-lg border border-rose-500/30">
                                <Activity className="w-4 h-4 text-rose-300 animate-pulse" />
                              </div>
                            )}
                          </div>
                        </td>
                        
                        <td className="py-5 px-6">
                          <span className="text-blue-300 text-xl font-bold group-hover:text-blue-200 transition-colors duration-200">
                            {wbcCount}
                          </span>
                        </td>
                        
                        <td className="py-5 px-6">
                          <div className="flex items-center space-x-3">
                            <span className="text-white font-bold text-lg">{ratio.toFixed(2)}</span>
                            {ratio > 5 && (
                              <div className={`p-1 rounded-lg border ${
                                ratio >= 10 
                                  ? 'bg-rose-500/20 border-rose-500/30' 
                                  : 'bg-rose-500/20 border-rose-500/30'
                              }`}>
                                <AlertCircle className={`w-4 h-4 ${
                                  ratio >= 10 ? 'text-rose-300' : 'text-rose-400'
                                }`} />
                              </div>
                            )}
                          </div>
                        </td>
                        
                        <td className="py-5 px-6">
                          {dominantParasite ? (
                            <div className="flex items-center space-x-3">
                              <span className={`inline-flex items-center px-3 py-1 rounded-xl text-xs font-bold border backdrop-blur-sm shadow-lg ${getParasiteTypeColor(dominantParasite.type)}`}>
                                {getParasiteFullName(dominantParasite.type)}
                              </span>
                              <div className="flex items-center space-x-1">
                                <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
                                <span className="text-blue-300 text-xs font-medium">
                                  {((dominantParasite.confidence <= 1 ? dominantParasite.confidence * 100 : dominantParasite.confidence) || 0).toFixed(0)}%
                                </span>
                              </div>
                            </div>
                          ) : (
                            <span className="text-gray-400 text-sm italic">No parasites detected</span>
                          )}
                        </td>
                        
                        <td className="py-5 px-6">
                          <div className="flex items-center space-x-3">
                            <SeverityBadge severity={ratioSeverity} size="sm" showIcon={false} />
                            <span className={`text-xs font-medium ${interpretation.color}`}>
                              {interpretation.text}
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Enhanced Summary Section */}
        <div className="mt-8 pt-6 border-t border-white/20">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {/* Total Parasites */}
            <div className="group text-center p-6 bg-gradient-to-br from-rose-500/10 via-rose-500/5 to-transparent border border-rose-500/20 rounded-xl hover:bg-rose-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
              <div className={`text-2xl font-bold mb-2 transition-colors duration-200 ${totals.parasites > 0 ? 'text-rose-300 group-hover:text-rose-200' : 'text-gray-400'}`}>
                {totals.parasites}
              </div>
              <div className="text-xs text-rose-200 font-medium flex items-center justify-center space-x-1">
                <Target className="w-3 h-3" />
                <span>Total Parasites</span>
              </div>
            </div>
            
            {/* Total WBCs */}
            <div className="group text-center p-6 bg-gradient-to-br from-blue-500/10 via-blue-500/5 to-transparent border border-blue-500/20 rounded-xl hover:bg-blue-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
              <div className="text-2xl font-bold text-blue-400 group-hover:text-blue-300 transition-colors duration-200 mb-2">
                {totals.wbc}
              </div>
              <div className="text-xs text-blue-200 font-medium flex items-center justify-center space-x-1">
                <Activity className="w-3 h-3" />
                <span>Total WBCs</span>
              </div>
            </div>
            
            {/* Images Analyzed */}
            <div className="group text-center p-6 bg-gradient-to-br from-purple-500/10 via-purple-500/5 to-transparent border border-purple-500/20 rounded-xl hover:bg-purple-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
              <div className="text-2xl font-bold text-purple-400 group-hover:text-purple-300 transition-colors duration-200 mb-2">
                {detections.length}
              </div>
              <div className="text-xs text-purple-200 font-medium flex items-center justify-center space-x-1">
                <Microscope className="w-3 h-3" />
                <span>Images Analyzed</span>
              </div>
            </div>
            
            {/* Average Ratio */}
            <div className="group text-center p-6 bg-gradient-to-br from-rose-500/10 via-rose-500/5 to-transparent border border-rose-500/20 rounded-xl hover:bg-rose-500/15 transition-all duration-300 hover:scale-105 backdrop-blur-sm shadow-lg">
              <div className={`text-2xl font-bold mb-2 transition-colors duration-200 ${
                avgRatio >= 10 ? 'text-rose-300 group-hover:text-rose-200' :
                avgRatio >= 5 ? 'text-rose-400 group-hover:text-rose-300' :
                avgRatio >= 1 ? 'text-yellow-400 group-hover:text-yellow-300' :
                'text-green-400 group-hover:text-green-300'
              }`}>
                {avgRatio.toFixed(2)}
              </div>
              <div className="text-xs text-rose-200 font-medium flex items-center justify-center space-x-1">
                <TrendingUp className="w-3 h-3" />
                <span>Avg P/WBC</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default ParasiteTable;
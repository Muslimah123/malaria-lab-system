
// src/components/results/ParasiteTable.jsx
import React from 'react';
import { Camera, TrendingUp, Activity, AlertCircle } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const ParasiteTable = ({ detections = [], showImageColumn = true }) => {
  if (!detections || detections.length === 0) {
    return (
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6">
        <div className="text-center py-8">
          <Camera className="w-12 h-12 text-blue-300 mx-auto mb-3" />
          <p className="text-blue-200">No detection data available</p>
        </div>
      </div>
    );
  }

  const getParasiteTypeColor = (type) => {
    const colors = {
      'PF': 'text-red-300 bg-red-500/20',
      'PM': 'text-orange-300 bg-orange-500/20',
      'PO': 'text-yellow-300 bg-yellow-500/20',
      'PV': 'text-green-300 bg-green-500/20',
    };
    return colors[type] || 'text-blue-300 bg-blue-500/20';
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
    if (ratio >= 10) return { text: 'High Density', color: 'text-red-300' };
    if (ratio >= 5) return { text: 'Moderate Density', color: 'text-orange-300' };
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
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl shadow-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
        <TrendingUp className="w-5 h-5 mr-2 text-blue-400" />
        Detection Details ({detections.length} images analyzed)
      </h3>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/20">
              {showImageColumn && (
                <th className="text-left py-3 px-4 text-blue-200 font-medium">Image</th>
              )}
              <th className="text-left py-3 px-4 text-blue-200 font-medium">Parasites</th>
              <th className="text-left py-3 px-4 text-blue-200 font-medium">WBCs</th>
              <th className="text-left py-3 px-4 text-blue-200 font-medium">P/WBC Ratio</th>
              <th className="text-left py-3 px-4 text-blue-200 font-medium">Dominant Type</th>
              <th className="text-left py-3 px-4 text-blue-200 font-medium">Density</th>
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
                <tr key={detection.imageId || index} className="border-b border-white/10 hover:bg-white/5 transition-colors">
                  {showImageColumn && (
                    <td className="py-4 px-4">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-white/10 rounded-lg flex items-center justify-center mr-3">
                          <Camera className="w-4 h-4 text-blue-300" />
                        </div>
                        <div>
                          <div className="text-white text-sm font-medium">
                            {detection.originalFilename || `Image ${index + 1}`}
                          </div>
                          <div className="text-blue-300 text-xs">
                            ID: {detection.imageId?.substring(0, 8) || `img${index + 1}`}
                          </div>
                        </div>
                      </div>
                    </td>
                  )}
                  <td className="py-4 px-4">
                    <div className="flex items-center">
                      <span className={`text-lg font-bold mr-2 ${
                        parasiteCount > 0 ? 'text-red-300' : 'text-gray-400'
                      }`}>
                        {parasiteCount}
                      </span>
                      {parasiteCount > 10 && (
                        <Activity className="w-4 h-4 text-red-400 animate-pulse" />
                      )}
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    <span className="text-blue-300 text-lg font-bold">{wbcCount}</span>
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center space-x-2">
                      <span className="text-white font-bold">{ratio.toFixed(2)}</span>
                      {ratio > 5 && (
                        <AlertCircle className={`w-4 h-4 ${
                          ratio >= 10 ? 'text-red-400' : 'text-orange-400'
                        }`} />
                      )}
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    {dominantParasite ? (
                      <div className="flex items-center">
                        <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getParasiteTypeColor(dominantParasite.type)}`}>
                          {getParasiteFullName(dominantParasite.type)}
                        </span>
                        <span className="text-blue-300 text-xs ml-2">
                          {((dominantParasite.confidence <= 1 ? dominantParasite.confidence * 100 : dominantParasite.confidence) || 0).toFixed(0)}%
                        </span>
                      </div>
                    ) : (
                      <span className="text-gray-400 text-sm">None</span>
                    )}
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center space-x-2">
                      <SeverityBadge severity={ratioSeverity} size="sm" showIcon={false} />
                      <span className={`text-xs ${interpretation.color}`}>
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

      {/* Summary Row */}
      <div className="mt-6 pt-4 border-t border-white/20">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
            <div className={`text-lg font-bold ${totals.parasites > 0 ? 'text-red-400' : 'text-gray-400'}`}>
              {totals.parasites}
            </div>
            <div className="text-xs text-blue-200">Total Parasites</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
            <div className="text-lg font-bold text-blue-400">
              {totals.wbc}
            </div>
            <div className="text-xs text-blue-200">Total WBCs</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
            <div className="text-lg font-bold text-purple-400">
              {detections.length}
            </div>
            <div className="text-xs text-blue-200">Images</div>
          </div>
          <div className="text-center p-4 bg-white/10 backdrop-blur-md rounded-lg border border-white/20">
            <div className={`text-lg font-bold ${
              avgRatio >= 10 ? 'text-red-400' :
              avgRatio >= 5 ? 'text-orange-400' :
              avgRatio >= 1 ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {avgRatio.toFixed(2)}
            </div>
            <div className="text-xs text-blue-200">Avg P/WBC</div>
          </div>
        </div>

        {/* Overall Assessment */}
        {totals.parasites > 0 && (
          <div className="mt-4 p-4 bg-white/5 rounded-lg border border-white/10">
            <div className="flex items-start">
              <Activity className={`w-5 h-5 mr-3 mt-0.5 flex-shrink-0 ${
                avgRatio >= 10 ? 'text-red-400' :
                avgRatio >= 5 ? 'text-orange-400' :
                'text-yellow-400'
              }`} />
              <div>
                <p className="text-white font-medium mb-1">Overall Parasite Density Assessment</p>
                <p className="text-blue-200 text-sm">
                  {avgRatio >= 10 
                    ? 'High parasite density detected across multiple images.'
                    : avgRatio >= 5
                    ? 'Moderate parasite density detected.'
                    : avgRatio >= 1
                    ? 'Low parasite density.'
                    : 'Very low parasite density.'
                  }
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ParasiteTable;
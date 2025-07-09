// 📁 client/src/pages/DiagnosisResults.jsx
// High-level, production-ready diagnosis/test result page
import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { ArrowLeft } from 'lucide-react';
import LoadingSpinner from '../components/common/LoadingSpinner';
import apiService from '../services/api';
import { TEST_RESULTS } from '../utils/constants';

const DiagnosisResults = () => {
  const { testId } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    const fetchResult = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await apiService.tests.getById(testId);
        setResult(response.data);
      } catch (err) {
        setError('Failed to load diagnosis result.');
      } finally {
        setLoading(false);
      }
    };
    fetchResult();
  }, [testId]);

  if (loading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>;
  if (error) return <div className="text-center text-red-600 py-12">{error}</div>;
  if (!result) return null;

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-6">
      <button onClick={() => navigate(-1)} className="btn btn-outline flex items-center mb-4">
        <ArrowLeft className="w-4 h-4 mr-2" /> Back
      </button>
      <h1 className="text-2xl font-bold mb-2">Diagnosis Result</h1>
      <div className="bg-white rounded-lg shadow-medical p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:space-x-8">
          <div className="flex-1 space-y-2">
            <div><span className="font-semibold">Patient:</span> {result.patient?.fullName || result.patientId}</div>
            <div><span className="font-semibold">Test ID:</span> {result._id}</div>
            <div><span className="font-semibold">Date:</span> {new Date(result.createdAt).toLocaleString()}</div>
            <div><span className="font-semibold">Status:</span> <span className={`font-bold ${result.status === TEST_RESULTS.POSITIVE ? 'text-red-600' : 'text-green-700'}`}>{result.status}</span></div>
            <div><span className="font-semibold">Most Probable Parasite:</span> {result.mostProbableParasite?.type || 'N/A'}</div>
            <div><span className="font-semibold">Parasite/WBC Ratio:</span> {result.parasiteWbcRatio?.toFixed(2) ?? 'N/A'}</div>
          </div>
          {result.images && result.images.length > 0 && (
            <div className="flex-1">
              <div className="font-semibold mb-2">Images</div>
              <div className="grid grid-cols-2 gap-2">
                {result.images.map((img, idx) => (
                  <img key={idx} src={img.url} alt={`Slide ${idx + 1}`} className="rounded border" />
                ))}
              </div>
            </div>
          )}
        </div>
        <div>
          <div className="font-semibold mb-2">Detections</div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm border">
              <thead>
                <tr className="bg-gray-50">
                  <th className="px-2 py-1 border">Image</th>
                  <th className="px-2 py-1 border">Parasite Type</th>
                  <th className="px-2 py-1 border">Confidence</th>
                  <th className="px-2 py-1 border">Bounding Box</th>
                </tr>
              </thead>
              <tbody>
                {result.detections?.flatMap((det, i) =>
                  det.parasites_detected.map((p, j) => (
                    <tr key={`${i}-${j}`}> 
                      <td className="border px-2 py-1">{det.image_id}</td>
                      <td className="border px-2 py-1">{p.type}</td>
                      <td className="border px-2 py-1">{(p.confidence * 100).toFixed(1)}%</td>
                      <td className="border px-2 py-1">[{p.bbox.join(', ')}]</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DiagnosisResults;

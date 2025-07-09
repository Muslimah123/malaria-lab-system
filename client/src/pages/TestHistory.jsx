// 📁 client/src/pages/TestHistory.jsx
// High-level, production-ready test history page
import React, { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import LoadingSpinner from '../components/common/LoadingSpinner';
import apiService from '../services/api';
import { useNavigate } from 'react-router-dom';

const TestHistory = () => {
  const currentUser = useSelector(state => state.auth.user);
  const [tests, setTests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    const fetchTests = async () => {
      setLoading(true);
      setError(null);
      try {
        const params = { page, search };
        const response = await apiService.tests.getAll(params);
        setTests(response.data || []);
        setTotalPages(response.pagination?.pages || 1);
      } catch (err) {
        setError('Failed to load test history.');
      } finally {
        setLoading(false);
      }
    };
    fetchTests();
  }, [page, search]);

  const navigate = useNavigate();

  if (loading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>;
  if (error) return <div className="text-center text-red-600 py-12">{error}</div>;

  return (
    <div className="max-w-5xl mx-auto py-8 space-y-6">
      <h1 className="text-2xl font-bold mb-2">Test History</h1>
      <div className="bg-white rounded-lg shadow-medical p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-4 gap-2">
          <input
            type="text"
            placeholder="Search by patient, test ID, or result..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="input w-full md:w-64"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm border">
            <thead>
              <tr className="bg-gray-50">
                <th className="px-2 py-1 border">Test ID</th>
                <th className="px-2 py-1 border">Patient</th>
                <th className="px-2 py-1 border">Date</th>
                <th className="px-2 py-1 border">Result</th>
                <th className="px-2 py-1 border">Status</th>
                <th className="px-2 py-1 border">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tests.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-4">No tests found.</td></tr>
              ) : (
                tests.map(test => (
                  <tr key={test._id} className="hover:bg-gray-50">
                    <td className="border px-2 py-1">{test._id}</td>
                    <td className="border px-2 py-1">{test.patient?.fullName || test.patientId}</td>
                    <td className="border px-2 py-1">{new Date(test.createdAt).toLocaleString()}</td>
                    <td className="border px-2 py-1 font-bold {test.status === 'POSITIVE' ? 'text-red-600' : 'text-green-700'}">{test.status}</td>
                    <td className="border px-2 py-1">{test.status}</td>
                    <td className="border px-2 py-1">
                      <button className="btn btn-sm btn-outline" onClick={() => navigate(`/results/${test._id}`)}>View</button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex justify-end space-x-2 mt-4">
            <button className="btn btn-outline btn-sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
            <span className="text-sm">Page {page} of {totalPages}</span>
            <button className="btn btn-outline btn-sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
      </div>
    </div>
  );
};

export default TestHistory;

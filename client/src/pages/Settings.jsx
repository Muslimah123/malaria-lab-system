// 📁 client/src/pages/Settings.jsx
// High-level, production-ready settings/profile page
import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { showSuccessToast, showErrorToast } from '../store/slices/notificationsSlice';
import apiService from '../services/api';

const Settings = () => {
  const user = useSelector(state => state.auth.user);
  const dispatch = useDispatch();
  const [form, setForm] = useState({
    firstName: user?.firstName || '',
    lastName: user?.lastName || '',
    email: user?.email || '',
    phone: user?.phone || '',
    department: user?.department || '',
    password: '',
    newPassword: '',
    confirmNewPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = e => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleProfileUpdate = async e => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await apiService.auth.updateProfile(form);
      dispatch(showSuccessToast('Profile updated successfully'));
    } catch (err) {
      setError('Failed to update profile.');
      dispatch(showErrorToast('Failed to update profile'));
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async e => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    if (form.newPassword !== form.confirmNewPassword) {
      setError('New passwords do not match.');
      setLoading(false);
      return;
    }
    try {
      await apiService.auth.changePassword({
        currentPassword: form.password,
        newPassword: form.newPassword
      });
      dispatch(showSuccessToast('Password changed successfully'));
      setForm({ ...form, password: '', newPassword: '', confirmNewPassword: '' });
    } catch (err) {
      setError('Failed to change password.');
      dispatch(showErrorToast('Failed to change password'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-8 space-y-8">
      <h1 className="text-2xl font-bold mb-2">Settings</h1>
      <div className="bg-white rounded-lg shadow-medical p-6 space-y-6">
        <form onSubmit={handleProfileUpdate} className="space-y-4">
          <h2 className="font-semibold text-lg mb-2">Profile</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">First Name</label>
              <input name="firstName" value={form.firstName} onChange={handleChange} className="input" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
              <input name="lastName" value={form.lastName} onChange={handleChange} className="input" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input name="email" value={form.email} onChange={handleChange} className="input" type="email" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Phone</label>
              <input name="phone" value={form.phone} onChange={handleChange} className="input" />
            </div>
            <div className="col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">Department</label>
              <input name="department" value={form.department} onChange={handleChange} className="input" />
            </div>
          </div>
          <div className="flex justify-end">
            <button type="submit" className="btn btn-primary" disabled={loading}>Update Profile</button>
          </div>
        </form>
        <form onSubmit={handlePasswordChange} className="space-y-4">
          <h2 className="font-semibold text-lg mb-2">Change Password</h2>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
            <input name="password" value={form.password} onChange={handleChange} className="input" type="password" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input name="newPassword" value={form.newPassword} onChange={handleChange} className="input" type="password" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
            <input name="confirmNewPassword" value={form.confirmNewPassword} onChange={handleChange} className="input" type="password" />
          </div>
          {error && <div className="text-red-600 text-sm">{error}</div>}
          <div className="flex justify-end">
            <button type="submit" className="btn btn-primary" disabled={loading}>Change Password</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Settings;

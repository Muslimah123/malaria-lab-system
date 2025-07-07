// 📁 client/src/components/admin/UserManagement.jsx
// Complete user management component matching your backend API

import React, { useState, useEffect, useCallback } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  Users, 
  Plus, 
  Search, 
  Edit3, 
  Trash2, 
  AlertCircle,
  Eye,
  EyeOff,
  X
} from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';
import { 
  selectUser, 
  selectCanManageUsers 
} from '../../store/slices/authSlice';
import { 
  showSuccessToast, 
  showErrorToast
} from '../../store/slices/notificationsSlice';
import { PAGINATION_DEFAULTS } from '../../utils/constants';
import apiService from '../../services/api';

const UserManagement = () => {
  const dispatch = useDispatch();
  const currentUser = useSelector(selectUser);
  const canManageUsers = useSelector(selectCanManageUsers);

  // State
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [deletingUser, setDeletingUser] = useState(null);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: PAGINATION_DEFAULTS.LIMIT,
    total: 0,
    pages: 0
  });

  // Fetch users with useCallback to fix dependency issues
  const fetchUsers = useCallback(async (page = 1, search = '', role = 'all') => {
    try {
      setLoading(true);
      
      const params = {
        page,
        limit: pagination.limit
      };

      let response;
      if (search.trim()) {
        // Use search endpoint
        response = await apiService.users.search(search.trim(), params);
      } else {
        // Use regular get all endpoint
        response = await apiService.users.getAll(params);
      }

      if (response.success) {
        let userData = response.data || [];
        
        // Filter by role if specified
        if (role !== 'all') {
          userData = userData.filter(user => user.role === role);
        }

        setUsers(userData);
        setPagination(response.pagination || {
          page,
          limit: pagination.limit,
          total: userData.length,
          pages: Math.ceil(userData.length / pagination.limit)
        });
      }
    } catch (error) {
      console.error('Failed to fetch users:', error);
      dispatch(showErrorToast('Failed to load users'));
    } finally {
      setLoading(false);
    }
  }, [dispatch, pagination.limit]);

  // Initial load
  useEffect(() => {
    if (canManageUsers) {
      fetchUsers();
    }
  }, [canManageUsers]);

  // Search handler with debounce
  useEffect(() => {
    const debounceTimer = setTimeout(() => {
      if (searchTerm !== '' || selectedRole !== 'all') {
        fetchUsers(1, searchTerm, selectedRole);
      } else {
        fetchUsers(1);
      }
    }, 500);

    return () => clearTimeout(debounceTimer);
  }, [searchTerm, selectedRole]);

  // Permission check
  if (!canManageUsers) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Access Denied</h2>
          <p className="text-gray-600">You don't have permission to manage users.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
          <p className="mt-1 text-sm text-gray-600">
            Manage system users, roles, and permissions
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add User
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-medical p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search users by username or email..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input pl-10"
            />
          </div>

          {/* Role Filter */}
          <div className="sm:w-48">
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="input"
            >
              <option value="all">All Roles</option>
              <option value="admin">Admin</option>
              <option value="supervisor">Supervisor</option>
              <option value="technician">Technician</option>
            </select>
          </div>
        </div>
      </div>

      {/* Users List */}
      <div className="bg-white rounded-lg shadow-medical">
        {loading ? (
          <div className="flex justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-12">
            <Users className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">
              {searchTerm ? 'No users found matching your search' : 'No users found'}
            </p>
          </div>
        ) : (
          <>
            {/* Table Header */}
            <div className="px-6 py-4 border-b border-gray-200 bg-gray-50 rounded-t-lg">
              <div className="grid grid-cols-12 gap-4 text-sm font-medium text-gray-600">
                <div className="col-span-3">User</div>
                <div className="col-span-2">Role</div>
                <div className="col-span-2">Department</div>
                <div className="col-span-2">Last Login</div>
                <div className="col-span-1">Status</div>
                <div className="col-span-2">Actions</div>
              </div>
            </div>

            {/* Table Body */}
            <div className="divide-y divide-gray-200">
              {users.map((user) => (
                <UserRow
                  key={user._id}
                  user={user}
                  currentUser={currentUser}
                  onEdit={setEditingUser}
                  onDelete={setDeletingUser}
                  onRoleChange={fetchUsers}
                />
              ))}
            </div>

            {/* Pagination */}
            {pagination.pages > 1 && (
              <div className="px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-lg">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-gray-600">
                    Showing {((pagination.page - 1) * pagination.limit) + 1} to{' '}
                    {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
                    {pagination.total} users
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => fetchUsers(pagination.page - 1, searchTerm, selectedRole)}
                      disabled={pagination.page <= 1}
                      className="btn btn-outline btn-sm"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => fetchUsers(pagination.page + 1, searchTerm, selectedRole)}
                      disabled={pagination.page >= pagination.pages}
                      className="btn btn-outline btn-sm"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Modals */}
      {showCreateModal && (
        <CreateUserModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            fetchUsers();
          }}
        />
      )}

      {editingUser && (
        <EditUserModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSuccess={() => {
            setEditingUser(null);
            fetchUsers();
          }}
        />
      )}

      {deletingUser && (
        <DeleteUserModal
          user={deletingUser}
          onClose={() => setDeletingUser(null)}
          onSuccess={() => {
            setDeletingUser(null);
            fetchUsers();
          }}
        />
      )}
    </div>
  );
};

// User Row Component
const UserRow = ({ user, currentUser, onEdit, onDelete, onRoleChange }) => {
  const dispatch = useDispatch();
  const [updatingRole, setUpdatingRole] = useState(false);

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case 'admin':
        return 'bg-red-100 text-red-800';
      case 'supervisor':
        return 'bg-blue-100 text-blue-800';
      case 'technician':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const handleRoleChange = async (newRole) => {
    if (newRole === user.role) return;
    
    try {
      setUpdatingRole(true);
      await apiService.users.updateRole(user._id, newRole);
      dispatch(showSuccessToast(`User role updated to ${newRole}`));
      onRoleChange();
    } catch (error) {
      dispatch(showErrorToast('Failed to update user role'));
    } finally {
      setUpdatingRole(false);
    }
  };

  const formatLastLogin = (lastLogin) => {
    if (!lastLogin) return 'Never';
    const date = new Date(lastLogin);
    const now = new Date();
    const diffInHours = (now - date) / (1000 * 60 * 60);
    
    if (diffInHours < 24) {
      return `${Math.floor(diffInHours)}h ago`;
    } else if (diffInHours < 24 * 7) {
      return `${Math.floor(diffInHours / 24)}d ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  return (
    <div className="px-6 py-4 hover:bg-gray-50">
      <div className="grid grid-cols-12 gap-4 items-center">
        {/* User Info */}
        <div className="col-span-3">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-primary-100 rounded-full flex items-center justify-center">
              <span className="text-primary-600 font-medium text-sm">
                {user.firstName?.[0]}{user.lastName?.[0]}
              </span>
            </div>
            <div>
              <p className="font-medium text-gray-900">
                {user.firstName} {user.lastName}
              </p>
              <p className="text-sm text-gray-600">{user.email}</p>
              <p className="text-xs text-gray-500">@{user.username}</p>
            </div>
          </div>
        </div>

        {/* Role */}
        <div className="col-span-2">
          {currentUser.role === 'admin' && user._id !== currentUser._id ? (
            <select
              value={user.role}
              onChange={(e) => handleRoleChange(e.target.value)}
              disabled={updatingRole}
              className="text-sm border border-gray-300 rounded px-2 py-1"
            >
              <option value="technician">Technician</option>
              <option value="supervisor">Supervisor</option>
              <option value="admin">Admin</option>
            </select>
          ) : (
            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRoleBadgeColor(user.role)}`}>
              {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
            </span>
          )}
          {updatingRole && <LoadingSpinner size="sm" />}
        </div>

        {/* Department */}
        <div className="col-span-2">
          <span className="text-sm text-gray-600">
            {user.department || 'Laboratory'}
          </span>
        </div>

        {/* Last Login */}
        <div className="col-span-2">
          <span className="text-sm text-gray-600">
            {formatLastLogin(user.lastLogin)}
          </span>
        </div>

        {/* Status */}
        <div className="col-span-1">
          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
            user.isActive 
              ? 'bg-green-100 text-green-800' 
              : 'bg-red-100 text-red-800'
          }`}>
            {user.isActive ? 'Active' : 'Inactive'}
          </span>
        </div>

        {/* Actions */}
        <div className="col-span-2">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onEdit(user)}
              className="p-1 text-gray-400 hover:text-blue-600"
              title="Edit user"
            >
              <Edit3 className="w-4 h-4" />
            </button>
            
            {user._id !== currentUser._id && (
              <button
                onClick={() => onDelete(user)}
                className="p-1 text-gray-400 hover:text-red-600"
                title="Delete user"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Create User Modal
const CreateUserModal = ({ onClose, onSuccess }) => {
  const dispatch = useDispatch();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    firstName: '',
    lastName: '',
    password: '',
    role: 'technician',
    department: 'Laboratory',
    phoneNumber: '',
    licenseNumber: ''
  });
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({});

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrors({});

    try {
      await apiService.auth.register(formData);
      dispatch(showSuccessToast('User created successfully'));
      onSuccess();
    } catch (error) {
      if (error.message.includes('already exists')) {
        setErrors({ 
          submit: 'A user with this email or username already exists' 
        });
      } else {
        setErrors({ submit: error.message });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-screen overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900">Create New User</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {errors.submit && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-800 text-sm">{errors.submit}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                First Name *
              </label>
              <input
                type="text"
                required
                value={formData.firstName}
                onChange={(e) => setFormData(prev => ({ ...prev, firstName: e.target.value }))}
                className="input"
                placeholder="First name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Last Name *
              </label>
              <input
                type="text"
                required
                value={formData.lastName}
                onChange={(e) => setFormData(prev => ({ ...prev, lastName: e.target.value }))}
                className="input"
                placeholder="Last name"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Username *
            </label>
            <input
              type="text"
              required
              value={formData.username}
              onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
              className="input"
              placeholder="username"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email *
            </label>
            <input
              type="email"
              required
              value={formData.email}
              onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
              className="input"
              placeholder="user@example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password *
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={formData.password}
                onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                className="input pr-10"
                placeholder="Password (min 6 characters)"
                minLength={6}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center"
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4 text-gray-400" />
                ) : (
                  <Eye className="h-4 w-4 text-gray-400" />
                )}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Role *
            </label>
            <select
              value={formData.role}
              onChange={(e) => setFormData(prev => ({ ...prev, role: e.target.value }))}
              className="input"
            >
              <option value="technician">Technician</option>
              <option value="supervisor">Supervisor</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Department
            </label>
            <input
              type="text"
              value={formData.department}
              onChange={(e) => setFormData(prev => ({ ...prev, department: e.target.value }))}
              className="input"
              placeholder="Laboratory"
            />
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="btn btn-outline"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" color="white" />
                  <span className="ml-2">Creating...</span>
                </>
              ) : (
                'Create User'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Placeholder modals (simplified)
const EditUserModal = ({ user, onClose, onSuccess }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white rounded-lg p-6 w-full max-w-md">
      <h3 className="text-lg font-medium text-gray-900 mb-4">Edit User</h3>
      <p className="text-gray-600 mb-4">Edit functionality coming soon...</p>
      <div className="flex justify-end">
        <button onClick={onClose} className="btn btn-outline">Close</button>
      </div>
    </div>
  </div>
);

const DeleteUserModal = ({ user, onClose, onSuccess }) => {
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(false);

  const handleDelete = async () => {
    setLoading(true);
    try {
      await apiService.users.delete(user._id);
      dispatch(showSuccessToast('User deleted successfully'));
      onSuccess();
    } catch (error) {
      dispatch(showErrorToast('Failed to delete user'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <div className="flex items-center mb-4">
          <AlertCircle className="w-6 h-6 text-red-600 mr-2" />
          <h3 className="text-lg font-medium text-gray-900">Delete User</h3>
        </div>
        <p className="text-gray-600 mb-4">
          Are you sure you want to delete <strong>{user.firstName} {user.lastName}</strong>? 
          This action cannot be undone.
        </p>
        <div className="flex justify-end space-x-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="btn btn-outline"
          >
            Cancel
          </button>
          <button
            onClick={handleDelete}
            disabled={loading}
            className="btn bg-red-600 text-white hover:bg-red-700"
          >
            {loading ? (
              <>
                <LoadingSpinner size="sm" color="white" />
                <span className="ml-2">Deleting...</span>
              </>
            ) : (
              'Delete User'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default UserManagement;
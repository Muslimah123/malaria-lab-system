import React, { useState } from 'react';
import { 
  Search, 
  Plus, 
  Edit, 
  Trash2, 
  MoreHorizontal,
  User,
  Users,
  Shield,
  Mail,
  Phone,
  Calendar,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Eye,
  EyeOff,
  Key,
  UserCheck,
  UserX,
  Settings,
  Download,
  Filter,
  X,
  Save,
  Crown,
  Briefcase,
  Microscope
} from 'lucide-react';

const UserManagementPage = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const [newUser, setNewUser] = useState({
    name: '',
    email: '',
    phone: '',
    role: '',
    department: '',
    password: '',
    confirmPassword: ''
  });

  // Mock user data
  const allUsers = [
    {
      id: 'USR-001',
      name: 'Dr. Sarah Johnson',
      email: 'sarah.johnson@malarialab.com',
      phone: '+250 788 111 222',
      role: 'admin',
      department: 'Administration',
      status: 'active',
      lastLogin: '2025-07-11T14:30:00Z',
      createdAt: '2025-01-15T09:00:00Z',
      testsProcessed: 0,
      avatar: 'SJ'
    },
    {
      id: 'USR-002',
      name: 'Dr. Michael Lee',
      email: 'michael.lee@malarialab.com',
      phone: '+250 788 333 444',
      role: 'supervisor',
      department: 'Laboratory',
      status: 'active',
      lastLogin: '2025-07-11T13:45:00Z',
      createdAt: '2025-02-20T10:30:00Z',
      testsProcessed: 0,
      avatar: 'ML'
    },
    {
      id: 'USR-003',
      name: 'Maria Garcia',
      email: 'maria.garcia@malarialab.com',
      phone: '+250 788 555 666',
      role: 'technician',
      department: 'Laboratory',
      status: 'active',
      lastLogin: '2025-07-11T14:15:00Z',
      createdAt: '2025-03-10T14:20:00Z',
      testsProcessed: 127,
      avatar: 'MG'
    },
    {
      id: 'USR-004',
      name: 'James Wilson',
      email: 'james.wilson@malarialab.com',
      phone: '+250 788 777 888',
      role: 'technician',
      department: 'Laboratory',
      status: 'active',
      lastLogin: '2025-07-11T12:30:00Z',
      createdAt: '2025-04-05T11:45:00Z',
      testsProcessed: 89,
      avatar: 'JW'
    },
    {
      id: 'USR-005',
      name: 'Sarah Chen',
      email: 'sarah.chen@malarialab.com',
      phone: '+250 788 999 000',
      role: 'technician',
      department: 'Laboratory',
      status: 'active',
      lastLogin: '2025-07-11T11:20:00Z',
      createdAt: '2025-05-12T16:10:00Z',
      testsProcessed: 76,
      avatar: 'SC'
    },
    {
      id: 'USR-006',
      name: 'Robert Davis',
      email: 'robert.davis@malarialab.com',
      phone: '+250 788 123 789',
      role: 'technician',
      department: 'Laboratory',
      status: 'inactive',
      lastLogin: '2025-07-05T09:15:00Z',
      createdAt: '2025-06-01T13:30:00Z',
      testsProcessed: 23,
      avatar: 'RD'
    }
  ];

  const rolePermissions = {
    admin: {
      name: 'Administrator',
      color: 'bg-purple-100 text-purple-800 border-purple-200',
      icon: Crown,
      permissions: [
        'Manage all users and roles',
        'View all test results',
        'Delete test records',
        'System configuration',
        'Export all data',
        'Audit log access'
      ]
    },
    supervisor: {
      name: 'Lab Supervisor',
      color: 'bg-blue-100 text-blue-800 border-blue-200',
      icon: Briefcase,
      permissions: [
        'Review and approve test results',
        'View all test records',
        'Manage technician assignments',
        'Generate reports',
        'Quality control oversight'
      ]
    },
    technician: {
      name: 'Lab Technician',
      color: 'bg-green-100 text-green-800 border-green-200',
      icon: Microscope,
      permissions: [
        'Upload and process samples',
        'View own test results',
        'Create patient records',
        'Run diagnostic tests',
        'Update test status'
      ]
    }
  };

  const filteredUsers = allUsers.filter(user => {
    if (searchTerm) {
      const searchFields = [
        user.name,
        user.email,
        user.id,
        user.department
      ].join(' ').toLowerCase();
      
      if (!searchFields.includes(searchTerm.toLowerCase())) {
        return false;
      }
    }

    if (selectedRole !== 'all' && user.role !== selectedRole) {
      return false;
    }

    if (selectedStatus !== 'all' && user.status !== selectedStatus) {
      return false;
    }

    return true;
  });

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const formatLastLogin = (dateString) => {
    const now = new Date();
    const loginDate = new Date(dateString);
    const diffInHours = Math.floor((now - loginDate) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return 'Just now';
    if (diffInHours < 24) return `${diffInHours}h ago`;
    const diffInDays = Math.floor(diffInHours / 24);
    if (diffInDays < 7) return `${diffInDays}d ago`;
    return formatDate(dateString);
  };

  const getRoleBadge = (role) => {
    const roleInfo = rolePermissions[role];
    if (!roleInfo) return null;
    
    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium border ${roleInfo.color}`}>
        <roleInfo.icon className="h-3 w-3" />
        <span>{roleInfo.name}</span>
      </span>
    );
  };

  const getStatusBadge = (status) => {
    const statusStyles = {
      active: { bg: "bg-green-100", text: "text-green-800", border: "border-green-200", icon: CheckCircle },
      inactive: { bg: "bg-gray-100", text: "text-gray-800", border: "border-gray-200", icon: XCircle },
      suspended: { bg: "bg-red-100", text: "text-red-800", border: "border-red-200", icon: AlertTriangle }
    };
    
    const style = statusStyles[status] || statusStyles.inactive;
    const IconComponent = style.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium border ${style.bg} ${style.text} ${style.border}`}>
        <IconComponent className="h-3 w-3" />
        <span>{status}</span>
      </span>
    );
  };

  const handleCreateUser = () => {
    // In real implementation, this would call the API
    console.log('Creating user:', newUser);
    setShowCreateModal(false);
    setNewUser({
      name: '',
      email: '',
      phone: '',
      role: '',
      department: '',
      password: '',
      confirmPassword: ''
    });
  };

  const handleEditUser = () => {
    // In real implementation, this would call the API
    console.log('Editing user:', selectedUser);
    setShowEditModal(false);
    setSelectedUser(null);
  };

  const handleDeleteUser = () => {
    // In real implementation, this would call the API
    console.log('Deleting user:', selectedUser);
    setShowDeleteConfirm(false);
    setSelectedUser(null);
  };

  const CreateUserModal = () => (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-white/20 rounded-lg p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white">Create New User</h3>
          <button
            onClick={() => setShowCreateModal(false)}
            className="text-gray-400 hover:text-white"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Full Name *</label>
              <input
                type="text"
                value={newUser.name}
                onChange={(e) => setNewUser({...newUser, name: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="Enter full name"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Email Address *</label>
              <input
                type="email"
                value={newUser.email}
                onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="user@malarialab.com"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Phone Number</label>
              <input
                type="tel"
                value={newUser.phone}
                onChange={(e) => setNewUser({...newUser, phone: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="+250 788 123 456"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Role *</label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({...newUser, role: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="">Select role</option>
                <option value="admin">Administrator</option>
                <option value="supervisor">Lab Supervisor</option>
                <option value="technician">Lab Technician</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Department</label>
              <select
                value={newUser.department}
                onChange={(e) => setNewUser({...newUser, department: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="">Select department</option>
                <option value="Administration">Administration</option>
                <option value="Laboratory">Laboratory</option>
                <option value="Quality Control">Quality Control</option>
                <option value="IT Support">IT Support</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Password *</label>
              <input
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="Enter secure password"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Confirm Password *</label>
              <input
                type="password"
                value={newUser.confirmPassword}
                onChange={(e) => setNewUser({...newUser, confirmPassword: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="Confirm password"
              />
            </div>
          </div>

          {newUser.role && (
            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">Role Permissions</h4>
              <ul className="text-blue-200 text-sm space-y-1">
                {rolePermissions[newUser.role]?.permissions.map((permission, index) => (
                  <li key={index} className="flex items-center space-x-2">
                    <CheckCircle className="h-3 w-3 text-green-400 flex-shrink-0" />
                    <span>{permission}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex items-center justify-end space-x-3 pt-6 border-t border-white/20">
            <button
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleCreateUser}
              className="flex items-center space-x-2 px-6 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              <Save className="h-4 w-4" />
              <span>Create User</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const DeleteConfirmModal = () => (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-white/20 rounded-lg p-6 w-full max-w-md mx-4">
        <div className="flex items-center space-x-4 mb-6">
          <div className="bg-red-500/20 p-3 rounded-full">
            <AlertTriangle className="h-6 w-6 text-red-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">Delete User</h3>
            <p className="text-blue-200 text-sm">This action cannot be undone</p>
          </div>
        </div>

        <p className="text-blue-200 mb-6">
          Are you sure you want to delete <strong className="text-white">{selectedUser?.name}</strong>? 
          This will permanently remove their account and all associated data.
        </p>

        <div className="flex items-center justify-end space-x-3">
          <button
            onClick={() => setShowDeleteConfirm(false)}
            className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleDeleteUser}
            className="flex items-center space-x-2 px-6 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors"
          >
            <Trash2 className="h-4 w-4" />
            <span>Delete User</span>
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900">
      {/* Header */}
      <header className="bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between py-4">
            <div className="flex items-center space-x-4">
              <div className="bg-blue-500 p-2 rounded-lg">
                <Users className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white">User Management</h1>
                <p className="text-blue-200 text-sm">Manage system users, roles, and permissions</p>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors">
                <Download className="h-4 w-4" />
                <span>Export</span>
              </button>
              <button
                onClick={() => setShowCreateModal(true)}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-white transition-colors"
              >
                <Plus className="h-4 w-4" />
                <span>New User</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Search and Filters */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 mb-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
              <input
                type="text"
                placeholder="Search users by name, email, ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            </div>

            <div className="flex items-center space-x-4">
              <select
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
                className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="all">All Roles</option>
                <option value="admin">Administrator</option>
                <option value="supervisor">Lab Supervisor</option>
                <option value="technician">Lab Technician</option>
              </select>

              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="suspended">Suspended</option>
              </select>

              <span className="text-blue-200 text-sm">
                {filteredUsers.length} users
              </span>
            </div>
          </div>
        </div>

        {/* Role Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {Object.entries(rolePermissions).map(([roleKey, roleInfo]) => {
            const roleCount = filteredUsers.filter(user => user.role === roleKey).length;
            return (
              <div key={roleKey} className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
                <div className="flex items-center space-x-4">
                  <div className={`p-3 rounded-lg bg-${roleInfo.color.includes('purple') ? 'purple' : roleInfo.color.includes('blue') ? 'blue' : 'green'}-500`}>
                    <roleInfo.icon className="h-6 w-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-white font-medium">{roleInfo.name}</h3>
                    <p className="text-blue-200 text-sm">{roleCount} users</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Users Table */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5 border-b border-white/20">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Department
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Last Login
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Tests Processed
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-white/5 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-3">
                        <div className="bg-blue-500 w-10 h-10 rounded-full flex items-center justify-center">
                          <span className="text-white text-sm font-medium">{user.avatar}</span>
                        </div>
                        <div>
                          <div className="text-white font-medium">{user.name}</div>
                          <div className="text-blue-300 text-sm">{user.email}</div>
                          <div className="text-blue-400 text-xs">{user.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {getRoleBadge(user.role)}
                    </td>
                    <td className="px-6 py-4 text-sm text-blue-200">
                      {user.department}
                    </td>
                    <td className="px-6 py-4">
                      {getStatusBadge(user.status)}
                    </td>
                    <td className="px-6 py-4 text-sm text-blue-200">
                      {formatLastLogin(user.lastLogin)}
                    </td>
                    <td className="px-6 py-4 text-sm text-white">
                      {user.testsProcessed > 0 ? user.testsProcessed.toLocaleString() : '-'}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => {
                            setSelectedUser(user);
                            setShowEditModal(true);
                          }}
                          className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                          <Key className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => {
                            setSelectedUser(user);
                            setShowDeleteConfirm(true);
                          }}
                          className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                        <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                          <MoreHorizontal className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Empty State */}
        {filteredUsers.length === 0 && (
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-12 text-center">
            <Users className="h-12 w-12 text-blue-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No users found</h3>
            <p className="text-blue-200 mb-6">
              {searchTerm || selectedRole !== 'all' || selectedStatus !== 'all'
                ? 'Try adjusting your search or filter criteria.'
                : 'No users have been created yet.'}
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              Create First User
            </button>
          </div>
        )}
      </main>

      {showCreateModal && <CreateUserModal />}
      {showDeleteConfirm && <DeleteConfirmModal />}
    </div>
  );
};

export default UserManagementPage;
// // src/pages/UserManagementPage.jsx - LIVE DATA VERSION
// import React, { useState, useEffect, useCallback } from 'react';
// import { useDispatch, useSelector } from 'react-redux';
// import { 
//   Search, 
//   Plus, 
//   Edit, 
//   Trash2, 
//   MoreHorizontal,
//   User,
//   Users,
//   Shield,
//   Mail,
//   Phone,
//   Calendar,
//   Clock,
//   CheckCircle,
//   XCircle,
//   AlertTriangle,
//   Eye,
//   EyeOff,
//   Key,
//   UserCheck,
//   UserX,
//   Settings,
//   Download,
//   Filter,
//   X,
//   Save,
//   Crown,
//   Briefcase,
//   Microscope,
//   RefreshCw,
//   AlertCircle
// } from 'lucide-react';

// // Redux imports
// import {
//   fetchUsers,
//   searchUsers,
//   updateUserRole,
//   deleteUser,
//   resetUserPassword,
//   clearUsersError,
//   clearUsersSearchResults,
//   selectUsers,
//   selectUsersLoading,
//   selectUsersError,
//   selectUsersPagination,
//   selectUsersSearchResults
// } from '../store/slices/usersSlice';

// import { showSuccessToast, showErrorToast, showWarningToast } from '../store/slices/notificationsSlice';
// import { selectUser } from '../store/slices/authSlice';

// // Components
// import AppLayout from '../components/layout/AppLayout';
// import LoadingSpinner, { TableSkeletonLoader, CardLoader } from '../components/common/LoadingSpinner';
// import { ConfirmModal, AlertModal, FormModal, useModal } from '../components/common/Modal';

// // Services
// import apiService from '../services/api';

// // Utils
// import { USER_ROLES } from '../utils/constants';

// const UserManagementPage = () => {
//   const dispatch = useDispatch();
  
//   // Redux state
//   const users = useSelector(selectUsers);
//   const isLoading = useSelector(selectUsersLoading);
//   const error = useSelector(selectUsersError);
//   const pagination = useSelector(selectUsersPagination);
//   const searchResults = useSelector(selectUsersSearchResults);
//   const currentUser = useSelector(selectUser);

//   // Local state
//   const [searchTerm, setSearchTerm] = useState('');
//   const [selectedRole, setSelectedRole] = useState('all');
//   const [selectedStatus, setSelectedStatus] = useState('all');
//   const [selectedUser, setSelectedUser] = useState(null);
//   const [isRefreshing, setIsRefreshing] = useState(false);
//   const [currentPage, setCurrentPage] = useState(1);

//   // Modal states
//   const createModal = useModal();
//   const editModal = useModal();
//   const deleteModal = useModal();
//   const passwordModal = useModal();

//   // Form state for create/edit
//   const [userForm, setUserForm] = useState({
//     firstName: '',
//     lastName: '',
//     email: '',
//     phoneNumber: '',
//     role: '',
//     department: '',
//     password: '',
//     confirmPassword: ''
//   });

//   // Password reset form
//   const [passwordForm, setPasswordForm] = useState({
//     newPassword: '',
//     confirmPassword: ''
//   });

//   const [isCreating, setIsCreating] = useState(false);
//   const [isUpdating, setIsUpdating] = useState(false);
//   const [isDeleting, setIsDeleting] = useState(false);
//   const [isResettingPassword, setIsResettingPassword] = useState(false);

//   const rolePermissions = {
//     admin: {
//       name: 'Administrator',
//       color: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
//       icon: Crown,
//       permissions: [
//         'Manage all users and roles',
//         'View all test results',
//         'Delete test records',
//         'System configuration',
//         'Export all data',
//         'Audit log access'
//       ]
//     },
//     supervisor: {
//       name: 'Lab Supervisor',
//       color: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
//       icon: Briefcase,
//       permissions: [
//         'Review and approve test results',
//         'View all test records',
//         'Manage technician assignments',
//         'Generate reports',
//         'Quality control oversight'
//       ]
//     },
//     technician: {
//       name: 'Lab Technician',
//       color: 'bg-green-500/20 text-green-300 border-green-500/30',
//       icon: Microscope,
//       permissions: [
//         'Upload and process samples',
//         'View own test results',
//         'Create patient records',
//         'Run diagnostic tests',
//         'Update test status'
//       ]
//     }
//   };

//   // Load users on mount and when filters change
//   useEffect(() => {
//     loadUsers();
//   }, [currentPage, selectedRole, selectedStatus]);

//   // Handle search with debounce
//   useEffect(() => {
//     const timer = setTimeout(() => {
//       if (searchTerm.trim()) {
//         handleSearch();
//       } else {
//         dispatch(clearUsersSearchResults());
//         loadUsers();
//       }
//     }, 500);
//     return () => clearTimeout(timer);
//   }, [searchTerm]);

//   const loadUsers = useCallback(async () => {
//     const params = {
//       page: currentPage,
//       limit: 20,
//       sort: 'firstName',
//       order: 'asc'
//     };

//     // Add filters
//     if (selectedRole !== 'all') params.role = selectedRole;
//     if (selectedStatus !== 'all') params.status = selectedStatus;

//     try {
//       await dispatch(fetchUsers(params)).unwrap();
//     } catch (error) {
//       dispatch(showErrorToast(error.message || 'Failed to load users'));
//     }
//   }, [dispatch, currentPage, selectedRole, selectedStatus]);

//   const handleSearch = useCallback(async () => {
//     if (!searchTerm.trim()) return;
    
//     try {
//       await dispatch(searchUsers({ 
//         query: searchTerm.trim(),
//         params: {
//           role: selectedRole !== 'all' ? selectedRole : undefined,
//           status: selectedStatus !== 'all' ? selectedStatus : undefined
//         }
//       })).unwrap();
//     } catch (error) {
//       dispatch(showErrorToast('Search failed'));
//     }
//   }, [dispatch, searchTerm, selectedRole, selectedStatus]);

//   const handleRefresh = async () => {
//     setIsRefreshing(true);
//     dispatch(clearUsersError());
//     await loadUsers();
//     setIsRefreshing(false);
//     dispatch(showSuccessToast('Users refreshed'));
//   };

//   const handleCreateUser = async () => {
//     // Validate form
//     if (!userForm.firstName || !userForm.lastName || !userForm.email || !userForm.role) {
//       dispatch(showErrorToast('Please fill in all required fields'));
//       return;
//     }

//     if (userForm.password !== userForm.confirmPassword) {
//       dispatch(showErrorToast('Passwords do not match'));
//       return;
//     }

//     setIsCreating(true);
//     try {
//       // ✅ CREATE USER: Call API to create user
//       const userData = {
//         firstName: userForm.firstName,
//         lastName: userForm.lastName,
//         email: userForm.email,
//         phoneNumber: userForm.phoneNumber,
//         role: userForm.role,
//         department: userForm.department,
//         password: userForm.password
//       };

//       const response = await apiService.auth.register(userData);
      
//       if (response.success) {
//         dispatch(showSuccessToast('User created successfully'));
//         createModal.closeModal();
//         resetForm();
//         await loadUsers(); // Refresh users list
//       }
//     } catch (error) {
//       const errorMessage = error.response?.data?.message || error.message || 'Failed to create user';
//       dispatch(showErrorToast(errorMessage));
//     } finally {
//       setIsCreating(false);
//     }
//   };

//   const handleUpdateUser = async () => {
//     if (!selectedUser) return;

//     setIsUpdating(true);
//     try {
//       // ✅ UPDATE USER: Call API to update user role
//       await dispatch(updateUserRole({ 
//         userId: selectedUser._id, 
//         role: userForm.role 
//       })).unwrap();
      
//       dispatch(showSuccessToast('User updated successfully'));
//       editModal.closeModal();
//       resetForm();
//       setSelectedUser(null);
//     } catch (error) {
//       dispatch(showErrorToast(error.message || 'Failed to update user'));
//     } finally {
//       setIsUpdating(false);
//     }
//   };

//   const handleDeleteUser = async () => {
//     if (!selectedUser) return;

//     setIsDeleting(true);
//     try {
//       await dispatch(deleteUser(selectedUser._id)).unwrap();
//       dispatch(showSuccessToast('User deleted successfully'));
//       deleteModal.closeModal();
//       setSelectedUser(null);
//     } catch (error) {
//       dispatch(showErrorToast(error.message || 'Failed to delete user'));
//     } finally {
//       setIsDeleting(false);
//     }
//   };

//   const handleResetPassword = async () => {
//     if (!selectedUser) return;
    
//     if (passwordForm.newPassword !== passwordForm.confirmPassword) {
//       dispatch(showErrorToast('Passwords do not match'));
//       return;
//     }

//     setIsResettingPassword(true);
//     try {
//       await dispatch(resetUserPassword({
//         userId: selectedUser._id,
//         newPassword: passwordForm.newPassword
//       })).unwrap();
      
//       dispatch(showSuccessToast('Password reset successfully'));
//       passwordModal.closeModal();
//       setPasswordForm({ newPassword: '', confirmPassword: '' });
//       setSelectedUser(null);
//     } catch (error) {
//       dispatch(showErrorToast(error.message || 'Failed to reset password'));
//     } finally {
//       setIsResettingPassword(false);
//     }
//   };

//   const resetForm = () => {
//     setUserForm({
//       firstName: '',
//       lastName: '',
//       email: '',
//       phoneNumber: '',
//       role: '',
//       department: '',
//       password: '',
//       confirmPassword: ''
//     });
//   };

//   // Use search results if searching, otherwise use regular users
//   const displayUsers = searchTerm.trim() ? searchResults : users;

//   const filteredUsers = displayUsers.filter(user => {
//     if (selectedRole !== 'all' && user.role !== selectedRole) {
//       return false;
//     }
//     if (selectedStatus !== 'all' && user.status !== selectedStatus) {
//       return false;
//     }
//     return true;
//   });

//   const formatDate = (dateString) => {
//     if (!dateString) return 'N/A';
//     return new Date(dateString).toLocaleDateString('en-US', {
//       month: 'short',
//       day: 'numeric',
//       year: 'numeric'
//     });
//   };

//   const formatLastLogin = (dateString) => {
//     if (!dateString) return 'Never';
//     const now = new Date();
//     const loginDate = new Date(dateString);
//     const diffInHours = Math.floor((now - loginDate) / (1000 * 60 * 60));
    
//     if (diffInHours < 1) return 'Just now';
//     if (diffInHours < 24) return `${diffInHours}h ago`;
//     const diffInDays = Math.floor(diffInHours / 24);
//     if (diffInDays < 7) return `${diffInDays}d ago`;
//     return formatDate(dateString);
//   };

//   const getRoleBadge = (role) => {
//     const roleInfo = rolePermissions[role];
//     if (!roleInfo) return null;
    
//     return (
//       <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border ${roleInfo.color}`}>
//         <roleInfo.icon className="h-3 w-3" />
//         <span>{roleInfo.name}</span>
//       </span>
//     );
//   };

//   const getStatusBadge = (status) => {
//     const statusStyles = {
//       active: { bg: "bg-green-500/20", text: "text-green-300", border: "border-green-500/30", icon: CheckCircle },
//       inactive: { bg: "bg-gray-500/20", text: "text-gray-300", border: "border-gray-500/30", icon: XCircle },
//       suspended: { bg: "bg-red-500/20", text: "text-red-300", border: "border-red-500/30", icon: AlertTriangle }
//     };
    
//     const style = statusStyles[status] || statusStyles.inactive;
//     const IconComponent = style.icon;
    
//     return (
//       <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border ${style.bg} ${style.text} ${style.border}`}>
//         <IconComponent className="h-3 w-3" />
//         <span className="capitalize">{status}</span>
//       </span>
//     );
//   };

//   // Error state
//   if (error) {
//     return (
//       <AppLayout>
//         <div className="min-h-screen flex items-center justify-center">
//           <div className="text-center">
//             <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
//             <h2 className="text-xl font-semibold text-white mb-2">Error Loading Users</h2>
//             <p className="text-blue-200 mb-4">{error}</p>
//             <button
//               onClick={handleRefresh}
//               className="bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-colors"
//             >
//               Try Again
//             </button>
//           </div>
//         </div>
//       </AppLayout>
//     );
//   }

//   return (
//     <AppLayout>
//       {/* Add spacing from sidebar */}
//       <div className="pl-4">
//         {/* Header */}
//         <div className="bg-gradient-to-r from-white/10 to-white/5 backdrop-blur-md border-b border-white/20 mb-6 shadow-lg">
//         <div className="px-6 py-4">
//           <div className="flex items-center justify-between">
//             <div className="flex items-center space-x-4">
//               <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-2 rounded-xl shadow-lg">
//                 <Users className="h-6 w-6 text-white" />
//               </div>
//               <div>
//                 <h1 className="text-xl font-semibold text-white">User Management</h1>
//                 <p className="text-blue-200 text-sm">Manage system users, roles, and permissions</p>
//               </div>
//             </div>

//             <div className="flex items-center space-x-3">
//               <button
//                 onClick={handleRefresh}
//                 disabled={isLoading || isRefreshing}
//                 className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105"
//               >
//                 <RefreshCw className={`h-4 w-4 ${(isLoading || isRefreshing) ? 'animate-spin' : ''}`} />
//                 <span>Refresh</span>
//               </button>
//               <button className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105">
//                 <Download className="h-4 w-4" />
//                 <span>Export</span>
//               </button>
//               {currentUser?.role === USER_ROLES.ADMIN && (
//                 <button
//                   onClick={createModal.openModal}
//                   className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white transition-all duration-200 hover:scale-105 shadow-lg"
//                 >
//                   <Plus className="h-4 w-4" />
//                   <span>New User</span>
//                 </button>
//               )}
//             </div>
//           </div>
//         </div>
//       </div>

//       <div className="space-y-6">
//         {/* Search and Filters */}
//         <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg">
//           <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
//             <div className="relative flex-1 max-w-md">
//               <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
//               <input
//                 type="text"
//                 placeholder="Search users by name, email, ID..."
//                 value={searchTerm}
//                 onChange={(e) => setSearchTerm(e.target.value)}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               />
//             </div>

//             <div className="flex items-center space-x-4">
//               <select
//                 value={selectedRole}
//                 onChange={(e) => setSelectedRole(e.target.value)}
//                 className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               >
//                 <option value="all">All Roles</option>
//                 <option value="admin">Administrator</option>
//                 <option value="supervisor">Lab Supervisor</option>
//                 <option value="technician">Lab Technician</option>
//               </select>

//               <select
//                 value={selectedStatus}
//                 onChange={(e) => setSelectedStatus(e.target.value)}
//                 className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               >
//                 <option value="all">All Status</option>
//                 <option value="active">Active</option>
//                 <option value="inactive">Inactive</option>
//                 <option value="suspended">Suspended</option>
//               </select>

//               <span className="text-blue-200 text-sm">
//                 {filteredUsers.length} users
//               </span>
//             </div>
//           </div>
//         </div>

//         {/* Role Summary Cards */}
//         <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
//           {Object.entries(rolePermissions).map(([roleKey, roleInfo]) => {
//             const roleCount = filteredUsers.filter(user => user.role === roleKey).length;
//             return (
//               <div key={roleKey} className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300">
//                 <div className="flex items-center space-x-4">
//                   <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 shadow-lg">
//                     <roleInfo.icon className="h-6 w-6 text-white" />
//                   </div>
//                   <div>
//                     <h3 className="text-white font-medium">{roleInfo.name}</h3>
//                     <p className="text-blue-200 text-sm">{roleCount} users</p>
//                   </div>
//                 </div>
//               </div>
//             );
//           })}
//         </div>

//         {/* Users Table */}
//         <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl overflow-hidden shadow-lg">
//           {isLoading ? (
//             <div className="p-6">
//               <TableSkeletonLoader rows={10} columns={8} />
//             </div>
//           ) : filteredUsers.length === 0 ? (
//             <div className="text-center py-12">
//               <Users className="h-12 w-12 text-blue-400 mx-auto mb-4" />
//               <h3 className="text-lg font-medium text-white mb-2">No users found</h3>
//               <p className="text-blue-200 mb-6">
//                 {searchTerm || selectedRole !== 'all' || selectedStatus !== 'all'
//                   ? 'Try adjusting your search or filter criteria.'
//                   : 'No users have been created yet.'}
//               </p>
//               {currentUser?.role === USER_ROLES.ADMIN && (
//                 <button
//                   onClick={createModal.openModal}
//                   className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg transition-all duration-200 hover:scale-105 shadow-lg"
//                 >
//                   Create First User
//                 </button>
//               )}
//             </div>
//           ) : (
//             <div className="overflow-x-auto">
//               <table className="w-full">
//                 <thead className="bg-white/5 border-b border-white/20">
//                   <tr>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       User
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Role
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Department
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Status
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Last Login
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Tests Processed
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Created
//                     </th>
//                     <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
//                       Actions
//                     </th>
//                   </tr>
//                 </thead>
//                 <tbody className="divide-y divide-white/10">
//                   {filteredUsers.map((user) => (
//                     <tr key={user._id} className="hover:bg-white/5 transition-colors">
//                       <td className="px-6 py-4">
//                         <div className="flex items-center space-x-3">
//                           <div className="bg-gradient-to-br from-blue-500 to-blue-600 w-10 h-10 rounded-full flex items-center justify-center shadow-lg">
//                             <span className="text-white text-sm font-medium">
//                               {user.firstName?.[0]}{user.lastName?.[0]}
//                             </span>
//                           </div>
//                           <div>
//                             <div className="text-white font-medium">
//                               {user.firstName} {user.lastName}
//                             </div>
//                             <div className="text-blue-300 text-sm">{user.email}</div>
//                             <div className="text-blue-400 text-xs">{user.username || user._id}</div>
//                           </div>
//                         </div>
//                       </td>
//                       <td className="px-6 py-4">
//                         {getRoleBadge(user.role)}
//                       </td>
//                       <td className="px-6 py-4 text-sm text-blue-200">
//                         {user.department || 'Not assigned'}
//                       </td>
//                       <td className="px-6 py-4">
//                         {getStatusBadge(user.status || 'active')}
//                       </td>
//                       <td className="px-6 py-4 text-sm text-blue-200">
//                         {formatLastLogin(user.lastLogin)}
//                       </td>
//                       <td className="px-6 py-4 text-sm text-white">
//                         {user.testsProcessed > 0 ? user.testsProcessed.toLocaleString() : '-'}
//                       </td>
//                       <td className="px-6 py-4 text-sm text-blue-200">
//                         {formatDate(user.createdAt)}
//                       </td>
//                       <td className="px-6 py-4">
//                         <div className="flex items-center space-x-2">
//                           {/* Edit Role Button */}
//                           {currentUser?.role === USER_ROLES.ADMIN && (
//                             <button
//                               onClick={() => {
//                                 setSelectedUser(user);
//                                 setUserForm({
//                                   firstName: user.firstName || '',
//                                   lastName: user.lastName || '',
//                                   email: user.email || '',
//                                   phoneNumber: user.phoneNumber || '',
//                                   role: user.role || '',
//                                   department: user.department || '',
//                                   password: '',
//                                   confirmPassword: ''
//                                 });
//                                 editModal.openModal();
//                               }}
//                               className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
//                               title="Edit User"
//                             >
//                               <Edit className="h-4 w-4" />
//                             </button>
//                           )}
                          
//                           {/* Reset Password Button */}
//                           {currentUser?.role === USER_ROLES.ADMIN && (
//                             <button
//                               onClick={() => {
//                                 setSelectedUser(user);
//                                 passwordModal.openModal();
//                               }}
//                               className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors"
//                               title="Reset Password"
//                             >
//                               <Key className="h-4 w-4" />
//                             </button>
//                           )}
                          
//                           {/* Delete User Button */}
//                           {currentUser?.role === USER_ROLES.ADMIN && user._id !== currentUser._id && (
//                             <button
//                               onClick={() => {
//                                 setSelectedUser(user);
//                                 deleteModal.openModal();
//                               }}
//                               className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
//                               title="Delete User"
//                             >
//                               <Trash2 className="h-4 w-4" />
//                             </button>
//                           )}
                          
//                           <button className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
//                             <MoreHorizontal className="h-4 w-4" />
//                           </button>
//                         </div>
//                       </td>
//                     </tr>
//                   ))}
//                 </tbody>
//               </table>
//             </div>
//           )}
//         </div>
//       </div>

//       {/* Create User Modal */}
//       <FormModal
//         isOpen={createModal.isOpen}
//         onClose={createModal.closeModal}
//         onSubmit={(e) => {
//           e.preventDefault();
//           handleCreateUser();
//         }}
//         title="Create New User"
//         submitText="Create User"
//         loading={isCreating}
//       >
//         <div className="space-y-4">
//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">First Name *</label>
//               <input
//                 type="text"
//                 value={userForm.firstName}
//                 onChange={(e) => setUserForm({...userForm, firstName: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="Enter first name"
//                 required
//               />
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Last Name *</label>
//               <input
//                 type="text"
//                 value={userForm.lastName}
//                 onChange={(e) => setUserForm({...userForm, lastName: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="Enter last name"
//                 required
//               />
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Email Address *</label>
//               <input
//                 type="email"
//                 value={userForm.email}
//                 onChange={(e) => setUserForm({...userForm, email: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="user@malarialab.com"
//                 required
//               />
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Phone Number</label>
//               <input
//                 type="tel"
//                 value={userForm.phoneNumber}
//                 onChange={(e) => setUserForm({...userForm, phoneNumber: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="+250 788 123 456"
//               />
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Role *</label>
//               <select
//                 value={userForm.role}
//                 onChange={(e) => setUserForm({...userForm, role: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 required
//               >
//                 <option value="">Select role</option>
//                 <option value="admin">Administrator</option>
//                 <option value="supervisor">Lab Supervisor</option>
//                 <option value="technician">Lab Technician</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Department</label>
//               <select
//                 value={userForm.department}
//                 onChange={(e) => setUserForm({...userForm, department: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               >
//                 <option value="">Select department</option>
//                 <option value="Administration">Administration</option>
//                 <option value="Laboratory">Laboratory</option>
//                 <option value="Quality Control">Quality Control</option>
//                 <option value="IT Support">IT Support</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Password *</label>
//               <input
//                 type="password"
//                 value={userForm.password}
//                 onChange={(e) => setUserForm({...userForm, password: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="Enter secure password"
//                 required
//               />
//             </div>

//             <div>
//               <label className="block text-blue-200 text-sm font-medium mb-2">Confirm Password *</label>
//               <input
//                 type="password"
//                 value={userForm.confirmPassword}
//                 onChange={(e) => setUserForm({...userForm, confirmPassword: e.target.value})}
//                 className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//                 placeholder="Confirm password"
//                 required
//               />
//             </div>
//           </div>

//           {userForm.role && (
//             <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
//               <h4 className="text-white font-medium mb-2">Role Permissions</h4>
//               <ul className="text-blue-200 text-sm space-y-1">
//                 {rolePermissions[userForm.role]?.permissions.map((permission, index) => (
//                   <li key={index} className="flex items-center space-x-2">
//                     <CheckCircle className="h-3 w-3 text-green-400 flex-shrink-0" />
//                     <span>{permission}</span>
//                   </li>
//                 ))}
//               </ul>
//             </div>
//           )}
//         </div>
//       </FormModal>

//       {/* Edit User Modal */}
//       <FormModal
//         isOpen={editModal.isOpen}
//         onClose={() => {
//           editModal.closeModal();
//           setSelectedUser(null);
//           resetForm();
//         }}
//         onSubmit={(e) => {
//           e.preventDefault();
//           handleUpdateUser();
//         }}
//         title="Edit User Role"
//         submitText="Update User"
//         loading={isUpdating}
//       >
//         <div className="space-y-4">
//           <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
//             <h4 className="text-white font-medium mb-2">User Information</h4>
//             <p className="text-blue-200 text-sm">
//               {selectedUser?.firstName} {selectedUser?.lastName} ({selectedUser?.email})
//             </p>
//           </div>

//           <div>
//             <label className="block text-blue-200 text-sm font-medium mb-2">Role *</label>
//             <select
//               value={userForm.role}
//               onChange={(e) => setUserForm({...userForm, role: e.target.value})}
//               className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               required
//             >
//               <option value="">Select role</option>
//               <option value="admin">Administrator</option>
//               <option value="supervisor">Lab Supervisor</option>
//               <option value="technician">Lab Technician</option>
//             </select>
//           </div>

//           {userForm.role && (
//             <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
//               <h4 className="text-white font-medium mb-2">Role Permissions</h4>
//               <ul className="text-blue-200 text-sm space-y-1">
//                 {rolePermissions[userForm.role]?.permissions.map((permission, index) => (
//                   <li key={index} className="flex items-center space-x-2">
//                     <CheckCircle className="h-3 w-3 text-green-400 flex-shrink-0" />
//                     <span>{permission}</span>
//                   </li>
//                 ))}
//               </ul>
//             </div>
//           )}
//         </div>
//       </FormModal>

//       {/* Reset Password Modal */}
//       <FormModal
//         isOpen={passwordModal.isOpen}
//         onClose={() => {
//           passwordModal.closeModal();
//           setSelectedUser(null);
//           setPasswordForm({ newPassword: '', confirmPassword: '' });
//         }}
//         onSubmit={(e) => {
//           e.preventDefault();
//           handleResetPassword();
//         }}
//         title="Reset User Password"
//         submitText="Reset Password"
//         loading={isResettingPassword}
//       >
//         <div className="space-y-4">
//           <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
//             <div className="flex items-center space-x-2">
//               <AlertTriangle className="h-4 w-4 text-yellow-400" />
//               <h4 className="text-white font-medium">Reset Password for:</h4>
//             </div>
//             <p className="text-blue-200 text-sm mt-1">
//               {selectedUser?.firstName} {selectedUser?.lastName} ({selectedUser?.email})
//             </p>
//           </div>

//           <div>
//             <label className="block text-blue-200 text-sm font-medium mb-2">New Password *</label>
//             <input
//               type="password"
//               value={passwordForm.newPassword}
//               onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
//               className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               placeholder="Enter new password"
//               required
//             />
//           </div>

//           <div>
//             <label className="block text-blue-200 text-sm font-medium mb-2">Confirm New Password *</label>
//             <input
//               type="password"
//               value={passwordForm.confirmPassword}
//               onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
//               className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
//               placeholder="Confirm new password"
//               required
//             />
//           </div>
//         </div>
//       </FormModal>

//       {/* Delete User Confirmation Modal */}
//       <ConfirmModal
//         isOpen={deleteModal.isOpen}
//         onClose={() => {
//           deleteModal.closeModal();
//           setSelectedUser(null);
//         }}
//         onConfirm={handleDeleteUser}
//         title="Delete User"
//         message={`Are you sure you want to delete ${selectedUser?.firstName} ${selectedUser?.lastName}? This action cannot be undone and will permanently remove their account and all associated data.`}
//         confirmText="Delete User"
//         type="error"
//         loading={isDeleting}
//       />
//       </div>
//     </AppLayout>
//   );
// };

// export default UserManagementPage;
// src/pages/UserManagementPage.jsx - ENHANCED WITH LIVE TEST STATISTICS
import React, { useState, useEffect, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
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
  Microscope,
  RefreshCw,
  AlertCircle,
  TrendingUp,
  TrendingDown,
  Award,
  Target,
  BarChart3,
  Activity,
  Zap,
  Star,
  Timer,
  CheckCircle2,
  XCircle2,
  Clock4,
  Archive,
  Minus
} from 'lucide-react';

// Redux imports - ENHANCED
import {
  fetchUsers,
  searchUsers,
  fetchUserStatistics,
  fetchTopPerformers,
  updateUserRole,
  toggleUserStatus,
  deleteUser,
  resetUserPassword,
  clearUsersError,
  clearUsersSearchResults,
  clearUsersSuccessMessage,
  selectUsers,
  selectUsersLoading,
  selectUsersError,
  selectUsersPagination,
  selectUsersSearchResults,
  selectSystemStatistics,
  selectStatisticsLoading,
  selectTopPerformers,
  selectTopPerformersLoading,
  selectUsersSuccessMessage,
  selectIsUpdatingRole,
  selectIsTogglingStatus,
  selectIsDeleting,
  selectIsResettingPassword,
  selectUsersStatistics
} from '../store/slices/usersSlice';

import { showSuccessToast, showErrorToast, showWarningToast } from '../store/slices/notificationsSlice';
import { selectUser } from '../store/slices/authSlice';

// Components
import AppLayout from '../components/layout/AppLayout';
import LoadingSpinner, { TableSkeletonLoader, CardLoader } from '../components/common/LoadingSpinner';
import { ConfirmModal, AlertModal, FormModal, useModal } from '../components/common/Modal';

// Services
import apiService from '../services/api';

// Utils
import { USER_ROLES } from '../utils/constants';

const UserManagementPage = () => {
  const dispatch = useDispatch();
  
  // Redux state - ENHANCED
  const users = useSelector(selectUsers);
  const isLoading = useSelector(selectUsersLoading);
  const error = useSelector(selectUsersError);
  const pagination = useSelector(selectUsersPagination);
  const searchResults = useSelector(selectUsersSearchResults);
  const systemStatistics = useSelector(selectSystemStatistics);
  const isLoadingStatistics = useSelector(selectStatisticsLoading);
  const topPerformers = useSelector(selectTopPerformers);
  const isLoadingTopPerformers = useSelector(selectTopPerformersLoading);
  const currentUser = useSelector(selectUser);
  const successMessage = useSelector(selectUsersSuccessMessage);
  const pageStatistics = useSelector(selectUsersStatistics);
  
  // Action loading states
  const isUpdatingRole = useSelector(selectIsUpdatingRole);
  const isTogglingStatus = useSelector(selectIsTogglingStatus);
  const isDeletingUser = useSelector(selectIsDeleting);
  const isResettingPassword = useSelector(selectIsResettingPassword);

  // Local state
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [selectedUser, setSelectedUser] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [showStatistics, setShowStatistics] = useState(true);
  const [viewMode, setViewMode] = useState('table'); // 'table' or 'cards'

  // Modal states
  const createModal = useModal();
  const editModal = useModal();
  const deleteModal = useModal();
  const passwordModal = useModal();
  const statusModal = useModal();

  // Form state for create/edit
  const [userForm, setUserForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phoneNumber: '',
    role: '',
    department: '',
    password: '',
    confirmPassword: ''
  });

  // Password reset form
  const [passwordForm, setPasswordForm] = useState({
    newPassword: '',
    confirmPassword: ''
  });

  const [isCreating, setIsCreating] = useState(false);

  const rolePermissions = {
    admin: {
      name: 'Administrator',
      color: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
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
      color: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
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
      color: 'bg-green-500/20 text-green-300 border-green-500/30',
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

  // ✅ ENHANCED: Load all data on mount
  useEffect(() => {
    loadAllData();
  }, []);

  // Load users when filters change
  useEffect(() => {
    loadUsers();
  }, [currentPage, selectedRole, selectedStatus]);

  // Handle search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchTerm.trim()) {
        handleSearch();
      } else {
        dispatch(clearUsersSearchResults());
        loadUsers();
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Show success messages
  useEffect(() => {
    if (successMessage) {
      dispatch(showSuccessToast(successMessage));
      setTimeout(() => {
        dispatch(clearUsersSuccessMessage());
      }, 3000);
    }
  }, [successMessage, dispatch]);

  // ✅ ENHANCED: Load comprehensive data
  const loadAllData = async () => {
    try {
      // Load users, statistics, and top performers in parallel
      await Promise.all([
        dispatch(fetchUsers({
          page: currentPage,
          limit: 20,
          role: selectedRole !== 'all' ? selectedRole : undefined,
          status: selectedStatus !== 'all' ? selectedStatus : undefined
        })),
        dispatch(fetchUserStatistics()),
        dispatch(fetchTopPerformers(5))
      ]);
    } catch (error) {
      dispatch(showErrorToast('Failed to load user management data'));
    }
  };

  const loadUsers = useCallback(async () => {
    const params = {
      page: currentPage,
      limit: 20,
      role: selectedRole !== 'all' ? selectedRole : undefined,
      status: selectedStatus !== 'all' ? selectedStatus : undefined
    };

    try {
      await dispatch(fetchUsers(params)).unwrap();
    } catch (error) {
      dispatch(showErrorToast(error || 'Failed to load users'));
    }
  }, [dispatch, currentPage, selectedRole, selectedStatus]);

  const handleSearch = useCallback(async () => {
    if (!searchTerm.trim()) return;
    
    try {
      await dispatch(searchUsers({ 
        query: searchTerm.trim(),
        params: {
          role: selectedRole !== 'all' ? selectedRole : undefined,
          status: selectedStatus !== 'all' ? selectedStatus : undefined
        }
      })).unwrap();
    } catch (error) {
      dispatch(showErrorToast('Search failed'));
    }
  }, [dispatch, searchTerm, selectedRole, selectedStatus]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    dispatch(clearUsersError());
    await loadAllData();
    setIsRefreshing(false);
    dispatch(showSuccessToast('Data refreshed successfully'));
  };

  const handleCreateUser = async () => {
    // Validate form
    if (!userForm.firstName || !userForm.lastName || !userForm.email || !userForm.role) {
      dispatch(showErrorToast('Please fill in all required fields'));
      return;
    }

    if (userForm.password !== userForm.confirmPassword) {
      dispatch(showErrorToast('Passwords do not match'));
      return;
    }

    setIsCreating(true);
    try {
      const userData = {
        firstName: userForm.firstName,
        lastName: userForm.lastName,
        email: userForm.email,
        phoneNumber: userForm.phoneNumber,
        role: userForm.role,
        department: userForm.department,
        password: userForm.password
      };

      const response = await apiService.auth.register(userData);
      
      if (response.success) {
        dispatch(showSuccessToast('User created successfully'));
        createModal.closeModal();
        resetForm();
        await loadAllData(); // Refresh all data
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message || 'Failed to create user';
      dispatch(showErrorToast(errorMessage));
    } finally {
      setIsCreating(false);
    }
  };

  const handleUpdateUser = async () => {
    if (!selectedUser) return;

    try {
      await dispatch(updateUserRole({ 
        userId: selectedUser._id, 
        role: userForm.role 
      })).unwrap();
      
      editModal.closeModal();
      resetForm();
      setSelectedUser(null);
      // Success message handled by Redux
    } catch (error) {
      dispatch(showErrorToast(error || 'Failed to update user'));
    }
  };

  // ✅ ENHANCED: Toggle user status (safer than deletion)
  const handleToggleUserStatus = async () => {
    if (!selectedUser) return;

    try {
      await dispatch(toggleUserStatus(selectedUser._id)).unwrap();
      statusModal.closeModal();
      setSelectedUser(null);
      // Success message handled by Redux
    } catch (error) {
      dispatch(showErrorToast(error || 'Failed to toggle user status'));
    }
  };

  const handleDeleteUser = async () => {
    if (!selectedUser) return;

    try {
      await dispatch(deleteUser(selectedUser._id)).unwrap();
      deleteModal.closeModal();
      setSelectedUser(null);
      // Success message handled by Redux
    } catch (error) {
      dispatch(showErrorToast(error || 'Failed to delete user'));
    }
  };

  const handleResetPassword = async () => {
    if (!selectedUser) return;
    
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      dispatch(showErrorToast('Passwords do not match'));
      return;
    }

    try {
      await dispatch(resetUserPassword({
        userId: selectedUser._id,
        newPassword: passwordForm.newPassword
      })).unwrap();
      
      passwordModal.closeModal();
      setPasswordForm({ newPassword: '', confirmPassword: '' });
      setSelectedUser(null);
      // Success message handled by Redux
    } catch (error) {
      dispatch(showErrorToast(error || 'Failed to reset password'));
    }
  };

  const resetForm = () => {
    setUserForm({
      firstName: '',
      lastName: '',
      email: '',
      phoneNumber: '',
      role: '',
      department: '',
      password: '',
      confirmPassword: ''
    });
  };

  // Use search results if searching, otherwise use regular users
  const displayUsers = searchTerm.trim() ? searchResults : users;

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const formatLastLogin = (dateString) => {
    if (!dateString) return 'Never';
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
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border ${roleInfo.color}`}>
        <roleInfo.icon className="h-3 w-3" />
        <span>{roleInfo.name}</span>
      </span>
    );
  };

  // ✅ ENHANCED: Status badge with isActive instead of status
  const getStatusBadge = (isActive) => {
    const statusInfo = isActive ? {
      bg: "bg-green-500/20",
      text: "text-green-300", 
      border: "border-green-500/30",
      icon: CheckCircle,
      label: "Active"
    } : {
      bg: "bg-gray-500/20",
      text: "text-gray-300",
      border: "border-gray-500/30", 
      icon: XCircle,
      label: "Inactive"
    };
    
    const IconComponent = statusInfo.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border ${statusInfo.bg} ${statusInfo.text} ${statusInfo.border}`}>
        <IconComponent className="h-3 w-3" />
        <span>{statusInfo.label}</span>
      </span>
    );
  };

  // ✅ ENHANCED: Get test performance badge
  const getPerformanceBadge = (user) => {
    if (!user.testsProcessed || user.testsProcessed === 0) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border bg-gray-500/20 text-gray-300 border-gray-500/30">
          <Minus className="h-3 w-3" />
          <span>No tests</span>
        </span>
      );
    }

    let badge = { bg: '', text: '', border: '', icon: Target, label: '' };
    
    if (user.successRate >= 95) {
      badge = { bg: 'bg-green-500/20', text: 'text-green-300', border: 'border-green-500/30', icon: Star, label: 'Excellent' };
    } else if (user.successRate >= 85) {
      badge = { bg: 'bg-blue-500/20', text: 'text-blue-300', border: 'border-blue-500/30', icon: TrendingUp, label: 'Good' };
    } else if (user.successRate >= 70) {
      badge = { bg: 'bg-yellow-500/20', text: 'text-yellow-300', border: 'border-yellow-500/30', icon: Target, label: 'Average' };
    } else {
      badge = { bg: 'bg-red-500/20', text: 'text-red-300', border: 'border-red-500/30', icon: TrendingDown, label: 'Needs Improvement' };
    }

    const IconComponent = badge.icon;
    
    return (
      <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg text-xs font-medium border ${badge.bg} ${badge.text} ${badge.border}`}>
        <IconComponent className="h-3 w-3" />
        <span>{badge.label}</span>
      </span>
    );
  };

  // Error state
  if (error) {
    return (
      <AppLayout>
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-white mb-2">Error Loading Users</h2>
            <p className="text-blue-200 mb-4">{error}</p>
            <button
              onClick={handleRefresh}
              className="bg-white text-blue-600 px-6 py-3 rounded-lg font-medium hover:bg-blue-50 transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="pl-4">
        {/* Header */}
        <div className="bg-gradient-to-r from-white/10 to-white/5 backdrop-blur-md border-b border-white/20 mb-6 shadow-lg">
          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-2 rounded-xl shadow-lg">
                  <Users className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-semibold text-white">User Management</h1>
                  <p className="text-blue-200 text-sm">Manage system users, roles, and performance metrics</p>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <button
                  onClick={() => setShowStatistics(!showStatistics)}
                  className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105"
                >
                  <BarChart3 className="h-4 w-4" />
                  <span>{showStatistics ? 'Hide Stats' : 'Show Stats'}</span>
                </button>
                <button
                  onClick={handleRefresh}
                  disabled={isLoading || isRefreshing}
                  className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105"
                >
                  <RefreshCw className={`h-4 w-4 ${(isLoading || isRefreshing) ? 'animate-spin' : ''}`} />
                  <span>Refresh</span>
                </button>
                <button className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-all duration-200 hover:scale-105">
                  <Download className="h-4 w-4" />
                  <span>Export</span>
                </button>
                {currentUser?.role === USER_ROLES.ADMIN && (
                  <button
                    onClick={createModal.openModal}
                    className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg text-white transition-all duration-200 hover:scale-105 shadow-lg"
                  >
                    <Plus className="h-4 w-4" />
                    <span>New User</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          {/* ✅ ENHANCED: Statistics Dashboard */}
          {showStatistics && (
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              {/* System Overview */}
              <div className="lg:col-span-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center space-x-4">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500 to-blue-600 shadow-lg">
                        <Users className="h-6 w-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">Total Users</h3>
                        <p className="text-2xl font-bold text-blue-300">
                          {isLoadingStatistics ? <CardLoader /> : systemStatistics.totalUsers.toLocaleString()}
                        </p>
                        <p className="text-xs text-blue-200">
                          {systemStatistics.activeUsers} active, {systemStatistics.inactiveUsers} inactive
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center space-x-4">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-green-500 to-green-600 shadow-lg">
                        <Activity className="h-6 w-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">Tests Processed</h3>
                        <p className="text-2xl font-bold text-green-300">
                          {isLoadingStatistics ? <CardLoader /> : systemStatistics.totalTestsProcessed.toLocaleString()}
                        </p>
                        <p className="text-xs text-blue-200">
                          {systemStatistics.avgTestsPerUser} avg per user
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center space-x-4">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500 to-purple-600 shadow-lg">
                        <Target className="h-6 w-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">Success Rate</h3>
                        <p className="text-2xl font-bold text-purple-300">
                          {isLoadingStatistics ? <CardLoader /> : `${systemStatistics.overallSuccessRate}%`}
                        </p>
                        <p className="text-xs text-blue-200">
                          {systemStatistics.totalCompletedTests} completed tests
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center space-x-4">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-orange-500 to-orange-600 shadow-lg">
                        <Clock4 className="h-6 w-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">Pending Tests</h3>
                        <p className="text-2xl font-bold text-orange-300">
                          {isLoadingStatistics ? <CardLoader /> : systemStatistics.totalPendingTests.toLocaleString()}
                        </p>
                        <p className="text-xs text-blue-200">
                          {systemStatistics.totalFailedTests} failed tests
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Role Distribution & Top Performers */}
              <div className="lg:col-span-2">
                <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300 h-full">
                  <h3 className="text-white font-medium mb-4 flex items-center space-x-2">
                    <Crown className="h-5 w-5 text-yellow-400" />
                    <span>Role Distribution</span>
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(rolePermissions).map(([roleKey, roleInfo]) => {
                      const count = roleKey === 'admin' ? systemStatistics.adminCount :
                                   roleKey === 'supervisor' ? systemStatistics.supervisorCount :
                                   systemStatistics.technicianCount;
                      const percentage = systemStatistics.totalUsers > 0 ? 
                        (count / systemStatistics.totalUsers * 100).toFixed(1) : 0;
                      
                      return (
                        <div key={roleKey} className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <roleInfo.icon className="h-4 w-4 text-blue-300" />
                            <span className="text-blue-200 text-sm">{roleInfo.name}</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-white font-medium">{count}</span>
                            <span className="text-blue-300 text-xs">({percentage}%)</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-2">
                <div className="bg-gradient-to-br from-white/10 to-white/5 backdrop-blur-md border border-white/20 rounded-xl p-6 hover:shadow-xl transition-all duration-300 h-full">
                  <h3 className="text-white font-medium mb-4 flex items-center space-x-2">
                    <Star className="h-5 w-5 text-yellow-400" />
                    <span>Top Performers</span>
                  </h3>
                  {isLoadingTopPerformers ? (
                    <div className="space-y-3">
                      {[1,2,3].map(i => (
                        <div key={i} className="animate-pulse">
                          <div className="flex items-center space-x-3">
                            <div className="w-8 h-8 bg-white/10 rounded-full"></div>
                            <div className="flex-1">
                              <div className="h-3 bg-white/10 rounded mb-1"></div>
                              <div className="h-2 bg-white/10 rounded w-3/4"></div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {topPerformers.slice(0, 5).map((performer, index) => (
                        <div key={performer._id} className="flex items-center space-x-3">
                          <div className="flex items-center justify-center w-8 h-8 rounded-full bg-gradient-to-br from-yellow-500 to-yellow-600 text-white text-xs font-bold">
                            {index + 1}
                          </div>
                          <div className="flex-1">
                            <p className="text-white text-sm font-medium">{performer.fullName}</p>
                            <p className="text-blue-200 text-xs">
                              {performer.testsProcessed} tests • {performer.successRate}% success
                            </p>
                          </div>
                          <div className="text-yellow-400 text-sm font-medium">
                            {performer.performanceScore}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Search and Filters */}
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl p-6 shadow-lg">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
                <input
                  type="text"
                  placeholder="Search users by name, email, ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                />
              </div>

              <div className="flex items-center space-x-4">
                <select
                  value={selectedRole}
                  onChange={(e) => setSelectedRole(e.target.value)}
                  className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                >
                  <option value="all">All Roles</option>
                  <option value="admin">Administrator</option>
                  <option value="supervisor">Lab Supervisor</option>
                  <option value="technician">Lab Technician</option>
                </select>

                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                >
                  <option value="all">All Status</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>

                <span className="text-blue-200 text-sm">
                  {displayUsers.length} users
                </span>
              </div>
            </div>
          </div>

          {/* Users Table */}
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-xl overflow-hidden shadow-lg">
            {isLoading ? (
              <div className="p-6">
                <TableSkeletonLoader rows={10} columns={9} />
              </div>
            ) : displayUsers.length === 0 ? (
              <div className="text-center py-12">
                <Users className="h-12 w-12 text-blue-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-white mb-2">No users found</h3>
                <p className="text-blue-200 mb-6">
                  {searchTerm || selectedRole !== 'all' || selectedStatus !== 'all'
                    ? 'Try adjusting your search or filter criteria.'
                    : 'No users have been created yet.'}
                </p>
                {currentUser?.role === USER_ROLES.ADMIN && (
                  <button
                    onClick={createModal.openModal}
                    className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white rounded-lg transition-all duration-200 hover:scale-105 shadow-lg"
                  >
                    Create First User
                  </button>
                )}
              </div>
            ) : (
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
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                        Tests Processed
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                        Success Rate
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                        Performance
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                        Last Login
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-blue-200 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/10">
                    {displayUsers.map((user) => (
                      <tr key={user._id} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center space-x-3">
                            <div className="bg-gradient-to-br from-blue-500 to-blue-600 w-10 h-10 rounded-full flex items-center justify-center shadow-lg">
                              <span className="text-white text-sm font-medium">
                                {user.firstName?.[0]}{user.lastName?.[0]}
                              </span>
                            </div>
                            <div>
                              <div className="text-white font-medium">
                                {user.firstName} {user.lastName}
                              </div>
                              <div className="text-blue-300 text-sm">{user.email}</div>
                              <div className="text-blue-400 text-xs">{user.department || 'Not assigned'}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {getRoleBadge(user.role)}
                        </td>
                        <td className="px-6 py-4">
                          {getStatusBadge(user.isActive)}
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-white font-medium">
                            {user.testsProcessed > 0 ? user.testsProcessed.toLocaleString() : '-'}
                          </div>
                          {user.testsProcessed > 0 && (
                            <div className="text-blue-300 text-xs">
                              {user.completedTests || 0} completed • {user.pendingTests || 0} pending
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-white font-medium">
                            {user.testsProcessed > 0 ? `${user.successRate || 0}%` : '-'}
                          </div>
                          {user.avgProcessingTime && (
                            <div className="text-blue-300 text-xs">
                              {user.avgProcessingTime}m avg time
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          {getPerformanceBadge(user)}
                        </td>
                        <td className="px-6 py-4 text-sm text-blue-200">
                          {formatLastLogin(user.lastLogin)}
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center space-x-2">
                            {/* Edit Role Button */}
                            {currentUser?.role === USER_ROLES.ADMIN && (
                              <button
                                onClick={() => {
                                  setSelectedUser(user);
                                  setUserForm({
                                    firstName: user.firstName || '',
                                    lastName: user.lastName || '',
                                    email: user.email || '',
                                    phoneNumber: user.phoneNumber || '',
                                    role: user.role || '',
                                    department: user.department || '',
                                    password: '',
                                    confirmPassword: ''
                                  });
                                  editModal.openModal();
                                }}
                                disabled={isUpdatingRole}
                                className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors disabled:opacity-50"
                                title="Edit User"
                              >
                                <Edit className="h-4 w-4" />
                              </button>
                            )}
                            
                            {/* Toggle Status Button */}
                            {currentUser?.role === USER_ROLES.ADMIN && user._id !== currentUser._id && (
                              <button
                                onClick={() => {
                                  setSelectedUser(user);
                                  statusModal.openModal();
                                }}
                                disabled={isTogglingStatus}
                                className="p-1 text-yellow-400 hover:text-yellow-300 hover:bg-yellow-500/10 rounded transition-colors disabled:opacity-50"
                                title={user.isActive ? "Deactivate User" : "Activate User"}
                              >
                                {user.isActive ? <UserX className="h-4 w-4" /> : <UserCheck className="h-4 w-4" />}
                              </button>
                            )}
                            
                            {/* Reset Password Button */}
                            {currentUser?.role === USER_ROLES.ADMIN && (
                              <button
                                onClick={() => {
                                  setSelectedUser(user);
                                  passwordModal.openModal();
                                }}
                                disabled={isResettingPassword}
                                className="p-1 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors disabled:opacity-50"
                                title="Reset Password"
                              >
                                <Key className="h-4 w-4" />
                              </button>
                            )}
                            
                            {/* Delete User Button */}
                            {currentUser?.role === USER_ROLES.ADMIN && user._id !== currentUser._id && (
                              <button
                                onClick={() => {
                                  setSelectedUser(user);
                                  deleteModal.openModal();
                                }}
                                disabled={isDeletingUser}
                                className="p-1 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors disabled:opacity-50"
                                title="Delete User"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Create User Modal */}
        <FormModal
          isOpen={createModal.isOpen}
          onClose={createModal.closeModal}
          onSubmit={(e) => {
            e.preventDefault();
            handleCreateUser();
          }}
          title="Create New User"
          submitText="Create User"
          loading={isCreating}
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">First Name *</label>
                <input
                  type="text"
                  value={userForm.firstName}
                  onChange={(e) => setUserForm({...userForm, firstName: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="Enter first name"
                  required
                />
              </div>

              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">Last Name *</label>
                <input
                  type="text"
                  value={userForm.lastName}
                  onChange={(e) => setUserForm({...userForm, lastName: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="Enter last name"
                  required
                />
              </div>

              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">Email Address *</label>
                <input
                  type="email"
                  value={userForm.email}
                  onChange={(e) => setUserForm({...userForm, email: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="user@malarialab.com"
                  required
                />
              </div>

              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">Phone Number</label>
                <input
                  type="tel"
                  value={userForm.phoneNumber}
                  onChange={(e) => setUserForm({...userForm, phoneNumber: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="+250 788 123 456"
                />
              </div>

              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">Role *</label>
                <select
                  value={userForm.role}
                  onChange={(e) => setUserForm({...userForm, role: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  required
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
                  value={userForm.department}
                  onChange={(e) => setUserForm({...userForm, department: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
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
                  value={userForm.password}
                  onChange={(e) => setUserForm({...userForm, password: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="Enter secure password"
                  required
                />
              </div>

              <div>
                <label className="block text-blue-200 text-sm font-medium mb-2">Confirm Password *</label>
                <input
                  type="password"
                  value={userForm.confirmPassword}
                  onChange={(e) => setUserForm({...userForm, confirmPassword: e.target.value})}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                  placeholder="Confirm password"
                  required
                />
              </div>
            </div>

            {userForm.role && (
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">Role Permissions</h4>
                <ul className="text-blue-200 text-sm space-y-1">
                  {rolePermissions[userForm.role]?.permissions.map((permission, index) => (
                    <li key={index} className="flex items-center space-x-2">
                      <CheckCircle className="h-3 w-3 text-green-400 flex-shrink-0" />
                      <span>{permission}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </FormModal>

        {/* Edit User Modal */}
        <FormModal
          isOpen={editModal.isOpen}
          onClose={() => {
            editModal.closeModal();
            setSelectedUser(null);
            resetForm();
          }}
          onSubmit={(e) => {
            e.preventDefault();
            handleUpdateUser();
          }}
          title="Edit User Role"
          submitText="Update User"
          loading={isUpdatingRole}
        >
          <div className="space-y-4">
            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">User Information</h4>
              <p className="text-blue-200 text-sm">
                {selectedUser?.firstName} {selectedUser?.lastName} ({selectedUser?.email})
              </p>
              {selectedUser?.testsProcessed > 0 && (
                <p className="text-blue-300 text-xs mt-1">
                  {selectedUser.testsProcessed} tests processed • {selectedUser.successRate}% success rate
                </p>
              )}
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Role *</label>
              <select
                value={userForm.role}
                onChange={(e) => setUserForm({...userForm, role: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                required
              >
                <option value="">Select role</option>
                <option value="admin">Administrator</option>
                <option value="supervisor">Lab Supervisor</option>
                <option value="technician">Lab Technician</option>
              </select>
            </div>

            {userForm.role && (
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">Role Permissions</h4>
                <ul className="text-blue-200 text-sm space-y-1">
                  {rolePermissions[userForm.role]?.permissions.map((permission, index) => (
                    <li key={index} className="flex items-center space-x-2">
                      <CheckCircle className="h-3 w-3 text-green-400 flex-shrink-0" />
                      <span>{permission}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </FormModal>

        {/* Reset Password Modal */}
        <FormModal
          isOpen={passwordModal.isOpen}
          onClose={() => {
            passwordModal.closeModal();
            setSelectedUser(null);
            setPasswordForm({ newPassword: '', confirmPassword: '' });
          }}
          onSubmit={(e) => {
            e.preventDefault();
            handleResetPassword();
          }}
          title="Reset User Password"
          submitText="Reset Password"
          loading={isResettingPassword}
        >
          <div className="space-y-4">
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 text-yellow-400" />
                <h4 className="text-white font-medium">Reset Password for:</h4>
              </div>
              <p className="text-blue-200 text-sm mt-1">
                {selectedUser?.firstName} {selectedUser?.lastName} ({selectedUser?.email})
              </p>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">New Password *</label>
              <input
                type="password"
                value={passwordForm.newPassword}
                onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="Enter new password"
                required
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Confirm New Password *</label>
              <input
                type="password"
                value={passwordForm.confirmPassword}
                onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent transition-all"
                placeholder="Confirm new password"
                required
              />
            </div>
          </div>
        </FormModal>

        {/* Toggle Status Confirmation Modal */}
        <ConfirmModal
          isOpen={statusModal.isOpen}
          onClose={() => {
            statusModal.closeModal();
            setSelectedUser(null);
          }}
          onConfirm={handleToggleUserStatus}
          title={selectedUser?.isActive ? "Deactivate User" : "Activate User"}
          message={`Are you sure you want to ${selectedUser?.isActive ? 'deactivate' : 'activate'} ${selectedUser?.firstName} ${selectedUser?.lastName}? ${selectedUser?.isActive ? 'They will no longer be able to access the system.' : 'They will be able to access the system again.'}`}
          confirmText={selectedUser?.isActive ? "Deactivate" : "Activate"}
          type={selectedUser?.isActive ? "warning" : "success"}
          loading={isTogglingStatus}
        />

        {/* Delete User Confirmation Modal */}
        <ConfirmModal
          isOpen={deleteModal.isOpen}
          onClose={() => {
            deleteModal.closeModal();
            setSelectedUser(null);
          }}
          onConfirm={handleDeleteUser}
          title="Delete User"
          message={`Are you sure you want to delete ${selectedUser?.firstName} ${selectedUser?.lastName}? This action cannot be undone and will permanently remove their account and all associated data.${selectedUser?.testsProcessed > 0 ? ` This user has processed ${selectedUser.testsProcessed} tests.` : ''}`}
          confirmText="Delete User"
          type="error"
          loading={isDeletingUser}
        />
      </div>
    </AppLayout>
  );
};

export default UserManagementPage;
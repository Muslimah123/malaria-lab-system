// // 📁 client/src/store/slices/usersSlice.js
// // User management slice for admin operations

// import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
// import apiService from '../../services/api';

// // Async thunks
// export const fetchUsers = createAsyncThunk(
//   'users/fetchUsers',
//   async (params = {}, { rejectWithValue }) => {
//     try {
//       const response = await apiService.users.getAll(params);
//       return response;
//     } catch (error) {
//       return rejectWithValue(error.message);
//     }
//   }
// );

// export const searchUsers = createAsyncThunk(
//   'users/searchUsers',
//   async ({ query, params = {} }, { rejectWithValue }) => {
//     try {
//       const response = await apiService.users.search(query, params);
//       return response;
//     } catch (error) {
//       return rejectWithValue(error.message);
//     }
//   }
// );

// export const updateUserRole = createAsyncThunk(
//   'users/updateUserRole',
//   async ({ userId, role }, { rejectWithValue }) => {
//     try {
//       const response = await apiService.users.updateRole(userId, role);
//       return { userId, role, data: response.data };
//     } catch (error) {
//       return rejectWithValue(error.message);
//     }
//   }
// );

// export const deleteUser = createAsyncThunk(
//   'users/deleteUser',
//   async (userId, { rejectWithValue }) => {
//     try {
//       await apiService.users.delete(userId);
//       return userId;
//     } catch (error) {
//       return rejectWithValue(error.message);
//     }
//   }
// );

// export const resetUserPassword = createAsyncThunk(
//   'users/resetUserPassword',
//   async ({ userId, newPassword }, { rejectWithValue }) => {
//     try {
//       const response = await apiService.users.resetPassword(userId, newPassword);
//       return { userId, message: response.message };
//     } catch (error) {
//       return rejectWithValue(error.message);
//     }
//   }
// );

// // Initial state
// const initialState = {
//   users: [],
//   isLoading: false,
//   isSearching: false,
//   error: null,
//   searchError: null,
//   pagination: {
//     page: 1,
//     limit: 20,
//     total: 0,
//     pages: 0
//   },
//   searchResults: []
// };

// // Users slice
// const usersSlice = createSlice({
//   name: 'users',
//   initialState,
//   reducers: {
//     clearError: (state) => {
//       state.error = null;
//       state.searchError = null;
//     },
//     clearSearchResults: (state) => {
//       state.searchResults = [];
//       state.searchError = null;
//     }
//   },
//   extraReducers: (builder) => {
//     builder
//       // Fetch users
//       .addCase(fetchUsers.pending, (state) => {
//         state.isLoading = true;
//         state.error = null;
//       })
//       .addCase(fetchUsers.fulfilled, (state, action) => {
//         state.isLoading = false;
//         state.users = action.payload.data || [];
//         state.pagination = action.payload.pagination || initialState.pagination;
//       })
//       .addCase(fetchUsers.rejected, (state, action) => {
//         state.isLoading = false;
//         state.error = action.payload;
//       })
      
//       // Search users
//       .addCase(searchUsers.pending, (state) => {
//         state.isSearching = true;
//         state.searchError = null;
//       })
//       .addCase(searchUsers.fulfilled, (state, action) => {
//         state.isSearching = false;
//         state.searchResults = action.payload.data || [];
//       })
//       .addCase(searchUsers.rejected, (state, action) => {
//         state.isSearching = false;
//         state.searchError = action.payload;
//       })
      
//       // Update user role
//       .addCase(updateUserRole.fulfilled, (state, action) => {
//         const { userId, role } = action.payload;
//         const userIndex = state.users.findIndex(user => user._id === userId);
//         if (userIndex !== -1) {
//           state.users[userIndex].role = role;
//         }
//       })
      
//       // Delete user
//       .addCase(deleteUser.fulfilled, (state, action) => {
//         const userId = action.payload;
//         state.users = state.users.filter(user => user._id !== userId);
//       });
//   }
// });

// export const { clearError: clearUsersError, clearSearchResults: clearUsersSearchResults } = usersSlice.actions;

// // Selectors
// export const selectUsers = (state) => state.users.users;
// export const selectUsersLoading = (state) => state.users.isLoading;
// export const selectUsersError = (state) => state.users.error;
// export const selectUsersPagination = (state) => state.users.pagination;
// export const selectUsersSearchResults = (state) => state.users.searchResults;

// export default usersSlice.reducer;
// 📁 client/src/store/slices/usersSlice.js
// Enhanced User management slice with comprehensive statistics and analytics

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import apiService from '../../services/api';

// ✅ ENHANCED ASYNC THUNKS

// Fetch users with enhanced statistics and filtering
export const fetchUsers = createAsyncThunk(
  'users/fetchUsers',
  async (params = {}, { rejectWithValue }) => {
    try {
      console.log('🔄 Fetching users with params:', params);
      const response = await apiService.users.getAll(params);
      console.log('✅ Users fetched successfully:', response);
      return response;
    } catch (error) {
      console.error('❌ Fetch users error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Search users with enhanced filters
export const searchUsers = createAsyncThunk(
  'users/searchUsers',
  async ({ query, params = {} }, { rejectWithValue }) => {
    try {
      console.log('🔍 Searching users:', { query, params });
      const response = await apiService.users.search(query, params);
      console.log('✅ Search completed:', response);
      return { ...response, searchQuery: query };
    } catch (error) {
      console.error('❌ Search users error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Get comprehensive user statistics
export const fetchUserStatistics = createAsyncThunk(
  'users/fetchUserStatistics',
  async (_, { rejectWithValue }) => {
    try {
      console.log('📊 Fetching user statistics...');
      const response = await apiService.users.getStatistics();
      console.log('✅ Statistics fetched:', response);
      return response;
    } catch (error) {
      console.error('❌ Fetch statistics error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Get top performing users
export const fetchTopPerformers = createAsyncThunk(
  'users/fetchTopPerformers',
  async (limit = 10, { rejectWithValue }) => {
    try {
      console.log('🏆 Fetching top performers...');
      const response = await apiService.users.getTopPerformers(limit);
      console.log('✅ Top performers fetched:', response);
      return response;
    } catch (error) {
      console.error('❌ Fetch top performers error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Update user role
export const updateUserRole = createAsyncThunk(
  'users/updateUserRole',
  async ({ userId, role }, { rejectWithValue }) => {
    try {
      console.log('🔄 Updating user role:', { userId, role });
      const response = await apiService.users.updateRole(userId, role);
      console.log('✅ Role updated:', response);
      return { userId, role, data: response.data };
    } catch (error) {
      console.error('❌ Update role error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Toggle user status (active/inactive)
export const toggleUserStatus = createAsyncThunk(
  'users/toggleUserStatus',
  async (userId, { rejectWithValue }) => {
    try {
      console.log('🔄 Toggling user status:', userId);
      const response = await apiService.users.toggleStatus(userId);
      console.log('✅ Status toggled:', response);
      return { userId, data: response.data };
    } catch (error) {
      console.error('❌ Toggle status error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Reset user password
export const resetUserPassword = createAsyncThunk(
  'users/resetUserPassword',
  async ({ userId, newPassword }, { rejectWithValue }) => {
    try {
      console.log('🔑 Resetting password for user:', userId);
      const response = await apiService.users.resetPassword(userId, newPassword);
      console.log('✅ Password reset successful');
      return { userId, message: response.message };
    } catch (error) {
      console.error('❌ Reset password error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// Delete user (with safety checks)
export const deleteUser = createAsyncThunk(
  'users/deleteUser',
  async (userId, { rejectWithValue }) => {
    try {
      console.log('🗑️ Deleting user:', userId);
      const response = await apiService.users.delete(userId);
      console.log('✅ User deleted successfully');
      return { userId, message: response.message };
    } catch (error) {
      console.error('❌ Delete user error:', error);
      return rejectWithValue(apiService.formatError(error));
    }
  }
);

// ✅ ENHANCED INITIAL STATE
const initialState = {
  // Core user data
  users: [],
  isLoading: false,
  error: null,
  
  // Pagination
  pagination: {
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  },
  
  // Enhanced statistics from backend
  statistics: {
    totalUsers: 0,
    totalTestsProcessed: 0,
    averageTestsPerUser: 0,
    averageSuccessRate: 0
  },
  
  // System-wide user statistics
  systemStatistics: {
    totalUsers: 0,
    activeUsers: 0,
    inactiveUsers: 0,
    totalTestsProcessed: 0,
    totalCompletedTests: 0,
    totalPendingTests: 0,
    totalFailedTests: 0,
    avgTestsPerUser: 0,
    overallSuccessRate: 0,
    activeUserPercentage: 0,
    adminCount: 0,
    supervisorCount: 0,
    technicianCount: 0,
    usersWithNoTests: 0
  },
  isLoadingStatistics: false,
  statisticsError: null,
  
  // Top performers
  topPerformers: [],
  isLoadingTopPerformers: false,
  topPerformersError: null,
  
  // Search functionality
  searchResults: [],
  isSearching: false,
  searchError: null,
  lastSearchQuery: '',
  
  // UI state
  filters: {
    role: 'all',
    status: 'all'
  },
  selectedUsers: [],
  
  // Action states
  isUpdatingRole: false,
  isTogglingStatus: false,
  isResettingPassword: false,
  isDeleting: false,
  
  // Success messages
  successMessage: null,
  
  // Last updated timestamp
  lastUpdated: null
};

// ✅ ENHANCED USERS SLICE
const usersSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {
    // Clear various error states
    clearError: (state) => {
      state.error = null;
      state.searchError = null;
      state.statisticsError = null;
      state.topPerformersError = null;
    },
    
    // Clear search results
    clearSearchResults: (state) => {
      state.searchResults = [];
      state.searchError = null;
      state.lastSearchQuery = '';
    },
    
    // Clear success message
    clearSuccessMessage: (state) => {
      state.successMessage = null;
    },
    
    // Set filters
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    
    // Reset filters
    resetFilters: (state) => {
      state.filters = {
        role: 'all',
        status: 'all'
      };
    },
    
    // Select/deselect users for batch operations
    toggleUserSelection: (state, action) => {
      const userId = action.payload;
      const index = state.selectedUsers.indexOf(userId);
      if (index >= 0) {
        state.selectedUsers.splice(index, 1);
      } else {
        state.selectedUsers.push(userId);
      }
    },
    
    // Select all users
    selectAllUsers: (state) => {
      state.selectedUsers = state.users.map(user => user._id);
    },
    
    // Clear selection
    clearSelection: (state) => {
      state.selectedUsers = [];
    },
    
    // Update local user data (for optimistic updates)
    updateUserLocal: (state, action) => {
      const { userId, updates } = action.payload;
      const userIndex = state.users.findIndex(user => user._id === userId);
      if (userIndex >= 0) {
        state.users[userIndex] = { ...state.users[userIndex], ...updates };
      }
      
      // Also update in search results if present
      const searchIndex = state.searchResults.findIndex(user => user._id === userId);
      if (searchIndex >= 0) {
        state.searchResults[searchIndex] = { ...state.searchResults[searchIndex], ...updates };
      }
    }
  },
  
  extraReducers: (builder) => {
    builder
      // ✅ FETCH USERS
      .addCase(fetchUsers.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchUsers.fulfilled, (state, action) => {
        state.isLoading = false;
        state.users = action.payload.data || [];
        state.pagination = action.payload.pagination || initialState.pagination;
        state.statistics = action.payload.statistics || initialState.statistics;
        state.lastUpdated = new Date().toISOString();
        console.log('📦 Users state updated:', { 
          userCount: state.users.length, 
          pagination: state.pagination,
          statistics: state.statistics 
        });
      })
      .addCase(fetchUsers.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
        console.error('❌ Fetch users failed:', action.payload);
      })
      
      // ✅ SEARCH USERS
      .addCase(searchUsers.pending, (state) => {
        state.isSearching = true;
        state.searchError = null;
      })
      .addCase(searchUsers.fulfilled, (state, action) => {
        state.isSearching = false;
        state.searchResults = action.payload.data || [];
        state.lastSearchQuery = action.payload.searchQuery || '';
        console.log('🔍 Search results updated:', { 
          resultCount: state.searchResults.length,
          query: state.lastSearchQuery 
        });
      })
      .addCase(searchUsers.rejected, (state, action) => {
        state.isSearching = false;
        state.searchError = action.payload;
        console.error('❌ Search failed:', action.payload);
      })
      
      // ✅ FETCH STATISTICS
      .addCase(fetchUserStatistics.pending, (state) => {
        state.isLoadingStatistics = true;
        state.statisticsError = null;
      })
      .addCase(fetchUserStatistics.fulfilled, (state, action) => {
        state.isLoadingStatistics = false;
        state.systemStatistics = action.payload.data || initialState.systemStatistics;
        console.log('📊 Statistics updated:', state.systemStatistics);
      })
      .addCase(fetchUserStatistics.rejected, (state, action) => {
        state.isLoadingStatistics = false;
        state.statisticsError = action.payload;
        console.error('❌ Statistics fetch failed:', action.payload);
      })
      
      // ✅ FETCH TOP PERFORMERS
      .addCase(fetchTopPerformers.pending, (state) => {
        state.isLoadingTopPerformers = true;
        state.topPerformersError = null;
      })
      .addCase(fetchTopPerformers.fulfilled, (state, action) => {
        state.isLoadingTopPerformers = false;
        state.topPerformers = action.payload.data || [];
        console.log('🏆 Top performers updated:', { count: state.topPerformers.length });
      })
      .addCase(fetchTopPerformers.rejected, (state, action) => {
        state.isLoadingTopPerformers = false;
        state.topPerformersError = action.payload;
        console.error('❌ Top performers fetch failed:', action.payload);
      })
      
      // ✅ UPDATE USER ROLE
      .addCase(updateUserRole.pending, (state) => {
        state.isUpdatingRole = true;
      })
      .addCase(updateUserRole.fulfilled, (state, action) => {
        state.isUpdatingRole = false;
        const { userId, role, data } = action.payload;
        
        // Update user in main list
        const userIndex = state.users.findIndex(user => user._id === userId);
        if (userIndex >= 0) {
          state.users[userIndex] = { ...state.users[userIndex], role, ...data };
        }
        
        // Update in search results if present
        const searchIndex = state.searchResults.findIndex(user => user._id === userId);
        if (searchIndex >= 0) {
          state.searchResults[searchIndex] = { ...state.searchResults[searchIndex], role, ...data };
        }
        
        state.successMessage = `User role updated to ${role}`;
        console.log('✅ Role updated locally:', { userId, role });
      })
      .addCase(updateUserRole.rejected, (state, action) => {
        state.isUpdatingRole = false;
        state.error = action.payload;
        console.error('❌ Role update failed:', action.payload);
      })
      
      // ✅ TOGGLE USER STATUS
      .addCase(toggleUserStatus.pending, (state) => {
        state.isTogglingStatus = true;
      })
      .addCase(toggleUserStatus.fulfilled, (state, action) => {
        state.isTogglingStatus = false;
        const { userId, data } = action.payload;
        
        // Update user in main list
        const userIndex = state.users.findIndex(user => user._id === userId);
        if (userIndex >= 0) {
          state.users[userIndex] = { ...state.users[userIndex], ...data };
        }
        
        // Update in search results if present
        const searchIndex = state.searchResults.findIndex(user => user._id === userId);
        if (searchIndex >= 0) {
          state.searchResults[searchIndex] = { ...state.searchResults[searchIndex], ...data };
        }
        
        state.successMessage = `User ${data.isActive ? 'activated' : 'deactivated'} successfully`;
        console.log('✅ Status toggled locally:', { userId, isActive: data.isActive });
      })
      .addCase(toggleUserStatus.rejected, (state, action) => {
        state.isTogglingStatus = false;
        state.error = action.payload;
        console.error('❌ Status toggle failed:', action.payload);
      })
      
      // ✅ RESET PASSWORD
      .addCase(resetUserPassword.pending, (state) => {
        state.isResettingPassword = true;
      })
      .addCase(resetUserPassword.fulfilled, (state, action) => {
        state.isResettingPassword = false;
        state.successMessage = action.payload.message;
        console.log('✅ Password reset completed');
      })
      .addCase(resetUserPassword.rejected, (state, action) => {
        state.isResettingPassword = false;
        state.error = action.payload;
        console.error('❌ Password reset failed:', action.payload);
      })
      
      // ✅ DELETE USER
      .addCase(deleteUser.pending, (state) => {
        state.isDeleting = true;
      })
      .addCase(deleteUser.fulfilled, (state, action) => {
        state.isDeleting = false;
        const userId = action.payload.userId;
        
        // Remove user from main list
        state.users = state.users.filter(user => user._id !== userId);
        
        // Remove from search results if present
        state.searchResults = state.searchResults.filter(user => user._id !== userId);
        
        // Remove from selection if selected
        state.selectedUsers = state.selectedUsers.filter(id => id !== userId);
        
        // Update pagination total
        if (state.pagination.total > 0) {
          state.pagination.total -= 1;
          state.pagination.pages = Math.ceil(state.pagination.total / state.pagination.limit);
        }
        
        state.successMessage = 'User deleted successfully';
        console.log('✅ User deleted locally:', userId);
      })
      .addCase(deleteUser.rejected, (state, action) => {
        state.isDeleting = false;
        state.error = action.payload;
        console.error('❌ Delete user failed:', action.payload);
      });
  }
});

// ✅ EXPORT ACTIONS
export const {
  clearError: clearUsersError,
  clearSearchResults: clearUsersSearchResults,
  clearSuccessMessage: clearUsersSuccessMessage,
  setFilters: setUsersFilters,
  resetFilters: resetUsersFilters,
  toggleUserSelection,
  selectAllUsers,
  clearSelection: clearUsersSelection,
  updateUserLocal
} = usersSlice.actions;

// ✅ ENHANCED SELECTORS
export const selectUsers = (state) => state.users.users;
export const selectUsersLoading = (state) => state.users.isLoading;
export const selectUsersError = (state) => state.users.error;
export const selectUsersPagination = (state) => state.users.pagination;
export const selectUsersStatistics = (state) => state.users.statistics;

// System statistics selectors
export const selectSystemStatistics = (state) => state.users.systemStatistics;
export const selectStatisticsLoading = (state) => state.users.isLoadingStatistics;
export const selectStatisticsError = (state) => state.users.statisticsError;

// Top performers selectors
export const selectTopPerformers = (state) => state.users.topPerformers;
export const selectTopPerformersLoading = (state) => state.users.isLoadingTopPerformers;
export const selectTopPerformersError = (state) => state.users.topPerformersError;

// Search selectors
export const selectUsersSearchResults = (state) => state.users.searchResults;
export const selectSearchLoading = (state) => state.users.isSearching;
export const selectSearchError = (state) => state.users.searchError;
export const selectLastSearchQuery = (state) => state.users.lastSearchQuery;

// Filter and UI selectors
export const selectUsersFilters = (state) => state.users.filters;
export const selectSelectedUsers = (state) => state.users.selectedUsers;
export const selectUsersSuccessMessage = (state) => state.users.successMessage;

// Action loading selectors
export const selectIsUpdatingRole = (state) => state.users.isUpdatingRole;
export const selectIsTogglingStatus = (state) => state.users.isTogglingStatus;
export const selectIsResettingPassword = (state) => state.users.isResettingPassword;
export const selectIsDeleting = (state) => state.users.isDeleting;

// Computed selectors
export const selectUsersWithTestStats = (state) => {
  return state.users.users.map(user => ({
    ...user,
    // Ensure we have default values for test statistics
    testsProcessed: user.testsProcessed || 0,
    completedTests: user.completedTests || 0,
    pendingTests: user.pendingTests || 0,
    failedTests: user.failedTests || 0,
    successRate: user.successRate || 0,
    avgProcessingTime: user.avgProcessingTime || null,
    lastTestDate: user.lastTestDate || null
  }));
};

export const selectFilteredUsers = (state) => {
  const { users, filters } = state.users;
  
  return users.filter(user => {
    // Role filter
    if (filters.role !== 'all' && user.role !== filters.role) {
      return false;
    }
    
    // Status filter
    if (filters.status !== 'all') {
      const isActive = filters.status === 'active';
      if (user.isActive !== isActive) {
        return false;
      }
    }
    
    return true;
  });
};

export const selectUserById = (state, userId) => {
  return state.users.users.find(user => user._id === userId) ||
         state.users.searchResults.find(user => user._id === userId);
};

export const selectIsUserSelected = (state, userId) => {
  return state.users.selectedUsers.includes(userId);
};

export const selectLastUpdated = (state) => state.users.lastUpdated;

export default usersSlice.reducer;
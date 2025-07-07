// // 📁 client/src/components/auth/LoginForm.jsx
// // Updated to integrate with your backend authentication system

// import React, { useState, useEffect } from 'react';
// import { useDispatch, useSelector } from 'react-redux';
// import { useNavigate, useLocation, Link } from 'react-router-dom';
// import { useForm } from 'react-hook-form';
// import { Eye, EyeOff, Lock, Mail, AlertCircle, CheckCircle } from 'lucide-react';
// import { 
//   login, 
//   selectIsLoading, 
//   selectAuthError, 
//   selectLoginAttempts,
//   clearError 
// } from '../../store/slices/authSlice';
// import LoadingSpinner from '../common/LoadingSpinner';
// import { ROUTES, VALIDATION_RULES } from '../../utils/constants';

// const LoginForm = () => {
//   const dispatch = useDispatch();
//   const navigate = useNavigate();
//   const location = useLocation();
  
//   const isLoading = useSelector(selectIsLoading);
//   const error = useSelector(selectAuthError);
//   const loginAttempts = useSelector(selectLoginAttempts);
  
//   const [showPassword, setShowPassword] = useState(false);
//   const [rememberMe, setRememberMe] = useState(false);

//   const {
//     register,
//     handleSubmit,
//     formState: { errors, isSubmitting },
//     reset,
//     setValue
//   } = useForm({
//     defaultValues: {
//       email: '',
//       password: ''
//     },
//     mode: 'onBlur' // Validate on blur for better UX
//   });

//   // Clear error when component mounts or user starts typing
//   useEffect(() => {
//     dispatch(clearError());
//   }, [dispatch]);

//   // Check for redirect after login
//   const redirectTo = location.state?.from?.pathname || ROUTES.DASHBOARD;

//   const onSubmit = async (data) => {
//     try {
//       dispatch(clearError());
      
//       const loginData = {
//         email: data.email.toLowerCase().trim(),
//         password: data.password
//       };

//       const result = await dispatch(login(loginData)).unwrap();
      
//       // Login successful
//       if (rememberMe) {
//         // Store user preference for remember me
//         localStorage.setItem('rememberMe', 'true');
//         localStorage.setItem('lastEmail', loginData.email);
//       } else {
//         localStorage.removeItem('rememberMe');
//         localStorage.removeItem('lastEmail');
//       }

//       // Navigate to intended page or dashboard
//       navigate(redirectTo, { replace: true });
      
//     } catch (err) {
//       // Error is handled by Redux store
//       console.error('Login failed:', err);
//     }
//   };

//   const togglePasswordVisibility = () => {
//     setShowPassword(!showPassword);
//   };

//   // Load remembered email on component mount
//   useEffect(() => {
//     const rememberedEmail = localStorage.getItem('lastEmail');
//     const shouldRemember = localStorage.getItem('rememberMe') === 'true';
    
//     if (shouldRemember && rememberedEmail) {
//       setValue('email', rememberedEmail);
//       setRememberMe(true);
//     }
//   }, [setValue]);

//   // Demo credentials helper
//   const fillDemoCredentials = (role) => {
//     const demoCredentials = {
//       admin: { email: 'admin@hospital.com', password: 'admin123' },
//       supervisor: { email: 'supervisor@hospital.com', password: 'super123' },
//       technician: { email: 'technician@hospital.com', password: 'tech123' }
//     };

//     const credentials = demoCredentials[role];
//     if (credentials) {
//       setValue('email', credentials.email);
//       setValue('password', credentials.password);
//     }
//   };

//   // Account lockout warning
//   const isAccountLocked = loginAttempts >= 5;
//   const attemptsRemaining = Math.max(0, 5 - loginAttempts);

//   return (
//     <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
//       <div className="max-w-md w-full space-y-8">
//         <div className="bg-white shadow-medical-lg rounded-lg p-8">
//           {/* Header */}
//           <div className="text-center mb-8">
//             <div className="flex items-center justify-center w-16 h-16 mx-auto mb-4 bg-primary-100 rounded-full">
//               <svg className="w-8 h-8 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
//               </svg>
//             </div>
//             <h1 className="text-2xl font-bold text-gray-900 mb-2">Malaria Lab System</h1>
//             <p className="text-gray-600">Sign in to your account</p>
//           </div>

//           {/* Success Message */}
//           {location.state?.message && (
//             <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg">
//               <div className="flex items-center">
//                 <CheckCircle className="w-5 h-5 text-green-400 mr-2" />
//                 <span className="text-green-800 text-sm">{location.state.message}</span>
//               </div>
//             </div>
//           )}

//           {/* Error Alert */}
//           {error && (
//             <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
//               <div className="flex items-center">
//                 <AlertCircle className="w-5 h-5 text-red-400 mr-2" />
//                 <div className="flex-1">
//                   <span className="text-red-800 text-sm">{error}</span>
//                   {loginAttempts > 0 && loginAttempts < 5 && (
//                     <p className="text-red-600 text-xs mt-1">
//                       {attemptsRemaining} attempt{attemptsRemaining !== 1 ? 's' : ''} remaining before account lockout
//                     </p>
//                   )}
//                 </div>
//               </div>
//             </div>
//           )}

//           {/* Account Locked Warning */}
//           {isAccountLocked && (
//             <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
//               <div className="flex items-center">
//                 <AlertCircle className="w-5 h-5 text-yellow-400 mr-2" />
//                 <div className="text-yellow-800 text-sm">
//                   <p className="font-medium">Account temporarily locked</p>
//                   <p className="text-xs mt-1">Too many failed login attempts. Please wait 15 minutes or contact support.</p>
//                 </div>
//               </div>
//             </div>
//           )}

//           {/* Login Form */}
//           <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
//             {/* Email Field */}
//             <div>
//               <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
//                 Email Address
//               </label>
//               <div className="relative">
//                 <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
//                   <Mail className="h-5 w-5 text-gray-400" />
//                 </div>
//                 <input
//                   {...register('email', {
//                     required: 'Email is required',
//                     pattern: {
//                       value: VALIDATION_RULES.EMAIL.PATTERN,
//                       message: VALIDATION_RULES.EMAIL.MESSAGE
//                     }
//                   })}
//                   type="email"
//                   id="email"
//                   className={`input pl-10 ${errors.email ? 'input-error' : ''}`}
//                   placeholder="Enter your email"
//                   autoComplete="email"
//                   disabled={isLoading || isSubmitting || isAccountLocked}
//                 />
//               </div>
//               {errors.email && (
//                 <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
//               )}
//             </div>

//             {/* Password Field */}
//             <div>
//               <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
//                 Password
//               </label>
//               <div className="relative">
//                 <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
//                   <Lock className="h-5 w-5 text-gray-400" />
//                 </div>
//                 <input
//                   {...register('password', {
//                     required: 'Password is required',
//                     minLength: {
//                       value: VALIDATION_RULES.PASSWORD.MIN_LENGTH,
//                       message: `Password must be at least ${VALIDATION_RULES.PASSWORD.MIN_LENGTH} characters`
//                     }
//                   })}
//                   type={showPassword ? 'text' : 'password'}
//                   id="password"
//                   className={`input pl-10 pr-10 ${errors.password ? 'input-error' : ''}`}
//                   placeholder="Enter your password"
//                   autoComplete="current-password"
//                   disabled={isLoading || isSubmitting || isAccountLocked}
//                 />
//                 <button
//                   type="button"
//                   className="absolute inset-y-0 right-0 pr-3 flex items-center"
//                   onClick={togglePasswordVisibility}
//                   disabled={isLoading || isSubmitting || isAccountLocked}
//                 >
//                   {showPassword ? (
//                     <EyeOff className="h-5 w-5 text-gray-400 hover:text-gray-600" />
//                   ) : (
//                     <Eye className="h-5 w-5 text-gray-400 hover:text-gray-600" />
//                   )}
//                 </button>
//               </div>
//               {errors.password && (
//                 <p className="mt-1 text-sm text-red-600">{errors.password.message}</p>
//               )}
//             </div>

//             {/* Remember Me & Forgot Password */}
//             <div className="flex items-center justify-between">
//               <div className="flex items-center">
//                 <input
//                   id="remember-me"
//                   name="remember-me"
//                   type="checkbox"
//                   checked={rememberMe}
//                   onChange={(e) => setRememberMe(e.target.checked)}
//                   className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
//                   disabled={isLoading || isSubmitting || isAccountLocked}
//                 />
//                 <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-700">
//                   Remember me
//                 </label>
//               </div>

//               <div className="text-sm">
//                 <Link
//                   to={ROUTES.FORGOT_PASSWORD}
//                   className="text-primary-600 hover:text-primary-500 font-medium"
//                 >
//                   Forgot your password?
//                 </Link>
//               </div>
//             </div>

//             {/* Submit Button */}
//             <div>
//               <button
//                 type="submit"
//                 disabled={isLoading || isSubmitting || isAccountLocked}
//                 className="btn btn-primary w-full"
//               >
//                 {isLoading || isSubmitting ? (
//                   <div className="flex items-center justify-center">
//                     <LoadingSpinner size="sm" color="white" />
//                     <span className="ml-2">Signing in...</span>
//                   </div>
//                 ) : (
//                   'Sign in'
//                 )}
//               </button>
//             </div>
//           </form>

//           {/* Demo Credentials (for development) */}
//           {process.env.NODE_ENV === 'development' && (
//             <div className="mt-8 p-4 bg-blue-50 border border-blue-200 rounded-lg">
//               <h4 className="text-sm font-medium text-blue-900 mb-3">Demo Credentials</h4>
//               <div className="space-y-2">
//                 <button
//                   type="button"
//                   onClick={() => fillDemoCredentials('admin')}
//                   className="w-full text-left p-2 text-xs bg-white border border-blue-200 rounded hover:bg-blue-50 transition-colors"
//                   disabled={isLoading || isSubmitting}
//                 >
//                   <strong>Admin:</strong> admin@malarialab.com / Amin1234!
//                 </button>
//                 <button
//                   type="button"
//                   onClick={() => fillDemoCredentials('supervisor')}
//                   className="w-full text-left p-2 text-xs bg-white border border-blue-200 rounded hover:bg-blue-50 transition-colors"
//                   disabled={isLoading || isSubmitting}
//                 >
//                   <strong>Supervisor:</strong> supervisor@malarialab.com / Super123!
//                 </button>
//                 <button
//                   type="button"
//                   onClick={() => fillDemoCredentials('technician')}
//                   className="w-full text-left p-2 text-xs bg-white border border-blue-200 rounded hover:bg-blue-50 transition-colors"
//                   disabled={isLoading || isSubmitting}
//                 >
//                   <strong>Technician:</strong> technician@malarialab.com / Tech123!
//                 </button>
//               </div>
//               <p className="text-xs text-blue-700 mt-2">
//                 Click any demo credential to auto-fill the form
//               </p>
//             </div>
//           )}

//           {/* Security Notice */}
//           <div className="mt-6 p-3 bg-gray-50 rounded-lg">
//             <p className="text-xs text-gray-600 text-center">
//               🔒 Your session is secure and encrypted. For security reasons, please log out when finished.
//             </p>
//           </div>
//         </div>

//         {/* Footer */}
//         <div className="text-center">
//           <p className="text-sm text-gray-600">
//             © 2024 Malaria Lab System. Advanced diagnosis for better healthcare.
//           </p>
//           <div className="mt-2 space-x-4">
//             <Link to="/privacy" className="text-xs text-gray-500 hover:text-gray-700">
//               Privacy Policy
//             </Link>
//             <Link to="/terms" className="text-xs text-gray-500 hover:text-gray-700">
//               Terms of Service
//             </Link>
//             <Link to="/support" className="text-xs text-gray-500 hover:text-gray-700">
//               Support
//             </Link>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default LoginForm;
// 📁 client/src/components/auth/LoginForm.jsx
// Modern Hospital Lab Design - Enhanced visual design with preserved logic

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Eye, EyeOff, Lock, Mail, AlertCircle, CheckCircle, Shield, Activity, Microscope } from 'lucide-react';
import { 
  login, 
  selectIsLoading, 
  selectAuthError, 
  selectLoginAttempts,
  clearError 
} from '../../store/slices/authSlice';
import LoadingSpinner from '../common/LoadingSpinner';
import { ROUTES, VALIDATION_RULES } from '../../utils/constants';

const LoginForm = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  
  const isLoading = useSelector(selectIsLoading);
  const error = useSelector(selectAuthError);
  const loginAttempts = useSelector(selectLoginAttempts);
  
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
    setValue
  } = useForm({
    defaultValues: {
      email: '',
      password: ''
    },
    mode: 'onBlur'
  });

  // Clear error when component mounts or user starts typing
  useEffect(() => {
    dispatch(clearError());
  }, [dispatch]);

  // Check for redirect after login
  const redirectTo = location.state?.from?.pathname || ROUTES.DASHBOARD;

  const onSubmit = async (data) => {
    try {
      dispatch(clearError());
      
      const loginData = {
        email: data.email.toLowerCase().trim(),
        password: data.password
      };

      const result = await dispatch(login(loginData)).unwrap();
      
      // Login successful
      if (rememberMe) {
        localStorage.setItem('rememberMe', 'true');
        localStorage.setItem('lastEmail', loginData.email);
      } else {
        localStorage.removeItem('rememberMe');
        localStorage.removeItem('lastEmail');
      }

      // Navigate to intended page or dashboard
      navigate(redirectTo, { replace: true });
      
    } catch (err) {
      console.error('Login failed:', err);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  // Load remembered email on component mount
  useEffect(() => {
    const rememberedEmail = localStorage.getItem('lastEmail');
    const shouldRemember = localStorage.getItem('rememberMe') === 'true';
    
    if (shouldRemember && rememberedEmail) {
      setValue('email', rememberedEmail);
      setRememberMe(true);
    }
  }, [setValue]);

  // Demo credentials helper
  const fillDemoCredentials = (role) => {
    const demoCredentials = {
      admin: { email: 'admin@malarialab.com', password: 'Admin1234!' },
      supervisor: { email: 'supervisor@malarialab.com', password: 'Super123!' },
      technician: { email: 'technician@malarialab.com', password: 'Tech123!' }
    };

    const credentials = demoCredentials[role];
    if (credentials) {
      setValue('email', credentials.email);
      setValue('password', credentials.password);
    }
  };

  // Account lockout warning
  const isAccountLocked = loginAttempts >= 5;
  const attemptsRemaining = Math.max(0, 5 - loginAttempts);

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900">
      {/* Animated Background Pattern */}
      <div className="absolute inset-0">
        {/* Primary gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-600/20 via-indigo-600/30 to-purple-600/20" />
        
        {/* Animated grid pattern */}
        <div 
          className="absolute inset-0 opacity-30"
          style={{
            backgroundImage: `
              linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px',
            animation: 'grid-move 20s linear infinite'
          }}
        />
        
        {/* Floating medical particles */}
        <div className="absolute inset-0">
          {[...Array(15)].map((_, i) => (
            <div
              key={i}
              className="absolute w-2 h-2 bg-blue-400/20 rounded-full animate-pulse"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 3}s`,
                animationDuration: `${2 + Math.random() * 2}s`
              }}
            />
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="relative z-10 flex items-center justify-center min-h-screen py-12 px-4 sm:px-6 lg:px-8">
        <div className="w-full max-w-md">
          
          {/* Main Login Card */}
          <div className="relative">
            {/* Glassmorphism background */}
            <div className="absolute inset-0 bg-white/10 backdrop-blur-xl rounded-2xl border border-white/20" />
            <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent rounded-2xl" />
            
            {/* Card content */}
            <div className="relative p-8 space-y-6">
              
              {/* Header Section */}
              <div className="text-center space-y-4">
                {/* Logo/Icon */}
                <div className="relative mx-auto w-20 h-20 mb-6">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-400 to-indigo-500 rounded-2xl blur-lg opacity-60" />
                  <div className="relative flex items-center justify-center w-full h-full bg-gradient-to-r from-blue-500 to-indigo-600 rounded-2xl shadow-2xl">
                    <Microscope className="w-8 h-8 text-white" />
                  </div>
                </div>
                
                {/* Title */}
                <div className="space-y-2">
                  <h1 className="text-3xl font-bold bg-gradient-to-r from-white via-blue-100 to-white bg-clip-text text-transparent">
                    Malaria Lab System
                  </h1>
                  <p className="text-blue-200/80 text-sm font-medium">
                    A Malaria Diagnostic Platform
                  </p>
                  <div className="flex items-center justify-center space-x-4 text-xs text-blue-300/60">
                    <div className="flex items-center space-x-1">
                      <Shield className="w-3 h-3" />
                      <span>Secure</span>
                    </div>
                    <div className="w-1 h-1 bg-blue-300/40 rounded-full" />
                    <div className="flex items-center space-x-1">
                      <Activity className="w-3 h-3" />
                      <span>Real-time</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Success Message */}
              {location.state?.message && (
                <div className="relative">
                  <div className="absolute inset-0 bg-emerald-500/20 backdrop-blur-sm rounded-xl border border-emerald-400/30" />
                  <div className="relative p-4 flex items-center space-x-3">
                    <div className="flex-shrink-0">
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    </div>
                    <span className="text-emerald-100 text-sm font-medium">{location.state.message}</span>
                  </div>
                </div>
              )}

              {/* Error Alert */}
              {error && (
                <div className="relative">
                  <div className="absolute inset-0 bg-red-500/20 backdrop-blur-sm rounded-xl border border-red-400/30" />
                  <div className="relative p-4 space-y-2">
                    <div className="flex items-center space-x-3">
                      <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                      <span className="text-red-100 text-sm font-medium">{error}</span>
                    </div>
                    {loginAttempts > 0 && loginAttempts < 5 && (
                      <p className="text-red-200/80 text-xs pl-8">
                        {attemptsRemaining} attempt{attemptsRemaining !== 1 ? 's' : ''} remaining
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Account Locked Warning */}
              {isAccountLocked && (
                <div className="relative">
                  <div className="absolute inset-0 bg-amber-500/20 backdrop-blur-sm rounded-xl border border-amber-400/30" />
                  <div className="relative p-4 space-y-2">
                    <div className="flex items-center space-x-3">
                      <AlertCircle className="w-5 h-5 text-amber-400 flex-shrink-0" />
                      <div>
                        <p className="text-amber-100 text-sm font-medium">Account Temporarily Locked</p>
                        <p className="text-amber-200/80 text-xs">Please wait 15 minutes or contact support</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Login Form */}
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
                
                {/* Email Field */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-blue-200/90">
                    Email Address
                  </label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 group-focus-within:border-blue-400/50 group-focus-within:bg-white/10 transition-all duration-300" />
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <Mail className="h-5 w-5 text-blue-300/70 group-focus-within:text-blue-400 transition-colors" />
                    </div>
                    <input
                      {...register('email', {
                        required: 'Email is required',
                        pattern: {
                          value: VALIDATION_RULES.EMAIL.PATTERN,
                          message: VALIDATION_RULES.EMAIL.MESSAGE
                        }
                      })}
                      type="email"
                      className={`relative w-full pl-12 pr-4 py-3 bg-transparent text-white placeholder-blue-300/50 focus:outline-none focus:ring-2 focus:ring-blue-400/50 rounded-xl transition-all duration-300 ${errors.email ? 'ring-2 ring-red-400/50' : ''}`}
                      placeholder="Enter your email address"
                      autoComplete="email"
                      disabled={isLoading || isSubmitting || isAccountLocked}
                    />
                  </div>
                  {errors.email && (
                    <p className="text-red-300 text-xs font-medium pl-2">{errors.email.message}</p>
                  )}
                </div>

                {/* Password Field */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-blue-200/90">
                    Password
                  </label>
                  <div className="relative group">
                    <div className="absolute inset-0 bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 group-focus-within:border-blue-400/50 group-focus-within:bg-white/10 transition-all duration-300" />
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-blue-300/70 group-focus-within:text-blue-400 transition-colors" />
                    </div>
                    <input
                      {...register('password', {
                        required: 'Password is required',
                        minLength: {
                          value: VALIDATION_RULES.PASSWORD.MIN_LENGTH,
                          message: `Password must be at least ${VALIDATION_RULES.PASSWORD.MIN_LENGTH} characters`
                        }
                      })}
                      type={showPassword ? 'text' : 'password'}
                      className={`relative w-full pl-12 pr-12 py-3 bg-transparent text-white placeholder-blue-300/50 focus:outline-none focus:ring-2 focus:ring-blue-400/50 rounded-xl transition-all duration-300 ${errors.password ? 'ring-2 ring-red-400/50' : ''}`}
                      placeholder="Enter your password"
                      autoComplete="current-password"
                      disabled={isLoading || isSubmitting || isAccountLocked}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-4 flex items-center"
                      onClick={togglePasswordVisibility}
                      disabled={isLoading || isSubmitting || isAccountLocked}
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5 text-blue-300/70 hover:text-blue-400 transition-colors" />
                      ) : (
                        <Eye className="h-5 w-5 text-blue-300/70 hover:text-blue-400 transition-colors" />
                      )}
                    </button>
                  </div>
                  {errors.password && (
                    <p className="text-red-300 text-xs font-medium pl-2">{errors.password.message}</p>
                  )}
                </div>

                {/* Remember Me & Forgot Password */}
                <div className="flex items-center justify-between pt-2">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="w-4 h-4 rounded border-2 border-blue-300/50 bg-white/10 text-blue-500 focus:ring-blue-400/50 focus:ring-2"
                      disabled={isLoading || isSubmitting || isAccountLocked}
                    />
                    <span className="text-sm text-blue-200/80">Remember me</span>
                  </label>

                  <Link
                    to={ROUTES.FORGOT_PASSWORD}
                    className="text-sm text-blue-300 hover:text-blue-200 font-medium transition-colors"
                  >
                    Forgot password?
                  </Link>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isLoading || isSubmitting || isAccountLocked}
                  className="relative w-full py-3 px-4 rounded-xl font-semibold text-white transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100 disabled:opacity-50 disabled:cursor-not-allowed group"
                >
                  {/* Button background */}
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-xl group-hover:from-blue-400 group-hover:to-indigo-500 transition-all duration-300" />
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-400/50 to-indigo-500/50 rounded-xl blur group-hover:blur-md transition-all duration-300" />
                  
                  {/* Button content */}
                  <span className="relative flex items-center justify-center space-x-2">
                    {isLoading || isSubmitting ? (
                      <>
                        <LoadingSpinner size="sm" color="white" />
                        <span>Authenticating...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4" />
                        <span>Secure Sign In</span>
                      </>
                    )}
                  </span>
                </button>
              </form>

              {/* Demo Credentials (Development Only) */}
              {process.env.NODE_ENV === 'development' && (
                <div className="relative">
                  <div className="absolute inset-0 bg-indigo-500/10 backdrop-blur-sm rounded-xl border border-indigo-400/20" />
                  <div className="relative p-4 space-y-3">
                    <h4 className="text-sm font-semibold text-indigo-300 flex items-center space-x-2">
                      <Activity className="w-4 h-4" />
                      <span>Demo Access</span>
                    </h4>
                    <div className="grid gap-2">
                      {[
                        { role: 'admin', label: 'System Administrator', email: 'admin@malarialab.com' },
                        { role: 'supervisor', label: 'Lab Supervisor', email: 'supervisor@malarialab.com' },
                        { role: 'technician', label: 'Lab Technician', email: 'technician@malarialab.com' }
                      ].map(({ role, label, email }) => (
                        <button
                          key={role}
                          type="button"
                          onClick={() => fillDemoCredentials(role)}
                          className="relative group p-2 rounded-lg text-left transition-all duration-200 hover:scale-[1.02]"
                          disabled={isLoading || isSubmitting}
                        >
                          <div className="absolute inset-0 bg-white/5 rounded-lg group-hover:bg-white/10 transition-all duration-200" />
                          <div className="relative text-xs">
                            <div className="font-medium text-indigo-200">{label}</div>
                            <div className="text-indigo-300/70">{email}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Security Notice */}
              <div className="relative">
                <div className="absolute inset-0 bg-slate-500/10 backdrop-blur-sm rounded-lg border border-slate-400/20" />
                <div className="relative p-3 flex items-center justify-center space-x-2">
                  <Shield className="w-4 h-4 text-slate-300" />
                  <p className="text-xs text-slate-300/80 text-center">
                    End-to-end encrypted • Session secured • HIPAA compliant
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="mt-8 text-center space-y-4">
            <div className="text-sm text-blue-200/60">
              © 2025 MalariaTech Laboratory Systems
            </div>
            <div className="flex justify-center space-x-6 text-xs">
              <Link to="/privacy" className="text-blue-300/70 hover:text-blue-200 transition-colors">
                Privacy Policy
              </Link>
              <Link to="/terms" className="text-blue-300/70 hover:text-blue-200 transition-colors">
                Terms of Service
              </Link>
              <Link to="/support" className="text-blue-300/70 hover:text-blue-200 transition-colors">
                Support
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* CSS Animation Styles */}
      <style jsx>{`
        @keyframes grid-move {
          0% { transform: translate(0, 0); }
          100% { transform: translate(50px, 50px); }
        }
      `}</style>
    </div>
  );
};

export default LoginForm;
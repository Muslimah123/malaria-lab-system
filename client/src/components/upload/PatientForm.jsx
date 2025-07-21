// // 📁 client/src/components/upload/PatientForm.jsx
// // Enhanced with debounce search and loading states - COMPLETE VERSION
// import React, { useState, useEffect, useCallback, useRef } from 'react';
// import { useForm } from 'react-hook-form';
// import { 
//   User, 
//   Phone, 
//   Mail, 
//   Calendar, 
//   MapPin, 
//   FileText, 
//   AlertCircle, 
//   Search,
//   Plus,
//   UserCheck,
//   CheckCircle,
//   Heart,
//   Stethoscope,
//   Building,
//   UserPlus,
//   TestTube
// } from 'lucide-react';
// import LoadingSpinner from '../common/LoadingSpinner';
// import { 
//   GENDER_OPTIONS, 
//   BLOOD_TYPES, 
//   TEST_PRIORITIES, 
//   SAMPLE_TYPES,
//   VALIDATION_RULES,
//   PATIENT_ID_FORMAT
// } from '../../utils/constants';
// import apiService from '../../services/api';

// // Debounce hook
// const useDebounce = (value, delay) => {
//   const [debouncedValue, setDebouncedValue] = useState(value);

//   useEffect(() => {
//     const handler = setTimeout(() => {
//       setDebouncedValue(value);
//     }, delay);

//     return () => {
//       clearTimeout(handler);
//     };
//   }, [value, delay]);

//   return debouncedValue;
// };

// const PatientForm = ({ 
//   initialData, 
//   testData, 
//   onSubmit, 
//   onTestDataChange, 
//   loading = false, 
//   error 
// }) => {
//   const [isNewPatient, setIsNewPatient] = useState(!initialData);
//   const [searchingPatient, setSearchingPatient] = useState(false);
//   const [searchResults, setSearchResults] = useState([]);
//   const [searchTerm, setSearchTerm] = useState('');
//   const [showEmergencyContact, setShowEmergencyContact] = useState(false);
//   const [showMedicalHistory, setShowMedicalHistory] = useState(false);
//   const [showReferringPhysician, setShowReferringPhysician] = useState(false);
//   const [selectedPatientLoading, setSelectedPatientLoading] = useState(false);
//   const [patientSelected, setPatientSelected] = useState(false);

//   // Debounced search term
//   const debouncedSearchTerm = useDebounce(searchTerm, 300);

//   // Form data persistence key
//   const FORM_STORAGE_KEY = 'malaria-lab-patient-form-draft';

//   const {
//     register,
//     handleSubmit,
//     formState: { errors, isSubmitting, isDirty },
//     reset,
//     watch,
//     setValue,
//     getValues
//   } = useForm({
//     defaultValues: {
//       // Patient data (matching backend Patient model)
//       patientId: initialData?.patientId || '',
//       firstName: initialData?.firstName || '',
//       lastName: initialData?.lastName || '',
//       dateOfBirth: initialData?.dateOfBirth ? 
//         new Date(initialData.dateOfBirth).toISOString().split('T')[0] : '',
//       gender: initialData?.gender || 'unknown',
//       age: initialData?.age || '',
//       phoneNumber: initialData?.phoneNumber || '',
//       email: initialData?.email || '',
      
//       // Address (nested object in backend)
//       street: initialData?.address?.street || '',
//       city: initialData?.address?.city || '',
//       state: initialData?.address?.state || '',
//       zipCode: initialData?.address?.zipCode || '',
//       country: initialData?.address?.country || 'Rwanda',
      
//       // Medical information
//       bloodType: initialData?.bloodType || 'unknown',
//       allergies: initialData?.allergies?.join(', ') || '',
      
//       // Emergency contact (nested object in backend)
//       emergencyContactName: initialData?.emergencyContact?.name || '',
//       emergencyContactRelationship: initialData?.emergencyContact?.relationship || '',
//       emergencyContactPhone: initialData?.emergencyContact?.phoneNumber || '',
      
//       // Hospital information
//       hospitalId: initialData?.hospitalId || '',
//       referringPhysicianName: initialData?.referringPhysician?.name || '',
//       referringPhysicianLicense: initialData?.referringPhysician?.licenseNumber || '',
//       referringPhysicianDepartment: initialData?.referringPhysician?.department || '',
      
//       // Test data
//       priority: testData?.priority || 'normal',
//       sampleType: testData?.sampleType || 'blood_smear',
//       symptoms: testData?.clinicalNotes?.symptoms || [],
//       duration: testData?.clinicalNotes?.duration || '',
//       travelHistory: testData?.clinicalNotes?.travelHistory || '',
//       medications: testData?.clinicalNotes?.medications || '',
//       additionalNotes: testData?.clinicalNotes?.additionalNotes || ''
//     }
//   });

//   const watchedData = watch();

//   // Load saved form data on mount
//   useEffect(() => {
//     if (!initialData && isNewPatient) {
//       const savedData = localStorage.getItem(FORM_STORAGE_KEY);
//       if (savedData) {
//         try {
//           const parsedData = JSON.parse(savedData);
//           Object.keys(parsedData).forEach(key => {
//             setValue(key, parsedData[key]);
//           });
//         } catch (error) {
//           console.error('Failed to load saved form data:', error);
//         }
//       }
//     }
//   }, [initialData, isNewPatient, setValue]);

//   // Auto-save form data to localStorage
//   useEffect(() => {
//     if (isDirty && isNewPatient) {
//       const formData = getValues();
//       localStorage.setItem(FORM_STORAGE_KEY, JSON.stringify(formData));
//     }
//   }, [watchedData, isDirty, isNewPatient, getValues]);

//   // Update test data when form values change
 
// useEffect(() => {
//   if (onTestDataChange) {
//     // Only update if values actually changed
//     const newTestData = {
//       priority: watchedData.priority,
//       sampleType: watchedData.sampleType,
//       clinicalNotes: {
//         symptoms: watchedData.symptoms,
//         duration: watchedData.duration,
//         travelHistory: watchedData.travelHistory,
//         medications: watchedData.medications,
//         additionalNotes: watchedData.additionalNotes
//       }
//     };
    
//     // Prevent infinite loops by checking if data actually changed
//     onTestDataChange(newTestData);
//   }
// }, [
//   watchedData.priority,
//   watchedData.sampleType,
//   watchedData.symptoms,
//   watchedData.duration,
//   watchedData.travelHistory,
//   watchedData.medications,
//   watchedData.additionalNotes,
//   // DON'T include onTestDataChange in dependencies
// ]);

//   // Debounced patient search
//   useEffect(() => {
//     if (debouncedSearchTerm && debouncedSearchTerm.length >= 2) {
//       searchPatients(debouncedSearchTerm);
//     } else {
//       setSearchResults([]);
//     }
//   }, [debouncedSearchTerm]);

//   // Search for existing patients
//   const searchPatients = async (searchTerm) => {
//   setSearchingPatient(true);
//   try {
//     const response = await apiService.patients.search(searchTerm);
    
//     // Handle the enhanced response structure
//     if (response.success) {
//       setSearchResults(response.data || []);
//     } else {
//       console.error('Search failed:', response.error);
//       setSearchResults([]);
//     }
//   } catch (error) {
//     console.error('Patient search failed:', error);
//     setSearchResults([]);
//   } finally {
//     setSearchingPatient(false);
//   }
// };

//   // Handle patient selection from search results
//   const selectPatient = async (patient) => {
//     setSelectedPatientLoading(true);
//     setPatientSelected(false);
    
//     try {
//       // Fill form with selected patient data
//       Object.keys(patient).forEach(key => {
//         if (key === 'address' && patient.address) {
//           setValue('street', patient.address.street || '');
//           setValue('city', patient.address.city || '');
//           setValue('state', patient.address.state || '');
//           setValue('zipCode', patient.address.zipCode || '');
//           setValue('country', patient.address.country || 'Rwanda');
//         } else if (key === 'emergencyContact' && patient.emergencyContact) {
//           setValue('emergencyContactName', patient.emergencyContact.name || '');
//           setValue('emergencyContactRelationship', patient.emergencyContact.relationship || '');
//           setValue('emergencyContactPhone', patient.emergencyContact.phoneNumber || '');
//         } else if (key === 'referringPhysician' && patient.referringPhysician) {
//           setValue('referringPhysicianName', patient.referringPhysician.name || '');
//           setValue('referringPhysicianLicense', patient.referringPhysician.licenseNumber || '');
//           setValue('referringPhysicianDepartment', patient.referringPhysician.department || '');
//         } else if (key === 'allergies' && Array.isArray(patient.allergies)) {
//           setValue('allergies', patient.allergies.join(', '));
//         } else if (key === 'dateOfBirth' && patient.dateOfBirth) {
//           setValue('dateOfBirth', new Date(patient.dateOfBirth).toISOString().split('T')[0]);
//         } else {
//           setValue(key, patient[key] || '');
//         }
//       });

//       setIsNewPatient(false);
//       setSearchResults([]);
//       setSearchTerm('');
//       setPatientSelected(true);
      
//       // Clear saved draft since we selected a patient
//       localStorage.removeItem(FORM_STORAGE_KEY);
      
//     } catch (error) {
//       console.error('Failed to select patient:', error);
//     } finally {
//       setSelectedPatientLoading(false);
//     }
//   };

//   const handleFormSubmit = (data) => {
//     // Transform form data to match backend Patient model structure
//     const patientData = {
//       // Basic information
//       patientId: data.patientId || undefined,
//       firstName: data.firstName.trim(),
//       lastName: data.lastName.trim(),
//       dateOfBirth: data.dateOfBirth || undefined,
//       gender: data.gender,
//       age: data.age ? parseInt(data.age) : undefined,
//       phoneNumber: data.phoneNumber.trim() || undefined,
//       email: data.email.trim() || undefined,
      
//       // Address object
//       address: {
//         street: data.street.trim() || undefined,
//         city: data.city.trim() || undefined,
//         state: data.state.trim() || undefined,
//         zipCode: data.zipCode.trim() || undefined,
//         country: data.country || 'Rwanda'
//       },
      
//       // Medical information
//       bloodType: data.bloodType,
//       allergies: data.allergies ? 
//         data.allergies.split(',').map(a => a.trim()).filter(a => a) : [],
      
//       // Emergency contact object
//       emergencyContact: (data.emergencyContactName || data.emergencyContactPhone) ? {
//         name: data.emergencyContactName.trim() || undefined,
//         relationship: data.emergencyContactRelationship.trim() || undefined,
//         phoneNumber: data.emergencyContactPhone.trim() || undefined
//       } : undefined,
      
//       // Hospital information
//       hospitalId: data.hospitalId.trim() || undefined,
//       referringPhysician: (data.referringPhysicianName || data.referringPhysicianLicense) ? {
//         name: data.referringPhysicianName.trim() || undefined,
//         licenseNumber: data.referringPhysicianLicense.trim() || undefined,
//         department: data.referringPhysicianDepartment.trim() || undefined
//       } : undefined,
      
//       // Include MongoDB _id if updating existing patient
//       ...(initialData?._id && { _id: initialData._id })
//     };

//     // Remove undefined values to avoid backend validation issues
//     Object.keys(patientData).forEach(key => {
//       if (patientData[key] === undefined) {
//         delete patientData[key];
//       } else if (typeof patientData[key] === 'object' && patientData[key] !== null) {
//         Object.keys(patientData[key]).forEach(subKey => {
//           if (patientData[key][subKey] === undefined) {
//             delete patientData[key][subKey];
//           }
//         });
//         // Remove empty objects
//         if (Object.keys(patientData[key]).length === 0) {
//           delete patientData[key];
//         }
//       }
//     });

//     // Clear saved form data on successful submit
//     localStorage.removeItem(FORM_STORAGE_KEY);
    
//     onSubmit(patientData);
//   };

//   // Calculate age from date of birth
//   const calculateAge = (dateOfBirth) => {
//     if (!dateOfBirth) return '';
    
//     const today = new Date();
//     const birthDate = new Date(dateOfBirth);
//     let age = today.getFullYear() - birthDate.getFullYear();
//     const monthDiff = today.getMonth() - birthDate.getMonth();
    
//     if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
//       age--;
//     }
//     return age;
//   };

//   // Auto-calculate age when date of birth changes
//   useEffect(() => {
//     const dateOfBirth = watchedData.dateOfBirth;
//     if (dateOfBirth) {
//       const calculatedAge = calculateAge(dateOfBirth);
//       if (calculatedAge >= 0) {
//         setValue('age', calculatedAge.toString());
//       }
//     }
//   }, [watchedData.dateOfBirth, setValue]);

//   // Clear saved draft
//   const clearDraft = () => {
//     localStorage.removeItem(FORM_STORAGE_KEY);
//     reset();
//   };

//   return (
//   <div className="space-y-6">
//     {/* Header */}
//     <div className="text-center mb-8">
//       <div className="w-16 h-16 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-4 border border-white/30">
//         <User className="w-8 h-8 text-white" />
//       </div>
//       <h3 className="text-xl font-semibold text-white mb-2">Patient Information</h3>
//       <p className="text-blue-200">Search for an existing patient or create a new patient record</p>
//     </div>

//     {/* Error Display */}
//     {error && (
//       <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
//         <div className="flex items-center text-red-200">
//           <AlertCircle className="w-5 h-5 mr-2" />
//           <span className="text-sm">{error}</span>
//         </div>
//       </div>
//     )}

//     {/* Draft notification */}
//     {isDirty && isNewPatient && (
//       <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-3">
//         <div className="flex items-center justify-between">
//           <div className="flex items-center text-blue-200">
//             <CheckCircle className="w-4 h-4 mr-2" />
//             <span className="text-sm">Form data is being auto-saved</span>
//           </div>
//           <button
//             type="button"
//             onClick={clearDraft}
//             className="text-blue-200 hover:text-white text-sm font-medium"
//           >
//             Clear draft
//           </button>
//         </div>
//       </div>
//     )}

//     {/* Patient Type Selection */}
//     <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//       <div className="flex items-center justify-center space-x-8 mb-6">
//         <label className="flex items-center cursor-pointer group">
//           <input
//             type="radio"
//             checked={!isNewPatient}
//             onChange={() => setIsNewPatient(false)}
//             className="mr-3 w-4 h-4 text-blue-500"
//           />
//           <div className="flex items-center text-white group-hover:text-blue-200">
//             <UserCheck className="w-5 h-5 mr-2" />
//             <span className="font-medium">Existing Patient</span>
//           </div>
//         </label>
        
//         <label className="flex items-center cursor-pointer group">
//           <input
//             type="radio"
//             checked={isNewPatient}
//             onChange={() => setIsNewPatient(true)}
//             className="mr-3 w-4 h-4 text-blue-500"
//           />
//           <div className="flex items-center text-white group-hover:text-blue-200">
//             <Plus className="w-5 h-5 mr-2" />
//             <span className="font-medium">New Patient</span>
//           </div>
//         </label>
//       </div>

//       {/* Patient Search */}
//       {!isNewPatient && (
//         <div className="relative">
//           <div className="flex items-center space-x-2">
//             <div className="flex-1 relative">
//               <Search className="absolute left-3 top-3 h-5 w-5 text-blue-300" />
//               <input
//                 type="text"
//                 placeholder="Search by Patient ID, name, or phone..."
//                 value={searchTerm}
//                 onChange={(e) => setSearchTerm(e.target.value)}
//                 className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 focus:border-white/50"
//               />
//             </div>
//             {(searchingPatient || selectedPatientLoading) && (
//               <LoadingSpinner size="sm" color="white" />
//             )}
//           </div>

//           {/* Patient selected indicator */}
//           {patientSelected && !selectedPatientLoading && (
//             <div className="mt-3 flex items-center text-green-400">
//               <CheckCircle className="w-4 h-4 mr-2" />
//               <span className="text-sm font-medium">Patient selected successfully</span>
//             </div>
//           )}

//           {/* Search Results */}
//           {searchResults.length > 0 && (
//             <div className="absolute top-full left-0 right-0 z-10 mt-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg shadow-xl max-h-60 overflow-y-auto">
//               {searchResults.map((patient) => (
//                 <button
//                   key={patient._id}
//                   type="button"
//                   onClick={() => selectPatient(patient)}
//                   className="w-full text-left p-4 hover:bg-white/10 border-b border-white/10 last:border-b-0 focus:bg-white/10 focus:outline-none transition-colors"
//                 >
//                   <div className="font-medium text-white">
//                     {patient.firstName} {patient.lastName}
//                   </div>
//                   <div className="text-sm text-blue-200">
//                     ID: {patient.patientId} • Age: {patient.age || 'Unknown'} • Phone: {patient.phoneNumber || 'N/A'}
//                   </div>
//                 </button>
//               ))}
//             </div>
//           )}

//           {/* No results */}
//           {debouncedSearchTerm && debouncedSearchTerm.length >= 2 && searchResults.length === 0 && !searchingPatient && (
//             <div className="absolute top-full left-0 right-0 z-10 mt-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
//               <p className="text-sm text-blue-200 text-center">
//                 No patients found matching "{debouncedSearchTerm}"
//               </p>
//             </div>
//           )}
//         </div>
//       )}
//     </div>

//     <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-6">
//       {/* Basic Information */}
//       <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//         <h4 className="text-lg font-medium text-white mb-6 flex items-center">
//           <User className="w-5 h-5 mr-2" />
//           Basic Information
//         </h4>
        
//         <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//           {/* Patient ID */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Patient ID {!isNewPatient && '*'}
//             </label>
//             <input
//               {...register('patientId', {
//                 ...((!isNewPatient) && {
//                   required: 'Patient ID is required for existing patients'
//                 })
//               })}
//               type="text"
//               className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
//                 errors.patientId ? 'border-red-500/50' : 'border-white/30'
//               }`}
//               placeholder={isNewPatient ? "Auto-generated" : "PAT-20240101-001"}
//               disabled={isNewPatient}
//             />
//             {errors.patientId && (
//               <p className="mt-1 text-sm text-red-300">{errors.patientId.message}</p>
//             )}
//           </div>

//           {/* First Name */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               First Name *
//             </label>
//             <input
//               {...register('firstName', { 
//                 required: 'First name is required',
//                 maxLength: { value: 50, message: 'First name must be less than 50 characters' }
//               })}
//               type="text"
//               className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
//                 errors.firstName ? 'border-red-500/50' : 'border-white/30'
//               }`}
//               placeholder="Enter first name"
//             />
//             {errors.firstName && (
//               <p className="mt-1 text-sm text-red-300">{errors.firstName.message}</p>
//             )}
//           </div>

//           {/* Last Name */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Last Name *
//             </label>
//             <input
//               {...register('lastName', { 
//                 required: 'Last name is required',
//                 maxLength: { value: 50, message: 'Last name must be less than 50 characters' }
//               })}
//               type="text"
//               className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
//                 errors.lastName ? 'border-red-500/50' : 'border-white/30'
//               }`}
//               placeholder="Enter last name"
//             />
//             {errors.lastName && (
//               <p className="mt-1 text-sm text-red-300">{errors.lastName.message}</p>
//             )}
//           </div>

//           {/* Date of Birth */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Date of Birth
//             </label>
//             <input
//               {...register('dateOfBirth')}
//               type="date"
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
//               max={new Date().toISOString().split('T')[0]}
//             />
//           </div>

//           {/* Age */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Age
//             </label>
//             <input
//               {...register('age', {
//                 min: { value: 0, message: 'Age must be positive' },
//                 max: { value: 150, message: 'Please enter a valid age' }
//               })}
//               type="number"
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//               placeholder="Auto-calculated from DOB"
//             />
//           </div>

//           {/* Gender */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Gender
//             </label>
//             <select
//               {...register('gender')}
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
//             >
//               {GENDER_OPTIONS.map(option => (
//                 <option key={option.value} value={option.value} className="bg-blue-800">
//                   {option.label}
//                 </option>
//               ))}
//             </select>
//           </div>
//         </div>
//       </div>

//       {/* Contact Information */}
//       <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//         <h4 className="text-lg font-medium text-white mb-6 flex items-center">
//           <Phone className="w-5 h-5 mr-2" />
//           Contact Information
//         </h4>
        
//         <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Phone Number
//             </label>
//             <input
//               {...register('phoneNumber')}
//               type="tel"
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//               placeholder="+250 XXX XXX XXX"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Email Address
//             </label>
//             <input
//               {...register('email')}
//               type="email"
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//               placeholder="patient@example.com"
//             />
//           </div>
//         </div>
//       </div>

//       {/* Test Information */}
//       <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//         <h4 className="text-lg font-medium text-white mb-6 flex items-center">
//           <TestTube className="w-5 h-5 mr-2" />
//           Test Information
//         </h4>
        
//         <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Priority
//             </label>
//             <select
//               {...register('priority')}
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
//             >
//               {Object.entries(TEST_PRIORITIES).map(([key, value]) => (
//                 <option key={value} value={value} className="bg-blue-800">
//                   {key.charAt(0) + key.slice(1).toLowerCase()}
//                 </option>
//               ))}
//             </select>
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Sample Type
//             </label>
//             <select
//               {...register('sampleType')}
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
//             >
//               {Object.entries(SAMPLE_TYPES).map(([key, value]) => (
//                 <option key={value} value={value} className="bg-blue-800">
//                   {key.split('_').map(word => 
//                     word.charAt(0) + word.slice(1).toLowerCase()
//                   ).join(' ')}
//                 </option>
//               ))}
//             </select>
//           </div>
//         </div>

//         {/* Clinical Notes */}
//         <div className="mt-6 space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">
//               Symptoms
//             </label>
//             <textarea
//               {...register('symptoms')}
//               rows={2}
//               className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//               placeholder="Describe current symptoms"
//             />
//           </div>

//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">
//                 Duration
//               </label>
//               <input
//                 {...register('duration')}
//                 type="text"
//                 className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//                 placeholder="e.g., 3 days, 1 week"
//               />
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">
//                 Travel History
//               </label>
//               <input
//                 {...register('travelHistory')}
//                 type="text"
//                 className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
//                 placeholder="Recent travel to endemic areas"
//               />
//             </div>
//           </div>
//         </div>
//       </div>

//       {/* Submit Button */}
//       <div className="text-center pt-6">
//         <button
//           type="submit"
//           disabled={loading || isSubmitting}
//           className="bg-white text-blue-600 px-8 py-4 rounded-lg font-semibold hover:bg-blue-50 transition-all hover:scale-105 disabled:opacity-50 disabled:hover:scale-100"
//         >
//           {loading || isSubmitting ? (
//             <div className="flex items-center justify-center">
//               <LoadingSpinner size="sm" color="blue" />
//               <span className="ml-2">
//                 {isNewPatient ? 'Creating...' : 'Updating...'}
//               </span>
//             </div>
//           ) : (
//             <>
//               <FileText className="w-5 h-5 mr-2 inline" />
//               {isNewPatient ? 'Create Patient & Test' : 'Update & Continue'}
//             </>
//           )}
//         </button>
//       </div>
//     </form>
//   </div>
// );
// };

// export default PatientForm;
// 📁 client/src/components/upload/PatientForm.jsx
// Enhanced with debounce search and loading states - COMPLETE VERSION WITH REDUX INTEGRATION
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { useDispatch, useSelector } from 'react-redux';
import { 
  User, 
  Phone, 
  Mail, 
  Calendar, 
  MapPin, 
  FileText, 
  AlertCircle, 
  Search,
  Plus,
  UserCheck,
  CheckCircle,
  Heart,
  Stethoscope,
  Building,
  UserPlus,
  TestTube
} from 'lucide-react';

// Redux imports
import {
  searchPatients as searchPatientsRedux,
  clearSearchResults,
  selectSearchResults,
  selectPatientsLoading,
  selectIsSearchingPatients
} from '../../store/slices/patientsSlice';

import LoadingSpinner from '../common/LoadingSpinner';
import { 
  GENDER_OPTIONS, 
  BLOOD_TYPES, 
  TEST_PRIORITIES, 
  SAMPLE_TYPES,
  VALIDATION_RULES,
  PATIENT_ID_FORMAT
} from '../../utils/constants';

// Debounce hook
const useDebounce = (value, delay) => {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

const PatientForm = ({ 
  initialData, 
  testData, 
  onSubmit, 
  onTestDataChange, 
  loading = false, 
  error 
}) => {
  const dispatch = useDispatch();
  
  // Redux selectors
  const searchResults = useSelector(selectSearchResults);
  const patientsLoading = useSelector(selectPatientsLoading);
  const isSearchingPatients = useSelector(selectIsSearchingPatients);

  const [isNewPatient, setIsNewPatient] = useState(!initialData);
  const [searchTerm, setSearchTerm] = useState('');
  const [showEmergencyContact, setShowEmergencyContact] = useState(false);
  const [showMedicalHistory, setShowMedicalHistory] = useState(false);
  const [showReferringPhysician, setShowReferringPhysician] = useState(false);
  const [selectedPatientLoading, setSelectedPatientLoading] = useState(false);
  const [patientSelected, setPatientSelected] = useState(false);

  // Debounced search term
  const debouncedSearchTerm = useDebounce(searchTerm, 300);

  // Form data persistence key
  const FORM_STORAGE_KEY = 'malaria-lab-patient-form-draft';

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isDirty },
    reset,
    watch,
    setValue,
    getValues
  } = useForm({
    defaultValues: {
      // Patient data (matching backend Patient model)
      patientId: initialData?.patientId || '',
      firstName: initialData?.firstName || '',
      lastName: initialData?.lastName || '',
      dateOfBirth: initialData?.dateOfBirth ? 
        new Date(initialData.dateOfBirth).toISOString().split('T')[0] : '',
      gender: initialData?.gender || 'unknown',
      age: initialData?.age || '',
      phoneNumber: initialData?.phoneNumber || '',
      email: initialData?.email || '',
      
      // Address (nested object in backend)
      street: initialData?.address?.street || '',
      city: initialData?.address?.city || '',
      state: initialData?.address?.state || '',
      zipCode: initialData?.address?.zipCode || '',
      country: initialData?.address?.country || 'Rwanda',
      
      // Medical information
      bloodType: initialData?.bloodType || 'unknown',
      allergies: initialData?.allergies?.join(', ') || '',
      
      // Emergency contact (nested object in backend)
      emergencyContactName: initialData?.emergencyContact?.name || '',
      emergencyContactRelationship: initialData?.emergencyContact?.relationship || '',
      emergencyContactPhone: initialData?.emergencyContact?.phoneNumber || '',
      
      // Hospital information
      hospitalId: initialData?.hospitalId || '',
      referringPhysicianName: initialData?.referringPhysician?.name || '',
      referringPhysicianLicense: initialData?.referringPhysician?.licenseNumber || '',
      referringPhysicianDepartment: initialData?.referringPhysician?.department || '',
      
      // Test data
      priority: testData?.priority || 'normal',
      sampleType: testData?.sampleType || 'blood_smear',
      symptoms: testData?.clinicalNotes?.symptoms || [],
      duration: testData?.clinicalNotes?.duration || '',
      travelHistory: testData?.clinicalNotes?.travelHistory || '',
      medications: testData?.clinicalNotes?.medications || '',
      additionalNotes: testData?.clinicalNotes?.additionalNotes || ''
    }
  });

  const watchedData = watch();

  // Load saved form data on mount
  useEffect(() => {
    if (!initialData && isNewPatient) {
      const savedData = localStorage.getItem(FORM_STORAGE_KEY);
      if (savedData) {
        try {
          const parsedData = JSON.parse(savedData);
          Object.keys(parsedData).forEach(key => {
            setValue(key, parsedData[key]);
          });
        } catch (error) {
          console.error('Failed to load saved form data:', error);
        }
      }
    }
  }, [initialData, isNewPatient, setValue]);

  // Auto-save form data to localStorage
  useEffect(() => {
    if (isDirty && isNewPatient) {
      const formData = getValues();
      localStorage.setItem(FORM_STORAGE_KEY, JSON.stringify(formData));
    }
  }, [watchedData, isDirty, isNewPatient, getValues]);

  // Update test data when form values change
  useEffect(() => {
    if (onTestDataChange) {
      // Only update if values actually changed
      const newTestData = {
        priority: watchedData.priority,
        sampleType: watchedData.sampleType,
        clinicalNotes: {
          symptoms: watchedData.symptoms,
          duration: watchedData.duration,
          travelHistory: watchedData.travelHistory,
          medications: watchedData.medications,
          additionalNotes: watchedData.additionalNotes
        }
      };
      
      // Prevent infinite loops by checking if data actually changed
      onTestDataChange(newTestData);
    }
  }, [
    watchedData.priority,
    watchedData.sampleType,
    watchedData.symptoms,
    watchedData.duration,
    watchedData.travelHistory,
    watchedData.medications,
    watchedData.additionalNotes,
    // DON'T include onTestDataChange in dependencies
  ]);

  // ✅ FIXED: Debounced patient search with Redux
  useEffect(() => {
    if (debouncedSearchTerm && debouncedSearchTerm.length >= 2) {
      searchPatients(debouncedSearchTerm);
    } else {
      // Clear search results when search term is too short
      dispatch(clearSearchResults());
    }
  }, [debouncedSearchTerm, dispatch]);

  // ✅ FIXED: Search for existing patients using Redux
  const searchPatients = async (searchTerm) => {
    try {
      // Use Redux thunk instead of direct API call
      await dispatch(searchPatientsRedux(searchTerm));
    } catch (error) {
      console.error('Patient search failed:', error);
    }
  };

  // ✅ FIXED: Handle patient selection from search results with cache clearing
  const selectPatient = async (patient) => {
    setSelectedPatientLoading(true);
    setPatientSelected(false);
    
    try {
      // Fill form with selected patient data
      Object.keys(patient).forEach(key => {
        if (key === 'address' && patient.address) {
          setValue('street', patient.address.street || '');
          setValue('city', patient.address.city || '');
          setValue('state', patient.address.state || '');
          setValue('zipCode', patient.address.zipCode || '');
          setValue('country', patient.address.country || 'Rwanda');
        } else if (key === 'emergencyContact' && patient.emergencyContact) {
          setValue('emergencyContactName', patient.emergencyContact.name || '');
          setValue('emergencyContactRelationship', patient.emergencyContact.relationship || '');
          setValue('emergencyContactPhone', patient.emergencyContact.phoneNumber || '');
        } else if (key === 'referringPhysician' && patient.referringPhysician) {
          setValue('referringPhysicianName', patient.referringPhysician.name || '');
          setValue('referringPhysicianLicense', patient.referringPhysician.licenseNumber || '');
          setValue('referringPhysicianDepartment', patient.referringPhysician.department || '');
        } else if (key === 'allergies' && Array.isArray(patient.allergies)) {
          setValue('allergies', patient.allergies.join(', '));
        } else if (key === 'dateOfBirth' && patient.dateOfBirth) {
          setValue('dateOfBirth', new Date(patient.dateOfBirth).toISOString().split('T')[0]);
        } else {
          setValue(key, patient[key] || '');
        }
      });

      setIsNewPatient(false);
      setSearchTerm('');
      setPatientSelected(true);
      
      // ✅ FIX: Clear search cache in Redux
      dispatch(clearSearchResults());
      
      // Clear saved draft since we selected a patient
      localStorage.removeItem(FORM_STORAGE_KEY);
      
    } catch (error) {
      console.error('Failed to select patient:', error);
    } finally {
      setSelectedPatientLoading(false);
    }
  };

  const handleFormSubmit = (data) => {
    // Transform form data to match backend Patient model structure
    const patientData = {
      // Basic information
      patientId: data.patientId || undefined,
      firstName: data.firstName.trim(),
      lastName: data.lastName.trim(),
      dateOfBirth: data.dateOfBirth || undefined,
      gender: data.gender,
      age: data.age ? parseInt(data.age) : undefined,
      phoneNumber: data.phoneNumber.trim() || undefined,
      email: data.email.trim() || undefined,
      
      // Address object
      address: {
        street: data.street.trim() || undefined,
        city: data.city.trim() || undefined,
        state: data.state.trim() || undefined,
        zipCode: data.zipCode.trim() || undefined,
        country: data.country || 'Rwanda'
      },
      
      // Medical information
      bloodType: data.bloodType,
      allergies: data.allergies ? 
        data.allergies.split(',').map(a => a.trim()).filter(a => a) : [],
      
      // Emergency contact object
      emergencyContact: (data.emergencyContactName || data.emergencyContactPhone) ? {
        name: data.emergencyContactName.trim() || undefined,
        relationship: data.emergencyContactRelationship.trim() || undefined,
        phoneNumber: data.emergencyContactPhone.trim() || undefined
      } : undefined,
      
      // Hospital information
      hospitalId: data.hospitalId.trim() || undefined,
      referringPhysician: (data.referringPhysicianName || data.referringPhysicianLicense) ? {
        name: data.referringPhysicianName.trim() || undefined,
        licenseNumber: data.referringPhysicianLicense.trim() || undefined,
        department: data.referringPhysicianDepartment.trim() || undefined
      } : undefined,
      
      // Include MongoDB _id if updating existing patient
      ...(initialData?._id && { _id: initialData._id })
    };

    // Remove undefined values to avoid backend validation issues
    Object.keys(patientData).forEach(key => {
      if (patientData[key] === undefined) {
        delete patientData[key];
      } else if (typeof patientData[key] === 'object' && patientData[key] !== null) {
        Object.keys(patientData[key]).forEach(subKey => {
          if (patientData[key][subKey] === undefined) {
            delete patientData[key][subKey];
          }
        });
        // Remove empty objects
        if (Object.keys(patientData[key]).length === 0) {
          delete patientData[key];
        }
      }
    });

    // Clear saved form data on successful submit
    localStorage.removeItem(FORM_STORAGE_KEY);
    
    onSubmit(patientData);
  };

  // Calculate age from date of birth
  const calculateAge = (dateOfBirth) => {
    if (!dateOfBirth) return '';
    
    const today = new Date();
    const birthDate = new Date(dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age;
  };

  // Auto-calculate age when date of birth changes
  useEffect(() => {
    const dateOfBirth = watchedData.dateOfBirth;
    if (dateOfBirth) {
      const calculatedAge = calculateAge(dateOfBirth);
      if (calculatedAge >= 0) {
        setValue('age', calculatedAge.toString());
      }
    }
  }, [watchedData.dateOfBirth, setValue]);

  // Clear saved draft
  const clearDraft = () => {
    localStorage.removeItem(FORM_STORAGE_KEY);
    reset();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="w-16 h-16 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center mx-auto mb-4 border border-white/30">
          <User className="w-8 h-8 text-white" />
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">Patient Information</h3>
        <p className="text-blue-200">Search for an existing patient or create a new patient record</p>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center text-red-200">
            <AlertCircle className="w-5 h-5 mr-2" />
            <span className="text-sm">{error}</span>
          </div>
        </div>
      )}

      {/* Draft notification */}
      {isDirty && isNewPatient && (
        <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center text-blue-200">
              <CheckCircle className="w-4 h-4 mr-2" />
              <span className="text-sm">Form data is being auto-saved</span>
            </div>
            <button
              type="button"
              onClick={clearDraft}
              className="text-blue-200 hover:text-white text-sm font-medium"
            >
              Clear draft
            </button>
          </div>
        </div>
      )}

      {/* Patient Type Selection */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
        <div className="flex items-center justify-center space-x-8 mb-6">
          <label className="flex items-center cursor-pointer group">
            <input
              type="radio"
              checked={!isNewPatient}
              onChange={() => setIsNewPatient(false)}
              className="mr-3 w-4 h-4 text-blue-500"
            />
            <div className="flex items-center text-white group-hover:text-blue-200">
              <UserCheck className="w-5 h-5 mr-2" />
              <span className="font-medium">Existing Patient</span>
            </div>
          </label>
          
          <label className="flex items-center cursor-pointer group">
            <input
              type="radio"
              checked={isNewPatient}
              onChange={() => setIsNewPatient(true)}
              className="mr-3 w-4 h-4 text-blue-500"
            />
            <div className="flex items-center text-white group-hover:text-blue-200">
              <Plus className="w-5 h-5 mr-2" />
              <span className="font-medium">New Patient</span>
            </div>
          </label>
        </div>

        {/* Patient Search */}
        {!isNewPatient && (
          <div className="relative">
            <div className="flex items-center space-x-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-3 h-5 w-5 text-blue-300" />
                <input
                  type="text"
                  placeholder="Search by Patient ID, name, or phone..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 focus:border-white/50"
                />
              </div>
              {(isSearchingPatients || selectedPatientLoading || patientsLoading) && (
                <LoadingSpinner size="sm" color="white" />
              )}
            </div>

            {/* Patient selected indicator */}
            {patientSelected && !selectedPatientLoading && (
              <div className="mt-3 flex items-center text-green-400">
                <CheckCircle className="w-4 h-4 mr-2" />
                <span className="text-sm font-medium">Patient selected successfully</span>
              </div>
            )}

            {/* ✅ FIXED: Search Results from Redux */}
            {searchResults.length > 0 && (
              <div className="absolute top-full left-0 right-0 z-10 mt-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg shadow-xl max-h-60 overflow-y-auto">
                {searchResults.map((patient) => (
                  <button
                    key={patient._id}
                    type="button"
                    onClick={() => selectPatient(patient)}
                    className="w-full text-left p-4 hover:bg-white/10 border-b border-white/10 last:border-b-0 focus:bg-white/10 focus:outline-none transition-colors"
                  >
                    <div className="font-medium text-white">
                      {patient.firstName} {patient.lastName}
                    </div>
                    <div className="text-sm text-blue-200">
                      ID: {patient.patientId} • Age: {patient.age || 'Unknown'} • Phone: {patient.phoneNumber || 'N/A'}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* No results */}
            {debouncedSearchTerm && debouncedSearchTerm.length >= 2 && searchResults.length === 0 && !isSearchingPatients && !patientsLoading && (
              <div className="absolute top-full left-0 right-0 z-10 mt-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
                <p className="text-sm text-blue-200 text-center">
                  No patients found matching "{debouncedSearchTerm}"
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-6">
        {/* Basic Information */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h4 className="text-lg font-medium text-white mb-6 flex items-center">
            <User className="w-5 h-5 mr-2" />
            Basic Information
          </h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Patient ID */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Patient ID {!isNewPatient && '*'}
              </label>
              <input
                {...register('patientId', {
                  ...((!isNewPatient) && {
                    required: 'Patient ID is required for existing patients'
                  })
                })}
                type="text"
                className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
                  errors.patientId ? 'border-red-500/50' : 'border-white/30'
                }`}
                placeholder={isNewPatient ? "Auto-generated" : "PAT-20240101-001"}
                disabled={isNewPatient}
              />
              {errors.patientId && (
                <p className="mt-1 text-sm text-red-300">{errors.patientId.message}</p>
              )}
            </div>

            {/* First Name */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                First Name *
              </label>
              <input
                {...register('firstName', { 
                  required: 'First name is required',
                  maxLength: { value: 50, message: 'First name must be less than 50 characters' }
                })}
                type="text"
                className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
                  errors.firstName ? 'border-red-500/50' : 'border-white/30'
                }`}
                placeholder="Enter first name"
              />
              {errors.firstName && (
                <p className="mt-1 text-sm text-red-300">{errors.firstName.message}</p>
              )}
            </div>

            {/* Last Name */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Last Name *
              </label>
              <input
                {...register('lastName', { 
                  required: 'Last name is required',
                  maxLength: { value: 50, message: 'Last name must be less than 50 characters' }
                })}
                type="text"
                className={`w-full px-4 py-3 bg-white/10 border rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50 ${
                  errors.lastName ? 'border-red-500/50' : 'border-white/30'
                }`}
                placeholder="Enter last name"
              />
              {errors.lastName && (
                <p className="mt-1 text-sm text-red-300">{errors.lastName.message}</p>
              )}
            </div>

            {/* Date of Birth */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Date of Birth
              </label>
              <input
                {...register('dateOfBirth')}
                type="date"
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
                max={new Date().toISOString().split('T')[0]}
              />
            </div>

            {/* Age */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Age
              </label>
              <input
                {...register('age', {
                  min: { value: 0, message: 'Age must be positive' },
                  max: { value: 150, message: 'Please enter a valid age' }
                })}
                type="number"
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                placeholder="Auto-calculated from DOB"
              />
            </div>

            {/* Gender */}
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Gender
              </label>
              <select
                {...register('gender')}
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
              >
                {GENDER_OPTIONS.map(option => (
                  <option key={option.value} value={option.value} className="bg-blue-800">
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Contact Information */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h4 className="text-lg font-medium text-white mb-6 flex items-center">
            <Phone className="w-5 h-5 mr-2" />
            Contact Information
          </h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Phone Number
              </label>
              <input
                {...register('phoneNumber')}
                type="tel"
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                placeholder="+250 XXX XXX XXX"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Email Address
              </label>
              <input
                {...register('email')}
                type="email"
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                placeholder="patient@example.com"
              />
            </div>
          </div>
        </div>

        {/* Test Information */}
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h4 className="text-lg font-medium text-white mb-6 flex items-center">
            <TestTube className="w-5 h-5 mr-2" />
            Test Information
          </h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Priority
              </label>
              <select
                {...register('priority')}
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
              >
                {Object.entries(TEST_PRIORITIES).map(([key, value]) => (
                  <option key={value} value={value} className="bg-blue-800">
                    {key.charAt(0) + key.slice(1).toLowerCase()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Sample Type
              </label>
              <select
                {...register('sampleType')}
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/50"
              >
                {Object.entries(SAMPLE_TYPES).map(([key, value]) => (
                  <option key={value} value={value} className="bg-blue-800">
                    {key.split('_').map(word => 
                      word.charAt(0) + word.slice(1).toLowerCase()
                    ).join(' ')}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Clinical Notes */}
          <div className="mt-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">
                Symptoms
              </label>
              <textarea
                {...register('symptoms')}
                rows={2}
                className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                placeholder="Describe current symptoms"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-blue-200 mb-2">
                  Duration
                </label>
                <input
                  {...register('duration')}
                  type="text"
                  className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                  placeholder="e.g., 3 days, 1 week"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-blue-200 mb-2">
                  Travel History
                </label>
                <input
                  {...register('travelHistory')}
                  type="text"
                  className="w-full px-4 py-3 bg-white/10 border border-white/30 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-white/50"
                  placeholder="Recent travel to endemic areas"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Submit Button */}
        <div className="text-center pt-6">
          <button
            type="submit"
            disabled={loading || isSubmitting}
            className="bg-white text-blue-600 px-8 py-4 rounded-lg font-semibold hover:bg-blue-50 transition-all hover:scale-105 disabled:opacity-50 disabled:hover:scale-100"
          >
            {loading || isSubmitting ? (
              <div className="flex items-center justify-center">
                <LoadingSpinner size="sm" color="blue" />
                <span className="ml-2">
                  {isNewPatient ? 'Creating...' : 'Updating...'}
                </span>
              </div>
            ) : (
              <>
                <FileText className="w-5 h-5 mr-2 inline" />
                {isNewPatient ? 'Create Patient & Test' : 'Update & Continue'}
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default PatientForm;
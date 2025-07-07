// 📁 client/src/components/upload/PatientForm.jsx
// Updated to match your backend Patient model exactly

import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
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
  UserCheck
} from 'lucide-react';
import LoadingSpinner from '../common/LoadingSpinner';
import { 
  GENDER_OPTIONS, 
  BLOOD_TYPES, 
  TEST_PRIORITIES, 
  SAMPLE_TYPES,
  VALIDATION_RULES,
  PATIENT_ID_FORMAT
} from '../../utils/constants';
import apiService from '../../services/api';

const PatientForm = ({ 
  initialData, 
  testData, 
  onSubmit, 
  onTestDataChange, 
  loading = false, 
  error 
}) => {
  const [isNewPatient, setIsNewPatient] = useState(!initialData);
  const [searchingPatient, setSearchingPatient] = useState(false);
  const [searchResults, setSearchResults] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showEmergencyContact, setShowEmergencyContact] = useState(false);
  const [showMedicalHistory, setShowMedicalHistory] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
    watch,
    setValue,
    getValues
  } = useForm({
    defaultValues: {
      // Patient data (matching backend Patient model)
      patientId: initialData?.patientId || '', // Will be auto-generated if empty
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
      symptoms: testData?.clinicalNotes?.symptoms || '',
      duration: testData?.clinicalNotes?.duration || '',
      travelHistory: testData?.clinicalNotes?.travelHistory || '',
      medications: testData?.clinicalNotes?.medications || '',
      additionalNotes: testData?.clinicalNotes?.additionalNotes || ''
    }
  });

  const watchedData = watch();

  // Update test data when form values change
  useEffect(() => {
    if (onTestDataChange) {
      onTestDataChange({
        priority: watchedData.priority,
        sampleType: watchedData.sampleType,
        clinicalNotes: {
          symptoms: watchedData.symptoms,
          duration: watchedData.duration,
          travelHistory: watchedData.travelHistory,
          medications: watchedData.medications,
          additionalNotes: watchedData.additionalNotes
        }
      });
    }
  }, [watchedData, onTestDataChange]);

  // Search for existing patients
  const searchPatients = async (searchTerm) => {
    if (!searchTerm || searchTerm.length < 2) {
      setSearchResults([]);
      return;
    }

    setSearchingPatient(true);
    try {
      const response = await apiService.patients.search(searchTerm);
      if (response.success) {
        setSearchResults(response.data || []);
      }
    } catch (error) {
      console.error('Patient search failed:', error);
      setSearchResults([]);
    } finally {
      setSearchingPatient(false);
    }
  };

  // Handle patient selection from search results
  const selectPatient = (patient) => {
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
    setSearchResults([]);
    setSearchTerm('');
  };

  const handleFormSubmit = (data) => {
    // Transform form data to match backend Patient model structure
    const patientData = {
      // Basic information
      patientId: data.patientId || undefined, // Let backend auto-generate if empty
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

  return (
    <div className="p-6">
      <div className="mb-6">
        <h3 className="text-lg font-medium text-gray-900 mb-2">Patient Information</h3>
        <p className="text-sm text-gray-600">
          Search for an existing patient or create a new patient record
        </p>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center">
            <AlertCircle className="w-5 h-5 text-red-400 mr-2" />
            <span className="text-red-800 text-sm">{error}</span>
          </div>
        </div>
      )}

      {/* Patient Search/Type Selection */}
      <div className="mb-6 p-4 bg-gray-50 rounded-lg">
        <div className="flex items-center space-x-4 mb-4">
          <label className="flex items-center">
            <input
              type="radio"
              checked={!isNewPatient}
              onChange={() => setIsNewPatient(false)}
              className="mr-2"
            />
            <UserCheck className="w-4 h-4 mr-2" />
            <span className="text-sm font-medium">Existing Patient</span>
          </label>
          <label className="flex items-center">
            <input
              type="radio"
              checked={isNewPatient}
              onChange={() => setIsNewPatient(true)}
              className="mr-2"
            />
            <Plus className="w-4 h-4 mr-2" />
            <span className="text-sm font-medium">New Patient</span>
          </label>
        </div>

        {/* Patient Search */}
        {!isNewPatient && (
          <div className="relative">
            <div className="flex items-center space-x-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by Patient ID, name, or phone..."
                  value={searchTerm}
                  onChange={(e) => {
                    setSearchTerm(e.target.value);
                    searchPatients(e.target.value);
                  }}
                  className="input pl-10"
                />
              </div>
              {searchingPatient && <LoadingSpinner size="sm" />}
            </div>

            {/* Search Results */}
            {searchResults.length > 0 && (
              <div className="absolute top-full left-0 right-0 z-10 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                {searchResults.map((patient) => (
                  <button
                    key={patient._id}
                    type="button"
                    onClick={() => selectPatient(patient)}
                    className="w-full text-left p-3 hover:bg-gray-50 border-b border-gray-100 last:border-b-0"
                  >
                    <div className="font-medium text-gray-900">
                      {patient.firstName} {patient.lastName}
                    </div>
                    <div className="text-sm text-gray-600">
                      ID: {patient.patientId} • Age: {patient.age || 'Unknown'} • 
                      Phone: {patient.phoneNumber || 'N/A'}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-6">
        {/* Basic Patient Information */}
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-md font-medium text-gray-900 mb-4">Basic Information</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Patient ID */}
            <div>
              <label htmlFor="patientId" className="block text-sm font-medium text-gray-700 mb-2">
                Patient ID {!isNewPatient && '*'}
              </label>
              <input
                {...register('patientId', {
                  ...((!isNewPatient) && {
                    required: 'Patient ID is required for existing patients',
                    pattern: {
                      value: PATIENT_ID_FORMAT,
                      message: 'Invalid Patient ID format (PAT-YYYYMMDD-XXX)'
                    }
                  })
                })}
                type="text"
                className={`input ${errors.patientId ? 'input-error' : ''}`}
                placeholder={isNewPatient ? "Auto-generated" : "PAT-20240101-001"}
                disabled={isNewPatient}
              />
              {errors.patientId && (
                <p className="mt-1 text-sm text-red-600">{errors.patientId.message}</p>
              )}
              {isNewPatient && (
                <p className="mt-1 text-sm text-gray-500">Patient ID will be auto-generated</p>
              )}
            </div>

            {/* First Name */}
            <div>
              <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-2">
                First Name *
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('firstName', { 
                    required: 'First name is required',
                    maxLength: { value: 50, message: 'First name must be less than 50 characters' }
                  })}
                  type="text"
                  className={`input pl-10 ${errors.firstName ? 'input-error' : ''}`}
                  placeholder="Enter first name"
                />
              </div>
              {errors.firstName && (
                <p className="mt-1 text-sm text-red-600">{errors.firstName.message}</p>
              )}
            </div>

            {/* Last Name */}
            <div>
              <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-2">
                Last Name *
              </label>
              <input
                {...register('lastName', { 
                  required: 'Last name is required',
                  maxLength: { value: 50, message: 'Last name must be less than 50 characters' }
                })}
                type="text"
                className={`input ${errors.lastName ? 'input-error' : ''}`}
                placeholder="Enter last name"
              />
              {errors.lastName && (
                <p className="mt-1 text-sm text-red-600">{errors.lastName.message}</p>
              )}
            </div>

            {/* Date of Birth */}
            <div>
              <label htmlFor="dateOfBirth" className="block text-sm font-medium text-gray-700 mb-2">
                Date of Birth
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Calendar className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('dateOfBirth', {
                    validate: (value) => {
                      if (!value) return true; // Optional field
                      const date = new Date(value);
                      const today = new Date();
                      if (date > today) return 'Date of birth cannot be in the future';
                      if (date < new Date('1900-01-01')) return 'Please enter a valid date of birth';
                      return true;
                    }
                  })}
                  type="date"
                  className={`input pl-10 ${errors.dateOfBirth ? 'input-error' : ''}`}
                  max={new Date().toISOString().split('T')[0]}
                />
              </div>
              {errors.dateOfBirth && (
                <p className="mt-1 text-sm text-red-600">{errors.dateOfBirth.message}</p>
              )}
            </div>

            {/* Age */}
            <div>
              <label htmlFor="age" className="block text-sm font-medium text-gray-700 mb-2">
                Age
              </label>
              <input
                {...register('age', {
                  min: { value: 0, message: 'Age must be positive' },
                  max: { value: 150, message: 'Please enter a valid age' },
                  pattern: {
                    value: /^\d+$/,
                    message: 'Age must be a number'
                  }
                })}
                type="number"
                className={`input ${errors.age ? 'input-error' : ''}`}
                placeholder="Auto-calculated from DOB"
                min="0"
                max="150"
              />
              {errors.age && (
                <p className="mt-1 text-sm text-red-600">{errors.age.message}</p>
              )}
            </div>

            {/* Gender */}
            <div>
              <label htmlFor="gender" className="block text-sm font-medium text-gray-700 mb-2">
                Gender
              </label>
              <select
                {...register('gender')}
                className="input"
              >
                {GENDER_OPTIONS.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Contact Information */}
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-md font-medium text-gray-900 mb-4">Contact Information</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Phone */}
            <div>
              <label htmlFor="phoneNumber" className="block text-sm font-medium text-gray-700 mb-2">
                Phone Number
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Phone className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('phoneNumber', {
                    pattern: {
                      value: VALIDATION_RULES.PHONE.PATTERN,
                      message: VALIDATION_RULES.PHONE.MESSAGE
                    }
                  })}
                  type="tel"
                  className={`input pl-10 ${errors.phoneNumber ? 'input-error' : ''}`}
                  placeholder="+250 XXX XXX XXX"
                />
              </div>
              {errors.phoneNumber && (
                <p className="mt-1 text-sm text-red-600">{errors.phoneNumber.message}</p>
              )}
            </div>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('email', {
                    pattern: {
                      value: VALIDATION_RULES.EMAIL.PATTERN,
                      message: VALIDATION_RULES.EMAIL.MESSAGE
                    }
                  })}
                  type="email"
                  className={`input pl-10 ${errors.email ? 'input-error' : ''}`}
                  placeholder="patient@example.com"
                />
              </div>
              {errors.email && (
                <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
              )}
            </div>
          </div>

          {/* Address */}
          <div className="mt-4 space-y-4">
            <div>
              <label htmlFor="street" className="block text-sm font-medium text-gray-700 mb-2">
                Street Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <MapPin className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  {...register('street')}
                  type="text"
                  className="input pl-10"
                  placeholder="Street address"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label htmlFor="city" className="block text-sm font-medium text-gray-700 mb-2">
                  City
                </label>
                <input
                  {...register('city')}
                  type="text"
                  className="input"
                  placeholder="City"
                />
              </div>

              <div>
                <label htmlFor="state" className="block text-sm font-medium text-gray-700 mb-2">
                  Province/State
                </label>
                <input
                  {...register('state')}
                  type="text"
                  className="input"
                  placeholder="Province"
                />
              </div>

              <div>
                <label htmlFor="zipCode" className="block text-sm font-medium text-gray-700 mb-2">
                  Postal Code
                </label>
                <input
                  {...register('zipCode')}
                  type="text"
                  className="input"
                  placeholder="Postal code"
                />
              </div>
            </div>

            <div>
              <label htmlFor="country" className="block text-sm font-medium text-gray-700 mb-2">
                Country
              </label>
              <input
                {...register('country')}
                type="text"
                className="input"
                defaultValue="Rwanda"
              />
            </div>
          </div>
        </div>

        {/* Medical Information */}
        <div className="border border-gray-200 rounded-lg p-4">
          <h4 className="text-md font-medium text-gray-900 mb-4">Medical Information</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="bloodType" className="block text-sm font-medium text-gray-700 mb-2">
                Blood Type
              </label>
              <select
                {...register('bloodType')}
                className="input"
              >
                {BLOOD_TYPES.map(type => (
                  <option key={type} value={type}>
                    {type === 'unknown' ? 'Unknown' : type}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="allergies" className="block text-sm font-medium text-gray-700 mb-2">
                Allergies
              </label>
              <input
                {...register('allergies')}
                type="text"
                className="input"
                placeholder="Comma-separated list of allergies"
              />
              <p className="mt-1 text-sm text-gray-500">
                Separate multiple allergies with commas
              </p>
            </div>
          </div>
        </div>

        {/* Emergency Contact - Collapsible */}
        <div className="border border-gray-200 rounded-lg p-4">
          <button
            type="button"
            onClick={() => setShowEmergencyContact(!showEmergencyContact)}
            className="flex items-center justify-between w-full text-left"
          >
            <h4 className="text-md font-medium text-gray-900">Emergency Contact</h4>
            <span className="text-gray-400">
              {showEmergencyContact ? '−' : '+'}
            </span>
          </button>
          
          {showEmergencyContact && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label htmlFor="emergencyContactName" className="block text-sm font-medium text-gray-700 mb-2">
                  Name
                </label>
                <input
                  {...register('emergencyContactName')}
                  type="text"
                  className="input"
                  placeholder="Emergency contact name"
                />
              </div>

              <div>
                <label htmlFor="emergencyContactRelationship" className="block text-sm font-medium text-gray-700 mb-2">
                  Relationship
                </label>
                <input
                  {...register('emergencyContactRelationship')}
                  type="text"
                  className="input"
                  placeholder="e.g., Spouse, Parent, Sibling"
                />
              </div>

              <div>
                <label htmlFor="emergencyContactPhone" className="block text-sm font-medium text-gray-700 mb-2">
                  Phone Number
                </label>
                <input
                  {...register('emergencyContactPhone')}
                  type="tel"
                  className="input"
                  placeholder="Emergency contact phone"
                />
              </div>
            </div>
          )}
        </div>

        {/* Test Information */}
        <div className="border-t border-gray-200 pt-6">
          <h4 className="text-md font-medium text-gray-900 mb-4">Test Information</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Priority */}
            <div>
              <label htmlFor="priority" className="block text-sm font-medium text-gray-700 mb-2">
                Priority
              </label>
              <select
                {...register('priority')}
                className="input"
              >
                {Object.entries(TEST_PRIORITIES).map(([key, value]) => (
                  <option key={value} value={value}>
                    {key.charAt(0) + key.slice(1).toLowerCase()}
                  </option>
                ))}
              </select>
            </div>

            {/* Sample Type */}
            <div>
              <label htmlFor="sampleType" className="block text-sm font-medium text-gray-700 mb-2">
                Sample Type
              </label>
              <select
                {...register('sampleType')}
                className="input"
              >
                {Object.entries(SAMPLE_TYPES).map(([key, value]) => (
                  <option key={value} value={value}>
                    {key.split('_').map(word => 
                      word.charAt(0) + word.slice(1).toLowerCase()
                    ).join(' ')}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Clinical Notes */}
        <div className="border-t border-gray-200 pt-6">
          <h4 className="text-md font-medium text-gray-900 mb-4">Clinical Notes</h4>
          
          <div className="space-y-4">
            <div>
              <label htmlFor="symptoms" className="block text-sm font-medium text-gray-700 mb-2">
                Symptoms
              </label>
              <textarea
                {...register('symptoms')}
                rows={2}
                className="input"
                placeholder="Describe current symptoms"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="duration" className="block text-sm font-medium text-gray-700 mb-2">
                  Duration
                </label>
                <input
                  {...register('duration')}
                  type="text"
                  className="input"
                  placeholder="e.g., 3 days, 1 week"
                />
              </div>

              <div>
                <label htmlFor="travelHistory" className="block text-sm font-medium text-gray-700 mb-2">
                  Travel History
                </label>
                <input
                  {...register('travelHistory')}
                  type="text"
                  className="input"
                  placeholder="Recent travel to endemic areas"
                />
              </div>
            </div>

            <div>
              <label htmlFor="medications" className="block text-sm font-medium text-gray-700 mb-2">
                Current Medications
              </label>
              <textarea
                {...register('medications')}
                rows={2}
                className="input"
                placeholder="List current medications"
              />
            </div>

            <div>
              <label htmlFor="additionalNotes" className="block text-sm font-medium text-gray-700 mb-2">
                Additional Notes
              </label>
              <textarea
                {...register('additionalNotes')}
                rows={3}
                className="input"
                placeholder="Any additional clinical information"
              />
            </div>
          </div>
        </div>

        {/* Submit Button */}
        <div className="flex justify-end pt-6 border-t border-gray-200">
          <button
            type="submit"
            disabled={loading || isSubmitting}
            className="btn btn-primary"
          >
            {loading || isSubmitting ? (
              <div className="flex items-center">
                <LoadingSpinner size="sm" color="white" />
                <span className="ml-2">
                  {isNewPatient ? 'Creating...' : 'Updating...'}
                </span>
              </div>
            ) : (
              <>
                <FileText className="w-4 h-4 mr-2" />
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
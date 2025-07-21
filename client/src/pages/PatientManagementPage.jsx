import React, { useState } from 'react';
import { 
  Search, 
  Plus, 
  Eye, 
  Edit, 
  MoreHorizontal,
  User,
  Calendar,
  Phone,
  Mail,
  MapPin,
  Activity,
  TestTube,
  Clock,
  Filter,
  Download,
  ArrowLeft,
  X,
  Save,
  AlertTriangle,
  CheckCircle,
  FileText,
  Heart,
  Users,
  TrendingUp,
  ChevronRight,
  ChevronLeft,
  ArrowUpDown
} from 'lucide-react';

const PatientManagementPage = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedPatient, setSelectedPatient] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [currentView, setCurrentView] = useState('list'); // 'list', 'details', 'history'
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState('name');
  const [sortDirection, setSortDirection] = useState('asc');

  const patientsPerPage = 8;

  // Mock patient data
  const allPatients = [
    {
      id: 'PAT-20250711-012',
      name: 'John Doe',
      age: 32,
      gender: 'Male',
      bloodType: 'O+',
      phone: '+250 788 123 456',
      email: 'john.doe@email.com',
      address: 'Kigali, Rwanda',
      dateOfBirth: '1992-03-15',
      createdAt: '2025-07-10T09:30:00Z',
      lastTest: '2025-07-11T14:32:18Z',
      totalTests: 3,
      positiveTests: 1,
      medicalHistory: 'Previous malaria episode in 2023',
      emergencyContact: 'Jane Doe - +250 788 654 321',
      allergies: 'None known'
    },
    {
      id: 'PAT-20250710-089',
      name: 'Alice Smith',
      age: 28,
      gender: 'Female',
      bloodType: 'A+',
      phone: '+250 788 234 567',
      email: 'alice.smith@email.com',
      address: 'Nyanza, Rwanda',
      dateOfBirth: '1996-08-22',
      createdAt: '2025-07-09T14:20:00Z',
      lastTest: '2025-07-11T13:45:22Z',
      totalTests: 2,
      positiveTests: 0,
      medicalHistory: 'No significant medical history',
      emergencyContact: 'Robert Smith - +250 788 765 432',
      allergies: 'Penicillin'
    },
    {
      id: 'PAT-20250711-009',
      name: 'Robert Brown',
      age: 45,
      gender: 'Male',
      bloodType: 'B+',
      phone: '+250 788 345 678',
      email: 'robert.brown@email.com',
      address: 'Huye, Rwanda',
      dateOfBirth: '1979-12-08',
      createdAt: '2025-07-11T08:15:00Z',
      lastTest: '2025-07-11T12:18:45Z',
      totalTests: 1,
      positiveTests: 0,
      medicalHistory: 'Hypertension, Diabetes Type 2',
      emergencyContact: 'Mary Brown - +250 788 876 543',
      allergies: 'Sulfa drugs'
    },
    {
      id: 'PAT-20250710-087',
      name: 'Emma Wilson',
      age: 24,
      gender: 'Female',
      bloodType: 'AB+',
      phone: '+250 788 456 789',
      email: 'emma.wilson@email.com',
      address: 'Musanze, Rwanda',
      dateOfBirth: '2000-05-14',
      createdAt: '2025-07-10T16:45:00Z',
      lastTest: '2025-07-11T11:22:33Z',
      totalTests: 4,
      positiveTests: 2,
      medicalHistory: 'Recurrent malaria episodes',
      emergencyContact: 'David Wilson - +250 788 987 654',
      allergies: 'None known'
    },
    {
      id: 'PAT-20250710-085',
      name: 'Michael Johnson',
      age: 38,
      gender: 'Male',
      bloodType: 'O-',
      phone: '+250 788 567 890',
      email: 'michael.johnson@email.com',
      address: 'Rubavu, Rwanda',
      dateOfBirth: '1986-11-30',
      createdAt: '2025-07-10T11:30:00Z',
      lastTest: '2025-07-11T10:15:12Z',
      totalTests: 5,
      positiveTests: 1,
      medicalHistory: 'Asthma',
      emergencyContact: 'Sarah Johnson - +250 788 098 765',
      allergies: 'Shellfish'
    }
  ];

  // Mock test history for selected patient
  const patientTestHistory = [
    {
      id: 'TEST-20250711-045',
      date: '2025-07-11T14:32:18Z',
      result: 'positive',
      severity: 'moderate',
      parasiteType: 'PF',
      technician: 'Maria Garcia',
      status: 'completed'
    },
    {
      id: 'TEST-20250709-032',
      date: '2025-07-09T09:15:30Z',
      result: 'negative',
      severity: 'negative',
      parasiteType: null,
      technician: 'James Wilson',
      status: 'completed'
    },
    {
      id: 'TEST-20250705-018',
      date: '2025-07-05T16:22:45Z',
      result: 'negative',
      severity: 'negative',
      parasiteType: null,
      technician: 'Sarah Chen',
      status: 'completed'
    }
  ];

  const [newPatient, setNewPatient] = useState({
    name: '',
    dateOfBirth: '',
    gender: '',
    bloodType: '',
    phone: '',
    email: '',
    address: '',
    emergencyContact: '',
    medicalHistory: '',
    allergies: ''
  });

  const filteredPatients = allPatients.filter(patient => {
    if (!searchTerm) return true;
    
    const searchFields = [
      patient.name,
      patient.id,
      patient.phone,
      patient.email
    ].join(' ').toLowerCase();
    
    return searchFields.includes(searchTerm.toLowerCase());
  });

  const sortedPatients = [...filteredPatients].sort((a, b) => {
    let aValue = a[sortField];
    let bValue = b[sortField];

    if (sortField === 'lastTest' || sortField === 'createdAt') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    }

    if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.ceil(sortedPatients.length / patientsPerPage);
  const startIndex = (currentPage - 1) * patientsPerPage;
  const paginatedPatients = sortedPatients.slice(startIndex, startIndex + patientsPerPage);

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const calculateAge = (dateOfBirth) => {
    const today = new Date();
    const birth = new Date(dateOfBirth);
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age--;
    }
    
    return age;
  };

  const getRiskLevel = (patient) => {
    const riskScore = patient.positiveTests / patient.totalTests;
    if (riskScore >= 0.5) return { level: 'High', color: 'bg-red-100 text-red-800 border-red-200' };
    if (riskScore >= 0.25) return { level: 'Medium', color: 'bg-yellow-100 text-yellow-800 border-yellow-200' };
    return { level: 'Low', color: 'bg-green-100 text-green-800 border-green-200' };
  };

  const getResultBadge = (result, severity, parasiteType) => {
    if (result === 'positive') {
      const severityStyles = {
        mild: "bg-yellow-100 text-yellow-800 border-yellow-200",
        moderate: "bg-orange-100 text-orange-800 border-orange-200",
        severe: "bg-red-100 text-red-800 border-red-200"
      };
      return (
        <span className={`px-2 py-1 rounded-full text-xs font-medium border ${severityStyles[severity]}`}>
          {result} ({parasiteType})
        </span>
      );
    } else if (result === 'negative') {
      return (
        <span className="px-2 py-1 rounded-full text-xs font-medium border bg-green-100 text-green-800 border-green-200">
          negative
        </span>
      );
    }
    return null;
  };

  const handleCreatePatient = () => {
    // In real implementation, this would call the API
    console.log('Creating patient:', newPatient);
    setShowCreateModal(false);
    setNewPatient({
      name: '',
      dateOfBirth: '',
      gender: '',
      bloodType: '',
      phone: '',
      email: '',
      address: '',
      emergencyContact: '',
      medicalHistory: '',
      allergies: ''
    });
  };

  const PatientDetailsView = ({ patient }) => (
    <div className="space-y-6">
      {/* Patient Header */}
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-4">
            <div className="bg-blue-500 p-3 rounded-full">
              <User className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white">{patient.name}</h2>
              <p className="text-blue-200">{patient.id}</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowEditModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors"
            >
              <Edit className="h-4 w-4" />
              <span>Edit</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-white transition-colors">
              <TestTube className="h-4 w-4" />
              <span>New Test</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white/5 border border-white/10 rounded-lg p-4">
            <div className="flex items-center space-x-3">
              <Activity className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-blue-200 text-sm">Total Tests</p>
                <p className="text-white font-medium text-xl">{patient.totalTests}</p>
              </div>
            </div>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-lg p-4">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="h-5 w-5 text-orange-400" />
              <div>
                <p className="text-blue-200 text-sm">Positive Tests</p>
                <p className="text-white font-medium text-xl">{patient.positiveTests}</p>
              </div>
            </div>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-lg p-4">
            <div className="flex items-center space-x-3">
              <TrendingUp className="h-5 w-5 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Risk Level</p>
                <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevel(patient).color}`}>
                  {getRiskLevel(patient).level}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Patient Information */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Personal Information</h3>
          <div className="space-y-4">
            <div className="flex items-center space-x-3">
              <Calendar className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Date of Birth</p>
                <p className="text-white">{formatDate(patient.dateOfBirth)} ({patient.age} years old)</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <User className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Gender</p>
                <p className="text-white">{patient.gender}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Heart className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Blood Type</p>
                <p className="text-white">{patient.bloodType}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Contact Information</h3>
          <div className="space-y-4">
            <div className="flex items-center space-x-3">
              <Phone className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Phone</p>
                <p className="text-white">{patient.phone}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Mail className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Email</p>
                <p className="text-white">{patient.email}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <MapPin className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-blue-200 text-sm">Address</p>
                <p className="text-white">{patient.address}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Medical Information</h3>
          <div className="space-y-4">
            <div>
              <p className="text-blue-200 text-sm mb-1">Medical History</p>
              <p className="text-white text-sm">{patient.medicalHistory || 'No significant medical history'}</p>
            </div>
            <div>
              <p className="text-blue-200 text-sm mb-1">Allergies</p>
              <p className="text-white text-sm">{patient.allergies || 'None known'}</p>
            </div>
            <div>
              <p className="text-blue-200 text-sm mb-1">Emergency Contact</p>
              <p className="text-white text-sm">{patient.emergencyContact}</p>
            </div>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Test History</h3>
          <div className="space-y-3">
            {patientTestHistory.slice(0, 3).map((test) => (
              <div key={test.id} className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                <div>
                  <p className="text-white text-sm font-medium">{test.id}</p>
                  <p className="text-blue-300 text-xs">{formatDate(test.date)}</p>
                </div>
                <div className="text-right">
                  {getResultBadge(test.result, test.severity, test.parasiteType)}
                </div>
              </div>
            ))}
            <button
              onClick={() => setCurrentView('history')}
              className="w-full text-blue-300 hover:text-white text-sm py-2 border border-white/20 rounded-lg hover:bg-white/5 transition-colors"
            >
              View Full History
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const PatientHistoryView = ({ patient }) => (
    <div className="space-y-6">
      <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Test History for {patient.name}</h3>
        <div className="space-y-4">
          {patientTestHistory.map((test) => (
            <div key={test.id} className="flex items-center justify-between p-4 bg-white/5 border border-white/10 rounded-lg">
              <div className="flex-1">
                <div className="flex items-center space-x-4 mb-2">
                  <p className="text-white font-medium">{test.id}</p>
                  {getResultBadge(test.result, test.severity, test.parasiteType)}
                </div>
                <div className="flex items-center space-x-4 text-sm text-blue-300">
                  <span>{formatDate(test.date)}</span>
                  <span>•</span>
                  <span>by {test.technician}</span>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <button className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                  <Eye className="h-4 w-4" />
                </button>
                <button className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded transition-colors">
                  <FileText className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const CreatePatientModal = () => (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-white/20 rounded-lg p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white">Create New Patient</h3>
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
                value={newPatient.name}
                onChange={(e) => setNewPatient({...newPatient, name: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="Enter full name"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Date of Birth *</label>
              <input
                type="date"
                value={newPatient.dateOfBirth}
                onChange={(e) => setNewPatient({...newPatient, dateOfBirth: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Gender *</label>
              <select
                value={newPatient.gender}
                onChange={(e) => setNewPatient({...newPatient, gender: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="">Select gender</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Blood Type</label>
              <select
                value={newPatient.bloodType}
                onChange={(e) => setNewPatient({...newPatient, bloodType: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <option value="">Select blood type</option>
                <option value="A+">A+</option>
                <option value="A-">A-</option>
                <option value="B+">B+</option>
                <option value="B-">B-</option>
                <option value="AB+">AB+</option>
                <option value="AB-">AB-</option>
                <option value="O+">O+</option>
                <option value="O-">O-</option>
              </select>
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Phone Number *</label>
              <input
                type="tel"
                value={newPatient.phone}
                onChange={(e) => setNewPatient({...newPatient, phone: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="+250 788 123 456"
              />
            </div>

            <div>
              <label className="block text-blue-200 text-sm font-medium mb-2">Email</label>
              <input
                type="email"
                value={newPatient.email}
                onChange={(e) => setNewPatient({...newPatient, email: e.target.value})}
                className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
                placeholder="patient@email.com"
              />
            </div>
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Address</label>
            <input
              type="text"
              value={newPatient.address}
              onChange={(e) => setNewPatient({...newPatient, address: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="City, Country"
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Emergency Contact</label>
            <input
              type="text"
              value={newPatient.emergencyContact}
              onChange={(e) => setNewPatient({...newPatient, emergencyContact: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Name - Phone number"
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Medical History</label>
            <textarea
              value={newPatient.medicalHistory}
              onChange={(e) => setNewPatient({...newPatient, medicalHistory: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              rows={3}
              placeholder="Previous conditions, surgeries, etc."
            />
          </div>

          <div>
            <label className="block text-blue-200 text-sm font-medium mb-2">Allergies</label>
            <input
              type="text"
              value={newPatient.allergies}
              onChange={(e) => setNewPatient({...newPatient, allergies: e.target.value})}
              className="w-full bg-white/10 border border-white/20 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="Known allergies or 'None known'"
            />
          </div>

          <div className="flex items-center justify-end space-x-3 pt-6 border-t border-white/20">
            <button
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleCreatePatient}
              className="flex items-center space-x-2 px-6 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              <Save className="h-4 w-4" />
              <span>Create Patient</span>
            </button>
          </div>
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
              {currentView !== 'list' && (
                <button
                  onClick={() => {
                    setCurrentView('list');
                    setSelectedPatient(null);
                  }}
                  className="mr-2 p-2 text-blue-200 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                >
                  <ArrowLeft className="h-5 w-5" />
                </button>
              )}
              <div className="bg-blue-500 p-2 rounded-lg">
                <Users className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-white">
                  {currentView === 'list' ? 'Patient Management' : 
                   currentView === 'details' ? 'Patient Details' : 'Test History'}
                </h1>
                <p className="text-blue-200 text-sm">
                  {currentView === 'list' ? 'Manage patient records and medical history' :
                   selectedPatient ? `${selectedPatient.name} • ${selectedPatient.id}` : ''}
                </p>
              </div>
            </div>

            {currentView === 'list' && (
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
                  <span>New Patient</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentView === 'list' && (
          <>
            {/* Search and Filters */}
            <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 mb-6">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-300 h-4 w-4" />
                  <input
                    type="text"
                    placeholder="Search patients by name, ID, phone..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-white/10 border border-white/20 rounded-lg pl-10 pr-4 py-2 text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-400"
                  />
                </div>

                <div className="flex items-center space-x-4 text-blue-200 text-sm">
                  <span>
                    Showing {paginatedPatients.length} of {filteredPatients.length} patients
                  </span>
                </div>
              </div>
            </div>

            {/* Patients Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {paginatedPatients.map((patient) => (
                <div key={patient.id} className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 hover:bg-white/15 transition-colors">
                  <div className="flex items-center justify-between mb-4">
                    <div className="bg-blue-500 p-2 rounded-full">
                      <User className="h-5 w-5 text-white" />
                    </div>
                    <button className="text-blue-300 hover:text-white">
                      <MoreHorizontal className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="mb-4">
                    <h3 className="text-white font-medium mb-1">{patient.name}</h3>
                    <p className="text-blue-300 text-sm">{patient.id}</p>
                    <p className="text-blue-200 text-sm">{patient.age} years • {patient.gender}</p>
                  </div>

                  <div className="flex items-center justify-between mb-4">
                    <div className="text-center">
                      <p className="text-white font-medium">{patient.totalTests}</p>
                      <p className="text-blue-300 text-xs">Tests</p>
                    </div>
                    <div className="text-center">
                      <p className="text-white font-medium">{patient.positiveTests}</p>
                      <p className="text-blue-300 text-xs">Positive</p>
                    </div>
                    <div className="text-center">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskLevel(patient).color}`}>
                        {getRiskLevel(patient).level}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => {
                        setSelectedPatient(patient);
                        setCurrentView('details');
                      }}
                      className="flex-1 flex items-center justify-center space-x-2 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded text-sm transition-colors"
                    >
                      <Eye className="h-3 w-3" />
                      <span>View</span>
                    </button>
                    <button className="flex items-center justify-center py-2 px-3 bg-white/10 hover:bg-white/20 border border-white/20 text-white rounded text-sm transition-colors">
                      <TestTube className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div className="text-sm text-blue-200">
                    Showing {startIndex + 1} to {Math.min(startIndex + patientsPerPage, filteredPatients.length)} of {filteredPatients.length} results
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                      disabled={currentPage === 1}
                      className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </button>
                    
                    <div className="flex items-center space-x-1">
                      {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                        const page = i + 1;
                        return (
                          <button
                            key={page}
                            onClick={() => setCurrentPage(page)}
                            className={`px-3 py-1 rounded text-sm transition-colors ${
                              currentPage === page
                                ? 'bg-blue-500 text-white'
                                : 'text-blue-300 hover:text-white hover:bg-white/10'
                            }`}
                          >
                            {page}
                          </button>
                        );
                      })}
                    </div>

                    <button
                      onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                      disabled={currentPage === totalPages}
                      className="p-2 text-blue-300 hover:text-white hover:bg-white/10 rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Empty State */}
            {filteredPatients.length === 0 && (
              <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-12 text-center">
                <Users className="h-12 w-12 text-blue-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-white mb-2">No patients found</h3>
                <p className="text-blue-200 mb-6">
                  {searchTerm
                    ? 'Try adjusting your search criteria.'
                    : 'No patients have been registered yet.'}
                </p>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
                >
                  Create First Patient
                </button>
              </div>
            )}
          </>
        )}

        {currentView === 'details' && selectedPatient && (
          <PatientDetailsView patient={selectedPatient} />
        )}

        {currentView === 'history' && selectedPatient && (
          <PatientHistoryView patient={selectedPatient} />
        )}
      </main>

      {showCreateModal && <CreatePatientModal />}
    </div>
  );
};

export default PatientManagementPage;
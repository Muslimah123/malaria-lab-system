// import React, { useState, useEffect } from 'react';
// import { 
//   User, 
//   Bell, 
//   Shield, 
//   Monitor, 
//   Database, 
//   Users, 
//   FileText, 
//   Zap,
//   Globe,
//   Lock,
//   Eye,
//   EyeOff,
//   Save,
//   RefreshCw,
//   Download,
//   Upload,
//   Trash2,
//   AlertTriangle,
//   CheckCircle,
//   X,
//   Camera,
//   Smartphone,
//   Mail,
//   Clock,
//   BarChart3,
//   Microscope,
//   Building,
//   Phone,
//   MapPin,
//   Plus,
//   Edit3,
//   Key
// } from 'lucide-react';

// const SettingsPage = () => {
//   const [activeTab, setActiveTab] = useState('profile');
//   const [loading, setLoading] = useState(false);
//   const [showPassword, setShowPassword] = useState(false);
//   const [changes, setChanges] = useState({});
//   const [showConfirmDialog, setShowConfirmDialog] = useState(false);
//   const [confirmAction, setConfirmAction] = useState(null);

//   // Mock user data for design purposes
//   const [user] = useState({
//     firstName: 'Dr. Sarah',
//     lastName: 'Chen',
//     email: 'sarah.chen@citylab.com',
//     role: 'supervisor',
//     avatar: null,
//     labName: 'City Medical Laboratory',
//     phone: '+250 788 123 456',
//     department: 'Parasitology',
//     license: 'ML-2024-001',
//     joinedDate: '2023-01-15'
//   });

//   const [settings, setSettings] = useState({
//     notifications: {
//       criticalResults: true,
//       testCompletion: true,
//       systemAlerts: true,
//       dailyReports: false,
//       weeklyReports: true,
//       email: true,
//       sms: false,
//       push: true,
//       sound: true,
//       frequency: 'immediate'
//     },
//     display: {
//       theme: 'dark',
//       language: 'en',
//       timezone: 'Africa/Kigali',
//       dateFormat: 'DD/MM/YYYY',
//       timeFormat: '24h',
//       density: 'comfortable',
//       animations: true
//     },
//     security: {
//       twoFactor: false,
//       sessionTimeout: 30,
//       passwordExpiry: 90,
//       ipRestriction: false,
//       loginNotifications: true,
//       autoLock: 15
//     },
//     lab: {
//       name: 'City Medical Laboratory',
//       address: '123 Health Street, Kigali, Rwanda',
//       phone: '+250 788 123 456',
//       email: 'info@citylab.com',
//       accreditation: 'CAP, WHO-AFRO',
//       defaultSampleType: 'blood_smear',
//       qualityThreshold: 85,
//       autoReview: false,
//       retentionPeriod: 365,
//       backupSchedule: 'daily'
//     },
//     integrations: {
//       hospitalEMR: false,
//       lims: false,
//       publicHealth: true,
//       cloudstorage: true,
//       apiAccess: false
//     }
//   });

//   const settingsTabs = [
//     { 
//       id: 'profile', 
//       name: 'Profile', 
//       icon: User,
//       description: 'Personal information and account details'
//     },
//     { 
//       id: 'notifications', 
//       name: 'Notifications', 
//       icon: Bell,
//       description: 'Alert preferences and communication settings'
//     },
//     { 
//       id: 'security', 
//       name: 'Security', 
//       icon: Shield,
//       description: 'Password, 2FA, and access control'
//     },
//     { 
//       id: 'display', 
//       name: 'Display', 
//       icon: Monitor,
//       description: 'Theme, language, and interface preferences'
//     },
//     ...(user.role !== 'technician' ? [
//       { 
//         id: 'lab', 
//         name: 'Laboratory', 
//         icon: Microscope,
//         description: 'Lab configuration and quality settings'
//       },
//       { 
//         id: 'integrations', 
//         name: 'Integrations', 
//         icon: Zap,
//         description: 'External systems and data connections'
//       },
//       { 
//         id: 'users', 
//         name: 'Team', 
//         icon: Users,
//         description: 'Manage lab personnel and permissions'
//       }
//     ] : [])
//   ];

//   const updateSetting = (section, key, value) => {
//     setSettings(prev => ({
//       ...prev,
//       [section]: {
//         ...prev[section],
//         [key]: value
//       }
//     }));
//     setChanges(prev => ({ ...prev, [section]: true }));
//   };

//   const handleSave = async (section) => {
//     setLoading(true);
//     try {
//       // Simulate API call
//       await new Promise(resolve => setTimeout(resolve, 1000));
//       console.log('Saving settings for:', section);
//       setChanges(prev => ({ ...prev, [section]: false }));
//     } catch (error) {
//       console.error('Failed to save settings:', error);
//     } finally {
//       setLoading(false);
//     }
//   };

//   const ToggleSwitch = ({ checked, onChange, disabled = false }) => (
//     <button
//       onClick={() => !disabled && onChange(!checked)}
//       disabled={disabled}
//       className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-transparent ${
//         checked ? 'bg-blue-600' : 'bg-gray-600'
//       } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
//     >
//       <span
//         className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
//           checked ? 'translate-x-6' : 'translate-x-1'
//         }`}
//       />
//     </button>
//   );

//   const SettingCard = ({ title, description, children, hasChanges = false }) => (
//     <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
//       <div className="flex items-start justify-between mb-4">
//         <div>
//           <h3 className="text-lg font-semibold text-white flex items-center gap-2">
//             {title}
//             {hasChanges && (
//               <span className="inline-flex h-2 w-2 rounded-full bg-yellow-400"></span>
//             )}
//           </h3>
//           {description && (
//             <p className="text-blue-300 text-sm mt-1">{description}</p>
//           )}
//         </div>
//       </div>
//       {children}
//     </div>
//   );

//   const renderProfileTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Personal Information" description="Update your profile details">
//         <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
//           {/* Avatar Section */}
//           <div className="md:col-span-2 flex items-center space-x-6">
//             <div className="relative">
//               <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
//                 <span className="text-2xl font-bold text-white">
//                   {user.firstName[0]}{user.lastName[0]}
//                 </span>
//               </div>
//               <button className="absolute -bottom-1 -right-1 bg-blue-600 rounded-full p-2 hover:bg-blue-700 transition-colors">
//                 <Camera className="h-4 w-4 text-white" />
//               </button>
//             </div>
//             <div>
//               <h3 className="text-lg font-medium text-white">{user.firstName} {user.lastName}</h3>
//               <p className="text-blue-300">{user.role.charAt(0).toUpperCase() + user.role.slice(1)}</p>
//               <p className="text-blue-400 text-sm">{user.department}</p>
//             </div>
//           </div>

//           {/* Form Fields */}
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">First Name</label>
//             <input
//               type="text"
//               defaultValue={user.firstName}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Last Name</label>
//             <input
//               type="text"
//               defaultValue={user.lastName}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Email</label>
//             <input
//               type="email"
//               defaultValue={user.email}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Phone</label>
//             <input
//               type="tel"
//               defaultValue={user.phone}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">License Number</label>
//             <input
//               type="text"
//               defaultValue={user.license}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Department</label>
//             <select className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
//               <option value="parasitology">Parasitology</option>
//               <option value="hematology">Hematology</option>
//               <option value="microbiology">Microbiology</option>
//               <option value="biochemistry">Biochemistry</option>
//             </select>
//           </div>
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button className="px-4 py-2 text-blue-300 hover:text-white transition-colors">
//             Cancel
//           </button>
//           <button 
//             onClick={() => handleSave('profile')}
//             disabled={loading}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Save Changes
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderNotificationsTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Alert Preferences" description="Configure when and how you receive notifications" hasChanges={changes.notifications}>
//         <div className="space-y-4">
//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Critical Results</p>
//               <p className="text-blue-300 text-sm">Immediate alerts for positive malaria results</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.criticalResults}
//               onChange={(checked) => updateSetting('notifications', 'criticalResults', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Test Completion</p>
//               <p className="text-blue-300 text-sm">Notify when tests are completed</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.testCompletion}
//               onChange={(checked) => updateSetting('notifications', 'testCompletion', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">System Alerts</p>
//               <p className="text-blue-300 text-sm">Equipment issues and system maintenance</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.systemAlerts}
//               onChange={(checked) => updateSetting('notifications', 'systemAlerts', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Daily Reports</p>
//               <p className="text-blue-300 text-sm">Summary of daily lab activities</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.dailyReports}
//               onChange={(checked) => updateSetting('notifications', 'dailyReports', checked)}
//             />
//           </div>
//         </div>
//       </SettingCard>

//       <SettingCard title="Notification Channels" description="Choose how you want to receive alerts">
//         <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <Mail className="h-5 w-5 text-blue-400" />
//               <span className="text-white">Email</span>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.email}
//               onChange={(checked) => updateSetting('notifications', 'email', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <Smartphone className="h-5 w-5 text-blue-400" />
//               <span className="text-white">SMS</span>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.sms}
//               onChange={(checked) => updateSetting('notifications', 'sms', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <Bell className="h-5 w-5 text-blue-400" />
//               <span className="text-white">Push</span>
//             </div>
//             <ToggleSwitch
//               checked={settings.notifications.push}
//               onChange={(checked) => updateSetting('notifications', 'push', checked)}
//             />
//           </div>
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button 
//             onClick={() => handleSave('notifications')}
//             disabled={loading || !changes.notifications}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Save Changes
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderSecurityTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Password & Authentication" description="Manage your login credentials">
//         <div className="space-y-4">
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Current Password</label>
//             <div className="relative">
//               <input
//                 type={showPassword ? "text" : "password"}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10"
//                 placeholder="Enter current password"
//               />
//               <button
//                 type="button"
//                 onClick={() => setShowPassword(!showPassword)}
//                 className="absolute right-3 top-1/2 transform -translate-y-1/2 text-blue-300 hover:text-white"
//               >
//                 {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
//               </button>
//             </div>
//           </div>

//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">New Password</label>
//               <input
//                 type="password"
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//                 placeholder="Enter new password"
//               />
//             </div>
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Confirm Password</label>
//               <input
//                 type="password"
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//                 placeholder="Confirm new password"
//               />
//             </div>
//           </div>

//           <div className="flex items-center justify-between py-4 border-t border-white/20">
//             <div>
//               <p className="text-white font-medium">Two-Factor Authentication</p>
//               <p className="text-blue-300 text-sm">Add an extra layer of security to your account</p>
//             </div>
//             <div className="flex items-center space-x-3">
//               <ToggleSwitch
//                 checked={settings.security.twoFactor}
//                 onChange={(checked) => updateSetting('security', 'twoFactor', checked)}
//               />
//               {settings.security.twoFactor && (
//                 <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm transition-colors">
//                   Configure
//                 </button>
//               )}
//             </div>
//           </div>
//         </div>
//       </SettingCard>

//       <SettingCard title="Session & Access Control" description="Manage login sessions and security policies">
//         <div className="space-y-4">
//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Session Timeout (minutes)</label>
//               <select 
//                 value={settings.security.sessionTimeout}
//                 onChange={(e) => updateSetting('security', 'sessionTimeout', parseInt(e.target.value))}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value={15}>15 minutes</option>
//                 <option value={30}>30 minutes</option>
//                 <option value={60}>1 hour</option>
//                 <option value={120}>2 hours</option>
//                 <option value={240}>4 hours</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Auto-lock Screen (minutes)</label>
//               <select 
//                 value={settings.security.autoLock}
//                 onChange={(e) => updateSetting('security', 'autoLock', parseInt(e.target.value))}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value={5}>5 minutes</option>
//                 <option value={10}>10 minutes</option>
//                 <option value={15}>15 minutes</option>
//                 <option value={30}>30 minutes</option>
//                 <option value={0}>Never</option>
//               </select>
//             </div>
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Login Notifications</p>
//               <p className="text-blue-300 text-sm">Get notified of new login attempts</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.security.loginNotifications}
//               onChange={(checked) => updateSetting('security', 'loginNotifications', checked)}
//             />
//           </div>
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button 
//             onClick={() => handleSave('security')}
//             disabled={loading}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Update Security
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderDisplayTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Appearance" description="Customize the look and feel of your interface">
//         <div className="space-y-6">
//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-3">Theme</label>
//             <div className="grid grid-cols-3 gap-3">
//               {['light', 'dark', 'system'].map((theme) => (
//                 <button
//                   key={theme}
//                   onClick={() => updateSetting('display', 'theme', theme)}
//                   className={`p-4 rounded-lg border transition-colors ${
//                     settings.display.theme === theme
//                       ? 'border-blue-500 bg-blue-500/20'
//                       : 'border-white/20 bg-white/5 hover:bg-white/10'
//                   }`}
//                 >
//                   <div className={`w-full h-8 rounded mb-2 ${
//                     theme === 'light' ? 'bg-gray-100' :
//                     theme === 'dark' ? 'bg-gray-800' :
//                     'bg-gradient-to-r from-gray-100 to-gray-800'
//                   }`}></div>
//                   <span className="text-white text-sm capitalize">{theme}</span>
//                 </button>
//               ))}
//             </div>
//           </div>

//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Language</label>
//               <select 
//                 value={settings.display.language}
//                 onChange={(e) => updateSetting('display', 'language', e.target.value)}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value="en">English</option>
//                 <option value="fr">Français</option>
//                 <option value="rw">Kinyarwanda</option>
//                 <option value="sw">Swahili</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Timezone</label>
//               <select 
//                 value={settings.display.timezone}
//                 onChange={(e) => updateSetting('display', 'timezone', e.target.value)}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value="Africa/Kigali">Africa/Kigali</option>
//                 <option value="Africa/Nairobi">Africa/Nairobi</option>
//                 <option value="UTC">UTC</option>
//                 <option value="Europe/London">Europe/London</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Date Format</label>
//               <select 
//                 value={settings.display.dateFormat}
//                 onChange={(e) => updateSetting('display', 'dateFormat', e.target.value)}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value="DD/MM/YYYY">DD/MM/YYYY</option>
//                 <option value="MM/DD/YYYY">MM/DD/YYYY</option>
//                 <option value="YYYY-MM-DD">YYYY-MM-DD</option>
//               </select>
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Time Format</label>
//               <select 
//                 value={settings.display.timeFormat}
//                 onChange={(e) => updateSetting('display', 'timeFormat', e.target.value)}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               >
//                 <option value="24h">24-hour</option>
//                 <option value="12h">12-hour</option>
//               </select>
//             </div>
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Animations</p>
//               <p className="text-blue-300 text-sm">Enable interface animations and transitions</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.display.animations}
//               onChange={(checked) => updateSetting('display', 'animations', checked)}
//             />
//           </div>
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button 
//             onClick={() => handleSave('display')}
//             disabled={loading}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Save Preferences
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderLabTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Laboratory Information" description="Configure lab details and contact information">
//         <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//           <div className="md:col-span-2">
//             <label className="block text-sm font-medium text-blue-200 mb-2">Laboratory Name</label>
//             <input
//               type="text"
//               value={settings.lab.name}
//               onChange={(e) => updateSetting('lab', 'name', e.target.value)}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div className="md:col-span-2">
//             <label className="block text-sm font-medium text-blue-200 mb-2">Address</label>
//             <textarea
//               value={settings.lab.address}
//               onChange={(e) => updateSetting('lab', 'address', e.target.value)}
//               rows={3}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Phone</label>
//             <input
//               type="tel"
//               value={settings.lab.phone}
//               onChange={(e) => updateSetting('lab', 'phone', e.target.value)}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Email</label>
//             <input
//               type="email"
//               value={settings.lab.email}
//               onChange={(e) => updateSetting('lab', 'email', e.target.value)}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Accreditation</label>
//             <input
//               type="text"
//               value={settings.lab.accreditation}
//               onChange={(e) => updateSetting('lab', 'accreditation', e.target.value)}
//               placeholder="e.g., CAP, WHO-AFRO"
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//           </div>

//           <div>
//             <label className="block text-sm font-medium text-blue-200 mb-2">Default Sample Type</label>
//             <select 
//               value={settings.lab.defaultSampleType}
//               onChange={(e) => updateSetting('lab', 'defaultSampleType', e.target.value)}
//               className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//             >
//               <option value="blood_smear">Blood Smear</option>
//               <option value="thick_smear">Thick Smear</option>
//               <option value="rdt">Rapid Diagnostic Test</option>
//               <option value="pcr">PCR</option>
//             </select>
//           </div>
//         </div>
//       </SettingCard>

//       <SettingCard title="Quality & Workflow Settings" description="Configure quality thresholds and automation">
//         <div className="space-y-4">
//           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Quality Threshold (%)</label>
//               <input
//                 type="number"
//                 min="0"
//                 max="100"
//                 value={settings.lab.qualityThreshold}
//                 onChange={(e) => updateSetting('lab', 'qualityThreshold', parseInt(e.target.value))}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               />
//             </div>

//             <div>
//               <label className="block text-sm font-medium text-blue-200 mb-2">Data Retention (days)</label>
//               <input
//                 type="number"
//                 min="30"
//                 max="3650"
//                 value={settings.lab.retentionPeriod}
//                 onChange={(e) => updateSetting('lab', 'retentionPeriod', parseInt(e.target.value))}
//                 className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
//               />
//             </div>
//           </div>

//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Automatic Review</p>
//               <p className="text-blue-300 text-sm">Enable AI-assisted quality review</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.lab.autoReview}
//               onChange={(checked) => updateSetting('lab', 'autoReview', checked)}
//             />
//           </div>
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button 
//             onClick={() => handleSave('lab')}
//             disabled={loading}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Save Lab Settings
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderIntegrationsTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="External Systems" description="Connect with hospital EMR and other systems">
//         <div className="space-y-4">
//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center">
//                 <Building className="h-5 w-5 text-white" />
//               </div>
//               <div>
//                 <p className="text-white font-medium">Hospital EMR</p>
//                 <p className="text-blue-300 text-sm">Sync results with hospital system</p>
//               </div>
//             </div>
//             <ToggleSwitch
//               checked={settings.integrations.hospitalEMR}
//               onChange={(checked) => updateSetting('integrations', 'hospitalEMR', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
//                 <BarChart3 className="h-5 w-5 text-white" />
//               </div>
//               <div>
//                 <p className="text-white font-medium">LIMS Integration</p>
//                 <p className="text-blue-300 text-sm">Laboratory Information Management System</p>
//               </div>
//             </div>
//             <ToggleSwitch
//               checked={settings.integrations.lims}
//               onChange={(checked) => updateSetting('integrations', 'lims', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <div className="w-10 h-10 bg-purple-600 rounded-lg flex items-center justify-center">
//                 <Globe className="h-5 w-5 text-white" />
//               </div>
//               <div>
//                 <p className="text-white font-medium">Public Health Reporting</p>
//                 <p className="text-blue-300 text-sm">Automatic reporting to health authorities</p>
//               </div>
//             </div>
//             <ToggleSwitch
//               checked={settings.integrations.publicHealth}
//               onChange={(checked) => updateSetting('integrations', 'publicHealth', checked)}
//             />
//           </div>

//           <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//             <div className="flex items-center space-x-3">
//               <div className="w-10 h-10 bg-orange-600 rounded-lg flex items-center justify-center">
//                 <Database className="h-5 w-5 text-white" />
//               </div>
//               <div>
//                 <p className="text-white font-medium">Cloud Storage</p>
//                 <p className="text-blue-300 text-sm">Backup data to cloud storage</p>
//               </div>
//             </div>
//             <ToggleSwitch
//               checked={settings.integrations.cloudstorage}
//               onChange={(checked) => updateSetting('integrations', 'cloudstorage', checked)}
//             />
//           </div>
//         </div>
//       </SettingCard>

//       <SettingCard title="API Access" description="Manage API keys and external access">
//         <div className="space-y-4">
//           <div className="flex items-center justify-between">
//             <div>
//               <p className="text-white font-medium">Enable API Access</p>
//               <p className="text-blue-300 text-sm">Allow external applications to access your data</p>
//             </div>
//             <ToggleSwitch
//               checked={settings.integrations.apiAccess}
//               onChange={(checked) => updateSetting('integrations', 'apiAccess', checked)}
//             />
//           </div>

//           {settings.integrations.apiAccess && (
//             <div className="border-t border-white/20 pt-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-white font-medium">API Key</p>
//                   <p className="text-blue-300 text-sm font-mono">lab_***************4f2a</p>
//                 </div>
//                 <div className="flex space-x-2">
//                   <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm transition-colors">
//                     Regenerate
//                   </button>
//                   <button className="px-3 py-1 bg-gray-600 hover:bg-gray-700 text-white rounded text-sm transition-colors">
//                     Copy
//                   </button>
//                 </div>
//               </div>
//             </div>
//           )}
//         </div>

//         <div className="flex justify-end space-x-3 mt-6">
//           <button 
//             onClick={() => handleSave('integrations')}
//             disabled={loading}
//             className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
//           >
//             {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
//             Save Integrations
//           </button>
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderUsersTab = () => (
//     <div className="space-y-6">
//       <SettingCard title="Team Members" description="Manage lab personnel and their access">
//         <div className="flex items-center justify-between mb-4">
//           <div className="flex items-center space-x-4">
//             <input
//               type="search"
//               placeholder="Search team members..."
//               className="px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
//             />
//             <select className="px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
//               <option value="">All Roles</option>
//               <option value="admin">Admin</option>
//               <option value="supervisor">Supervisor</option>
//               <option value="technician">Technician</option>
//             </select>
//           </div>
//           <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center gap-2">
//             <Plus className="h-4 w-4" />
//             Add Member
//           </button>
//         </div>

//         <div className="space-y-3">
//           {[
//             { name: 'Dr. Sarah Chen', email: 'sarah.chen@lab.com', role: 'supervisor', status: 'active' },
//             { name: 'James Wilson', email: 'james.wilson@lab.com', role: 'technician', status: 'active' },
//             { name: 'Maria Garcia', email: 'maria.garcia@lab.com', role: 'technician', status: 'active' },
//             { name: 'David Park', email: 'david.park@lab.com', role: 'admin', status: 'inactive' }
//           ].map((member, index) => (
//             <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
//               <div className="flex items-center space-x-3">
//                 <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
//                   <span className="text-sm font-bold text-white">
//                     {member.name.split(' ').map(n => n[0]).join('')}
//                   </span>
//                 </div>
//                 <div>
//                   <p className="text-white font-medium">{member.name}</p>
//                   <p className="text-blue-300 text-sm">{member.email}</p>
//                 </div>
//               </div>
//               <div className="flex items-center space-x-3">
//                 <span className={`px-2 py-1 rounded-full text-xs font-medium ${
//                   member.role === 'admin' ? 'bg-red-500/20 text-red-300' :
//                   member.role === 'supervisor' ? 'bg-blue-500/20 text-blue-300' :
//                   'bg-green-500/20 text-green-300'
//                 }`}>
//                   {member.role}
//                 </span>
//                 <span className={`px-2 py-1 rounded-full text-xs font-medium ${
//                   member.status === 'active' ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-300'
//                 }`}>
//                   {member.status}
//                 </span>
//                 <button className="p-2 text-blue-300 hover:text-white transition-colors">
//                   <Edit3 className="h-4 w-4" />
//                 </button>
//               </div>
//             </div>
//           ))}
//         </div>
//       </SettingCard>
//     </div>
//   );

//   const renderActiveTab = () => {
//     switch (activeTab) {
//       case 'profile':
//         return renderProfileTab();
//       case 'notifications':
//         return renderNotificationsTab();
//       case 'security':
//         return renderSecurityTab();
//       case 'display':
//         return renderDisplayTab();
//       case 'lab':
//         return renderLabTab();
//       case 'integrations':
//         return renderIntegrationsTab();
//       case 'users':
//         return renderUsersTab();
//       default:
//         return renderProfileTab();
//     }
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 p-4">
//       <div className="max-w-7xl mx-auto">
//         {/* Header */}
//         <div className="mb-8">
//           <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
//           <p className="text-blue-300">Customize your lab management experience</p>
//         </div>

//         <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
//           {/* Sidebar */}
//           <div className="lg:col-span-1">
//             <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 sticky top-4">
//               <nav className="space-y-2">
//                 {settingsTabs.map((tab) => {
//                   const Icon = tab.icon;
//                   return (
//                     <button
//                       key={tab.id}
//                       onClick={() => setActiveTab(tab.id)}
//                       className={`w-full flex items-center space-x-3 px-3 py-3 rounded-lg transition-colors text-left ${
//                         activeTab === tab.id
//                           ? 'bg-blue-600 text-white'
//                           : 'text-blue-300 hover:text-white hover:bg-white/10'
//                       }`}
//                     >
//                       <Icon className="h-5 w-5" />
//                       <div className="flex-1 min-w-0">
//                         <p className="font-medium">{tab.name}</p>
//                         <p className="text-xs opacity-75 truncate">{tab.description}</p>
//                       </div>
//                       {changes[tab.id] && (
//                         <span className="inline-flex h-2 w-2 rounded-full bg-yellow-400"></span>
//                       )}
//                     </button>
//                   );
//                 })}
//               </nav>
//             </div>
//           </div>

//           {/* Main Content */}
//           <div className="lg:col-span-3">
//             {renderActiveTab()}
//           </div>
//         </div>

//         {/* Confirmation Dialog */}
//         {showConfirmDialog && (
//           <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
//             <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 max-w-md w-full mx-4">
//               <div className="flex items-center space-x-3 mb-4">
//                 <AlertTriangle className="h-6 w-6 text-yellow-400" />
//                 <h3 className="text-lg font-semibold text-white">Confirm Action</h3>
//               </div>
//               <p className="text-blue-300 mb-6">
//                 Are you sure you want to reset these settings? This action cannot be undone.
//               </p>
//               <div className="flex space-x-3">
//                 <button
//                   onClick={() => setShowConfirmDialog(false)}
//                   className="flex-1 px-4 py-2 text-blue-300 hover:text-white transition-colors"
//                 >
//                   Cancel
//                 </button>
//                 <button
//                   onClick={() => {
//                     confirmAction?.();
//                     setShowConfirmDialog(false);
//                   }}
//                   className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
//                 >
//                   Reset
//                 </button>
//               </div>
//             </div>
//           </div>
//         )}
//       </div>
//     </div>
//   );
// };

// export default SettingsPage;
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  User, 
  Bell, 
  Shield, 
  Monitor, 
  Database, 
  Users, 
  Zap,
  Globe,
  Lock,
  Eye,
  EyeOff,
  Save,
  RefreshCw,
  Download,
  Upload,
  Trash2,
  AlertTriangle,
  CheckCircle,
  X,
  Camera,
  Smartphone,
  Mail,
  Clock,
  BarChart3,
  Microscope,
  Building,
  Phone,
  MapPin,
  Plus,
  Edit3,
  Key
} from 'lucide-react';

// Store imports
import { selectUser, selectIsAuthenticated } from '../store/slices/authSlice';
import { showErrorToast, showSuccessToast } from '../store/slices/notificationsSlice';

// Component imports
import Header from '../components/common/Header';
import Sidebar from '../components/common/Sidebar';
import LoadingSpinner from '../components/common/LoadingSpinner';
import Toast from '../components/common/Toast';

// Services
import apiService from '../services/api';

const SettingsPage = () => {
  const dispatch = useDispatch();
  const user = useSelector(selectUser);
  const isAuthenticated = useSelector(selectIsAuthenticated);

  // UI State
  const [activeTab, setActiveTab] = useState('profile');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [confirmAction, setConfirmAction] = useState(null);

  // Loading States
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadingSection, setLoadingSection] = useState('');

  // Data State
  const [profile, setProfile] = useState({});
  const [userSettings, setUserSettings] = useState({});
  const [labSettings, setLabSettings] = useState({});
  const [systemStatus, setSystemStatus] = useState({});
  const [changes, setChanges] = useState({});

  // Form State
  const [profileForm, setProfileForm] = useState({});
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // Settings tabs based on user role
  const settingsTabs = [
    { 
      id: 'profile', 
      name: 'Profile', 
      icon: User,
      description: 'Personal information and account details'
    },
    { 
      id: 'notifications', 
      name: 'Notifications', 
      icon: Bell,
      description: 'Alert preferences and communication settings'
    },
    { 
      id: 'security', 
      name: 'Security', 
      icon: Shield,
      description: 'Password, 2FA, and access control'
    },
    { 
      id: 'display', 
      name: 'Display', 
      icon: Monitor,
      description: 'Theme, language, and interface preferences'
    },
    ...(user?.role !== 'technician' ? [
      { 
        id: 'lab', 
        name: 'Laboratory', 
        icon: Microscope,
        description: 'Lab configuration and quality settings'
      },
      { 
        id: 'integrations', 
        name: 'Integrations', 
        icon: Zap,
        description: 'External systems and data connections'
      },
      { 
        id: 'users', 
        name: 'Team', 
        icon: Users,
        description: 'Manage lab personnel and permissions'
      }
    ] : [])
  ];

  // Initialize data
  useEffect(() => {
    if (isAuthenticated) {
      loadInitialData();
    }
  }, [isAuthenticated]);

  const loadInitialData = async () => {
    try {
      setLoading(true);
      
      // Load profile and user settings for all users
      const [profileResponse, settingsResponse] = await Promise.all([
        apiService.settings.getProfile(),
        apiService.settings.getUserSettings()
      ]);

      setProfile(profileResponse.data.profile);
      setProfileForm(profileResponse.data.profile);
      setUserSettings(settingsResponse.data.settings);

      // Load lab settings for supervisors/admins
      if (['supervisor', 'admin'].includes(user?.role)) {
        try {
          const labResponse = await apiService.settings.getLabSettings();
          setLabSettings(labResponse.data.settings);
        } catch (error) {
          console.warn('Could not load lab settings:', error);
        }
      }

      // Load system status for supervisors/admins
      if (['supervisor', 'admin'].includes(user?.role)) {
        try {
          const statusResponse = await apiService.settings.getSystemStatus();
          setSystemStatus(statusResponse.data);
        } catch (error) {
          console.warn('Could not load system status:', error);
        }
      }

    } catch (error) {
      console.error('Failed to load settings data:', error);
      dispatch(showErrorToast('Failed to load settings data'));
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    loadInitialData();
  };

  // Profile Management
  const handleProfileUpdate = async (formData) => {
    try {
      setSaving(true);
      const response = await apiService.settings.updateProfile(formData);
      
      setProfile(response.data.profile);
      setProfileForm(response.data.profile);
      dispatch(showSuccessToast('Profile updated successfully'));
      
    } catch (error) {
      console.error('Failed to update profile:', error);
      dispatch(showErrorToast(
        error.response?.data?.message || 'Failed to update profile'
      ));
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordChange = async () => {
    try {
      if (passwordForm.newPassword !== passwordForm.confirmPassword) {
        dispatch(showErrorToast('New passwords do not match'));
        return;
      }

      setSaving(true);
      await apiService.settings.changePassword({
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword
      });

      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });
      
      dispatch(showSuccessToast('Password changed successfully'));
      
    } catch (error) {
      console.error('Failed to change password:', error);
      dispatch(showErrorToast(
        error.response?.data?.message || 'Failed to change password'
      ));
    } finally {
      setSaving(false);
    }
  };

  // Settings Management
  const handleSettingsUpdate = async (section, data) => {
    try {
      setLoadingSection(section);
      await apiService.settings.updateUserSettings(section, data);
      
      // Update local state
      setUserSettings(prev => ({
        ...prev,
        [section]: { ...prev[section], ...data }
      }));
      
      // Clear changes indicator
      setChanges(prev => ({ ...prev, [section]: false }));
      
      dispatch(showSuccessToast(`${section} settings updated successfully`));
      
    } catch (error) {
      console.error(`Failed to update ${section} settings:`, error);
      dispatch(showErrorToast(
        error.response?.data?.message || `Failed to update ${section} settings`
      ));
    } finally {
      setLoadingSection('');
    }
  };

  const handleLabSettingsUpdate = async (section, data, reason = '') => {
    try {
      if (user?.role !== 'admin') {
        dispatch(showErrorToast('Admin access required'));
        return;
      }

      setLoadingSection(section);
      await apiService.settings.updateLabSettings(section, data, reason);
      
      // Update local state
      setLabSettings(prev => ({
        ...prev,
        [section]: { ...prev[section], ...data }
      }));
      
      dispatch(showSuccessToast(`Lab ${section} settings updated successfully`));
      
    } catch (error) {
      console.error(`Failed to update lab ${section} settings:`, error);
      dispatch(showErrorToast(
        error.response?.data?.message || `Failed to update lab ${section} settings`
      ));
    } finally {
      setLoadingSection('');
    }
  };

  const handleResetSettings = (section) => {
    setConfirmAction(() => async () => {
      try {
        setLoadingSection('reset');
        await apiService.settings.resetUserSettings(section);
        
        // Reload settings
        const response = await apiService.settings.getUserSettings();
        setUserSettings(response.data.settings);
        
        dispatch(showSuccessToast(
          section ? `${section} settings reset to defaults` : 'All settings reset to defaults'
        ));
        
      } catch (error) {
        console.error('Failed to reset settings:', error);
        dispatch(showErrorToast('Failed to reset settings'));
      } finally {
        setLoadingSection('');
      }
    });
    setShowConfirmDialog(true);
  };

  // Update settings and track changes
  const updateSetting = (section, key, value) => {
    setUserSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value
      }
    }));
    setChanges(prev => ({ ...prev, [section]: true }));
  };

  const updateLabSetting = (section, key, value) => {
    setLabSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value
      }
    }));
  };

  // Reusable Components
  const ToggleSwitch = ({ checked, onChange, disabled = false }) => (
    <button
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-transparent ${
        checked ? 'bg-blue-600' : 'bg-gray-600'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          checked ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  );

  const SettingCard = ({ title, description, children, hasChanges = false, loading = false }) => (
    <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            {title}
            {hasChanges && (
              <span className="inline-flex h-2 w-2 rounded-full bg-yellow-400"></span>
            )}
            {loading && (
              <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />
            )}
          </h3>
          {description && (
            <p className="text-blue-300 text-sm mt-1">{description}</p>
          )}
        </div>
      </div>
      {children}
    </div>
  );

  // Tab Renderers
  const renderProfileTab = () => (
    <div className="space-y-6">
      <SettingCard 
        title="Personal Information" 
        description="Update your profile details"
        loading={saving}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Avatar Section */}
          <div className="md:col-span-2 flex items-center space-x-6">
            <div className="relative">
              <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                <span className="text-2xl font-bold text-white">
                  {profile.firstName?.[0]}{profile.lastName?.[0]}
                </span>
              </div>
              <button className="absolute -bottom-1 -right-1 bg-blue-600 rounded-full p-2 hover:bg-blue-700 transition-colors">
                <Camera className="h-4 w-4 text-white" />
              </button>
            </div>
            <div>
              <h3 className="text-lg font-medium text-white">
                {profile.firstName} {profile.lastName}
              </h3>
              <p className="text-blue-300">{profile.role?.charAt(0).toUpperCase() + profile.role?.slice(1)}</p>
              <p className="text-blue-400 text-sm">{profile.department}</p>
            </div>
          </div>

          {/* Form Fields */}
          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">First Name</label>
            <input
              type="text"
              value={profileForm.firstName || ''}
              onChange={(e) => setProfileForm(prev => ({ ...prev, firstName: e.target.value }))}
              className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">Last Name</label>
            <input
              type="text"
              value={profileForm.lastName || ''}
              onChange={(e) => setProfileForm(prev => ({ ...prev, lastName: e.target.value }))}
              className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">Email</label>
            <input
              type="email"
              value={profileForm.email || ''}
              disabled
              className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-gray-400 cursor-not-allowed"
            />
            <p className="text-blue-400 text-xs mt-1">Email cannot be changed</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">Phone</label>
            <input
              type="tel"
              value={profileForm.phoneNumber || ''}
              onChange={(e) => setProfileForm(prev => ({ ...prev, phoneNumber: e.target.value }))}
              className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="+250XXXXXXXXX"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">License Number</label>
            <input
              type="text"
              value={profileForm.licenseNumber || ''}
              onChange={(e) => setProfileForm(prev => ({ ...prev, licenseNumber: e.target.value }))}
              className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">Department</label>
            <select 
              value={profileForm.department || ''}
              onChange={(e) => setProfileForm(prev => ({ ...prev, department: e.target.value }))}
              className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="Laboratory">Laboratory</option>
              <option value="Parasitology">Parasitology</option>
              <option value="Hematology">Hematology</option>
              <option value="Microbiology">Microbiology</option>
              <option value="Biochemistry">Biochemistry</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end space-x-3 mt-6">
          <button 
            onClick={() => setProfileForm(profile)}
            className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
            disabled={saving}
          >
            Cancel
          </button>
          <button 
            onClick={() => handleProfileUpdate(profileForm)}
            disabled={saving}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save Changes
          </button>
        </div>
      </SettingCard>

      {/* Password Change Card */}
      <SettingCard title="Change Password" description="Update your login password">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-blue-200 mb-2">Current Password</label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={passwordForm.currentPassword}
                onChange={(e) => setPasswordForm(prev => ({ ...prev, currentPassword: e.target.value }))}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10"
                placeholder="Enter current password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-blue-300 hover:text-white"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">New Password</label>
              <input
                type="password"
                value={passwordForm.newPassword}
                onChange={(e) => setPasswordForm(prev => ({ ...prev, newPassword: e.target.value }))}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter new password"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">Confirm Password</label>
              <input
                type="password"
                value={passwordForm.confirmPassword}
                onChange={(e) => setPasswordForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Confirm new password"
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3 mt-6">
            <button 
              onClick={() => setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })}
              className="px-4 py-2 text-blue-300 hover:text-white transition-colors"
              disabled={saving}
            >
              Cancel
            </button>
            <button 
              onClick={handlePasswordChange}
              disabled={saving || !passwordForm.currentPassword || !passwordForm.newPassword}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Key className="h-4 w-4" />}
              Change Password
            </button>
          </div>
        </div>
      </SettingCard>
    </div>
  );

  const renderNotificationsTab = () => (
    <div className="space-y-6">
      <SettingCard 
        title="Alert Preferences" 
        description="Configure when and how you receive notifications" 
        hasChanges={changes.notifications}
        loading={loadingSection === 'notifications'}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Critical Results</p>
              <p className="text-blue-300 text-sm">Immediate alerts for positive malaria results</p>
            </div>
            <ToggleSwitch
              checked={userSettings.notifications?.criticalResults ?? true}
              onChange={(checked) => updateSetting('notifications', 'criticalResults', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Test Completion</p>
              <p className="text-blue-300 text-sm">Notify when tests are completed</p>
            </div>
            <ToggleSwitch
              checked={userSettings.notifications?.testCompletion ?? true}
              onChange={(checked) => updateSetting('notifications', 'testCompletion', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">System Alerts</p>
              <p className="text-blue-300 text-sm">Equipment issues and system maintenance</p>
            </div>
            <ToggleSwitch
              checked={userSettings.notifications?.systemAlerts ?? true}
              onChange={(checked) => updateSetting('notifications', 'systemAlerts', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Daily Reports</p>
              <p className="text-blue-300 text-sm">Summary of daily lab activities</p>
            </div>
            <ToggleSwitch
              checked={userSettings.notifications?.dailyReports ?? false}
              onChange={(checked) => updateSetting('notifications', 'dailyReports', checked)}
            />
          </div>
        </div>

        <div className="border-t border-white/20 pt-4 mt-6">
          <h4 className="text-white font-medium mb-4">Notification Channels</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
              <div className="flex items-center space-x-3">
                <Mail className="h-5 w-5 text-blue-400" />
                <span className="text-white">Email</span>
              </div>
              <ToggleSwitch
                checked={userSettings.notifications?.email ?? true}
                onChange={(checked) => updateSetting('notifications', 'email', checked)}
              />
            </div>

            <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
              <div className="flex items-center space-x-3">
                <Smartphone className="h-5 w-5 text-blue-400" />
                <span className="text-white">SMS</span>
              </div>
              <ToggleSwitch
                checked={userSettings.notifications?.sms ?? false}
                onChange={(checked) => updateSetting('notifications', 'sms', checked)}
              />
            </div>

            <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
              <div className="flex items-center space-x-3">
                <Bell className="h-5 w-5 text-blue-400" />
                <span className="text-white">Push</span>
              </div>
              <ToggleSwitch
                checked={userSettings.notifications?.push ?? true}
                onChange={(checked) => updateSetting('notifications', 'push', checked)}
              />
            </div>
          </div>
        </div>

        <div className="flex justify-end space-x-3 mt-6">
          <button 
            onClick={() => handleSettingsUpdate('notifications', userSettings.notifications)}
            disabled={!changes.notifications || loadingSection === 'notifications'}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loadingSection === 'notifications' ? 
              <RefreshCw className="h-4 w-4 animate-spin" /> : 
              <Save className="h-4 w-4" />
            }
            Save Changes
          </button>
        </div>
      </SettingCard>
    </div>
  );

  const renderDisplayTab = () => (
    <div className="space-y-6">
      <SettingCard 
        title="Appearance" 
        description="Customize the look and feel of your interface"
        hasChanges={changes.display}
        loading={loadingSection === 'display'}
      >
        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-blue-200 mb-3">Theme</label>
            <div className="grid grid-cols-3 gap-3">
              {['light', 'dark', 'system'].map((theme) => (
                <button
                  key={theme}
                  onClick={() => updateSetting('display', 'theme', theme)}
                  className={`p-4 rounded-lg border transition-colors ${
                    userSettings.display?.theme === theme
                      ? 'border-blue-500 bg-blue-500/20'
                      : 'border-white/20 bg-white/5 hover:bg-white/10'
                  }`}
                >
                  <div className={`w-full h-8 rounded mb-2 ${
                    theme === 'light' ? 'bg-gray-100' :
                    theme === 'dark' ? 'bg-gray-800' :
                    'bg-gradient-to-r from-gray-100 to-gray-800'
                  }`}></div>
                  <span className="text-white text-sm capitalize">{theme}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">Language</label>
              <select 
                value={userSettings.display?.language || 'en'}
                onChange={(e) => updateSetting('display', 'language', e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="en">English</option>
                <option value="fr">Français</option>
                <option value="rw">Kinyarwanda</option>
                <option value="sw">Swahili</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">Timezone</label>
              <select 
                value={userSettings.display?.timezone || 'Africa/Kigali'}
                onChange={(e) => updateSetting('display', 'timezone', e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="Africa/Kigali">Africa/Kigali</option>
                <option value="Africa/Nairobi">Africa/Nairobi</option>
                <option value="UTC">UTC</option>
                <option value="Europe/London">Europe/London</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">Date Format</label>
              <select 
                value={userSettings.display?.dateFormat || 'DD/MM/YYYY'}
                onChange={(e) => updateSetting('display', 'dateFormat', e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                <option value="YYYY-MM-DD">YYYY-MM-DD</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-blue-200 mb-2">Time Format</label>
              <select 
                value={userSettings.display?.timeFormat || '24h'}
                onChange={(e) => updateSetting('display', 'timeFormat', e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="24h">24-hour</option>
                <option value="12h">12-hour</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Animations</p>
              <p className="text-blue-300 text-sm">Enable interface animations and transitions</p>
            </div>
            <ToggleSwitch
              checked={userSettings.display?.animations ?? true}
              onChange={(checked) => updateSetting('display', 'animations', checked)}
            />
          </div>
        </div>

        <div className="flex justify-end space-x-3 mt-6">
          <button 
            onClick={() => handleSettingsUpdate('display', userSettings.display)}
            disabled={!changes.display || loadingSection === 'display'}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loadingSection === 'display' ? 
              <RefreshCw className="h-4 w-4 animate-spin" /> : 
              <Save className="h-4 w-4" />
            }
            Save Preferences
          </button>
        </div>
      </SettingCard>
    </div>
  );

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'profile':
        return renderProfileTab();
      case 'notifications':
        return renderNotificationsTab();
      case 'display':
        return renderDisplayTab();
      case 'security':
        return <div className="text-white">Security settings coming soon...</div>;
      case 'lab':
        return <div className="text-white">Lab settings coming soon...</div>;
      case 'integrations':
        return <div className="text-white">Integrations coming soon...</div>;
      case 'users':
        return <div className="text-white">User management coming soon...</div>;
      default:
        return renderProfileTab();
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
        <div className="text-white text-lg">Please log in to access settings</div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex items-center justify-center">
        <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-8 flex items-center space-x-4">
          <LoadingSpinner size="lg" color="white" />
          <span className="text-white text-lg">Loading settings...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-purple-900 flex">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        onClose={() => setSidebarOpen(false)} 
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-64">
        {/* Header */}
        <Header
          title="Settings"
          subtitle="Customize your lab management experience"
          onMenuClick={() => setSidebarOpen(true)}
          onRefresh={handleRefresh}
          showSearch={false}
          showNotifications={true}
        />

        {/* Main Content Area */}
        <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 overflow-y-auto pt-24">
          <div className="max-w-7xl mx-auto">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              {/* Sidebar */}
              <div className="lg:col-span-1">
                <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-4 sticky top-4">
                  <nav className="space-y-2">
                    {settingsTabs.map((tab) => {
                      const Icon = tab.icon;
                      return (
                        <button
                          key={tab.id}
                          onClick={() => setActiveTab(tab.id)}
                          className={`w-full flex items-center space-x-3 px-3 py-3 rounded-lg transition-colors text-left ${
                            activeTab === tab.id
                              ? 'bg-blue-600 text-white'
                              : 'text-blue-300 hover:text-white hover:bg-white/10'
                          }`}
                        >
                          <Icon className="h-5 w-5" />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium">{tab.name}</p>
                            <p className="text-xs opacity-75 truncate">{tab.description}</p>
                          </div>
                          {changes[tab.id] && (
                            <span className="inline-flex h-2 w-2 rounded-full bg-yellow-400"></span>
                          )}
                        </button>
                      );
                    })}
                  </nav>
                </div>
              </div>

              {/* Main Content */}
              <div className="lg:col-span-3">
                {renderActiveTab()}
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Confirmation Dialog */}
      {showConfirmDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white/10 backdrop-blur-md border border-white/20 rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex items-center space-x-3 mb-4">
              <AlertTriangle className="h-6 w-6 text-yellow-400" />
              <h3 className="text-lg font-semibold text-white">Confirm Action</h3>
            </div>
            <p className="text-blue-300 mb-6">
              Are you sure you want to reset these settings? This action cannot be undone.
            </p>
            <div className="flex space-x-3">
              <button
                onClick={() => setShowConfirmDialog(false)}
                className="flex-1 px-4 py-2 text-blue-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  confirmAction?.();
                  setShowConfirmDialog(false);
                }}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
              >
                Reset
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notifications */}
      <Toast />
    </div>
  );
};

export default SettingsPage;
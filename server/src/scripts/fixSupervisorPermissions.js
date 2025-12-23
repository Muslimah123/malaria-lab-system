// 📁 server/src/scripts/fixSupervisorPermissions.js
// Quick script to fix supervisor permissions

const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

async function fixSupervisorPermissions() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/malaria_lab', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('✅ Connected to MongoDB');

    // Find supervisor users
    const supervisors = await User.find({ role: 'supervisor' });
    console.log(`📊 Found ${supervisors.length} supervisor users`);

    // Update permissions for each supervisor
    for (const supervisor of supervisors) {
      const updatedPermissions = {
        canUploadSamples: true,
        canViewAllTests: true,
        canDeleteTests: false,
        canManageUsers: false,
        canExportReports: true
      };

      await User.findByIdAndUpdate(supervisor._id, { permissions: updatedPermissions });
      console.log(`✅ Updated permissions for supervisor: ${supervisor.username}`);
      console.log(`   New permissions:`, updatedPermissions);
    }

    console.log(`\n🎉 Successfully updated ${supervisors.length} supervisor users`);

  } catch (error) {
    console.error('❌ Error fixing supervisor permissions:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
}

// Run the script if called directly
if (require.main === module) {
  fixSupervisorPermissions();
}

module.exports = { fixSupervisorPermissions };

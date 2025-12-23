// 📁 server/src/scripts/fixPermissions.js
// Script to fix user permissions based on their roles

const mongoose = require('mongoose');
const User = require('../models/User');
const { DEFAULT_PERMISSIONS } = require('../../utils/constants');
require('dotenv').config();

async function fixUserPermissions() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/malaria_lab', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('✅ Connected to MongoDB');

    // Get all users
    const users = await User.find({});
    console.log(`📊 Found ${users.length} users`);

    let updatedCount = 0;

    // Update each user's permissions based on their role
    for (const user of users) {
      if (DEFAULT_PERMISSIONS[user.role]) {
        const updatedPermissions = { ...user.permissions };
        let hasChanges = false;

        Object.keys(DEFAULT_PERMISSIONS[user.role]).forEach(permission => {
          if (updatedPermissions[permission] !== DEFAULT_PERMISSIONS[user.role][permission]) {
            updatedPermissions[permission] = DEFAULT_PERMISSIONS[user.role][permission];
            hasChanges = true;
          }
        });

        if (hasChanges) {
          await User.findByIdAndUpdate(user._id, { permissions: updatedPermissions });
          console.log(`✅ Updated permissions for ${user.username} (${user.role})`);
          console.log(`   Old:`, user.permissions);
          console.log(`   New:`, updatedPermissions);
          updatedCount++;
        } else {
          console.log(`ℹ️  No changes needed for ${user.username} (${user.role})`);
        }
      } else {
        console.log(`⚠️  Unknown role for ${user.username}: ${user.role}`);
      }
    }

    console.log(`\n🎉 Successfully updated permissions for ${updatedCount} users`);
    
    // Show summary of what each role should have
    console.log('\n📋 Role Permission Summary:');
    Object.entries(DEFAULT_PERMISSIONS).forEach(([role, permissions]) => {
      console.log(`\n${role.toUpperCase()}:`);
      Object.entries(permissions).forEach(([permission, value]) => {
        console.log(`  ${permission}: ${value}`);
      });
    });

  } catch (error) {
    console.error('❌ Error fixing permissions:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
}

// Run the script if called directly
if (require.main === module) {
  fixUserPermissions();
}

module.exports = { fixUserPermissions };

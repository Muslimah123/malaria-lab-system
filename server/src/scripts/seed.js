// 📁 server/src/scripts/seed.js
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

const User = require('../models/User');
const logger = require('../utils/logger');

async function seedDatabase() {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/malaria_lab';
    await mongoose.connect(mongoUri);
    console.log('✅ Connected to MongoDB for seeding');

    // Check if users already exist
    const existingUsers = await User.countDocuments();
    if (existingUsers > 0) {
      console.log('⚠️  Users already exist in the database. Skipping seed...');
      console.log(`Found ${existingUsers} existing users`);
      
      // List existing users
      const users = await User.find().select('email role');
      console.log('\nExisting users:');
      users.forEach(user => {
        console.log(`- ${user.email} (${user.role})`);
      });
      
      return;
    }

    // Create test users
    const users = [
      {
        username: 'admin',
        email: 'admin@malarialab.com',
        password: 'Admin123!',
        role: 'admin',
        firstName: 'Admin',
        lastName: 'User',
        phoneNumber: '+1234567890',
        department: 'Administration',
        licenseNumber: 'ADMIN001',
        permissions: {
          canUploadSamples: true,
          canViewAllTests: true,
          canDeleteTests: true,
          canManageUsers: true,
          canExportReports: true
        },
        isActive: true
      },
      {
        username: 'supervisor',
        email: 'supervisor@malarialab.com',
        password: 'Super123!',
        role: 'supervisor',
        firstName: 'Supervisor',
        lastName: 'User',
        phoneNumber: '+1234567891',
        department: 'Laboratory',
        licenseNumber: 'SUP001',
        permissions: {
          canUploadSamples: true,
          canViewAllTests: true,
          canDeleteTests: false,
          canManageUsers: false,
          canExportReports: true
        },
        isActive: true
      },
      {
        username: 'technician',
        email: 'tech@malarialab.com',
        password: 'Tech123!',
        role: 'technician',
        firstName: 'Technician',
        lastName: 'User',
        phoneNumber: '+1234567892',
        department: 'Laboratory',
        licenseNumber: 'TECH001',
        permissions: {
          canUploadSamples: true,
          canViewAllTests: false,
          canDeleteTests: false,
          canManageUsers: false,
          canExportReports: true
        },
        isActive: true
      }
    ];

    // Create users
    for (const userData of users) {
      const user = new User(userData);
      await user.save();
      console.log(`✅ Created user: ${user.email} (${user.role})`);
    }

    console.log('\n🎉 Database seeding completed!');
    console.log('\n📋 Test credentials:');
    console.log('─────────────────────────────────────────');
    console.log('Admin:       admin@malarialab.com / Admin123!');
    console.log('Supervisor:  supervisor@malarialab.com / Super123!');
    console.log('Technician:  tech@malarialab.com / Tech123!');
    console.log('─────────────────────────────────────────');

  } catch (error) {
    console.error('❌ Seeding failed:', error);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
}

// Run the seed function
seedDatabase();
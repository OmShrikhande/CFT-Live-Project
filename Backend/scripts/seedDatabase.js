import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, '../.env') });

// Import models
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import TransferRequest from '../models/TransferRequest.js';

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB Connected for seeding');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  }
};

// Sample data
const organizationsData = [
  {
    name: 'Tech Solutions Inc.',
    code: 'TECH001',
    description: 'Leading technology solutions provider',
    address: {
      street: '123 Tech Street',
      city: 'San Francisco',
      state: 'CA',
      country: 'USA',
      zipCode: '94105'
    },
    contact: {
      email: 'contact@techsolutions.com',
      phone: '+1-555-0123',
      website: 'https://techsolutions.com'
    },
    settings: {
      maxAdmins: 15,
      maxUsersPerAdmin: 500,
      allowUserTransfer: true,
      requireSuperAdminApproval: true
    }
  },
  {
    name: 'Global Enterprises Ltd.',
    code: 'GLOBAL01',
    description: 'International business solutions company',
    address: {
      street: '456 Business Ave',
      city: 'New York',
      state: 'NY',
      country: 'USA',
      zipCode: '10001'
    },
    contact: {
      email: 'info@globalenterprises.com',
      phone: '+1-555-0456',
      website: 'https://globalenterprises.com'
    },
    settings: {
      maxAdmins: 20,
      maxUsersPerAdmin: 1000,
      allowUserTransfer: true,
      requireSuperAdminApproval: true
    }
  }
];

const usersData = [
  // Super Admins
  {
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@techsolutions.com',
    password: 'SuperAdmin123!',
    role: 'super_admin',
    profile: {
      phone: '+1-555-0100',
      bio: 'Chief Technology Officer and Super Administrator'
    }
  },
  {
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane.smith@globalenterprises.com',
    password: 'SuperAdmin123!',
    role: 'super_admin',
    profile: {
      phone: '+1-555-0200',
      bio: 'Chief Executive Officer and Super Administrator'
    }
  },
  
  // Admins for Tech Solutions
  {
    firstName: 'Mike',
    lastName: 'Johnson',
    email: 'mike.johnson@techsolutions.com',
    password: 'Admin123!',
    role: 'admin',
    profile: {
      phone: '+1-555-0101',
      bio: 'Senior Project Manager'
    }
  },
  {
    firstName: 'Sarah',
    lastName: 'Wilson',
    email: 'sarah.wilson@techsolutions.com',
    password: 'Admin123!',
    role: 'admin',
    profile: {
      phone: '+1-555-0102',
      bio: 'Team Lead - Development'
    }
  },
  {
    firstName: 'David',
    lastName: 'Brown',
    email: 'david.brown@techsolutions.com',
    password: 'Admin123!',
    role: 'admin',
    profile: {
      phone: '+1-555-0103',
      bio: 'Operations Manager'
    }
  },

  // Admins for Global Enterprises
  {
    firstName: 'Lisa',
    lastName: 'Davis',
    email: 'lisa.davis@globalenterprises.com',
    password: 'Admin123!',
    role: 'admin',
    profile: {
      phone: '+1-555-0201',
      bio: 'Regional Manager - North America'
    }
  },
  {
    firstName: 'Robert',
    lastName: 'Miller',
    email: 'robert.miller@globalenterprises.com',
    password: 'Admin123!',
    role: 'admin',
    profile: {
      phone: '+1-555-0202',
      bio: 'Department Head - Sales'
    }
  },

  // Regular Users for Tech Solutions
  {
    firstName: 'Alice',
    lastName: 'Anderson',
    email: 'alice.anderson@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1001',
      bio: 'Software Developer'
    }
  },
  {
    firstName: 'Bob',
    lastName: 'Taylor',
    email: 'bob.taylor@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1002',
      bio: 'Frontend Developer'
    }
  },
  {
    firstName: 'Carol',
    lastName: 'White',
    email: 'carol.white@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1003',
      bio: 'UI/UX Designer'
    }
  },
  {
    firstName: 'Daniel',
    lastName: 'Garcia',
    email: 'daniel.garcia@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1004',
      bio: 'Backend Developer'
    }
  },
  {
    firstName: 'Emma',
    lastName: 'Martinez',
    email: 'emma.martinez@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1005',
      bio: 'Quality Assurance Engineer'
    }
  },
  {
    firstName: 'Frank',
    lastName: 'Rodriguez',
    email: 'frank.rodriguez@techsolutions.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-1006',
      bio: 'DevOps Engineer'
    }
  },

  // Regular Users for Global Enterprises
  {
    firstName: 'Grace',
    lastName: 'Lee',
    email: 'grace.lee@globalenterprises.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-2001',
      bio: 'Business Analyst'
    }
  },
  {
    firstName: 'Henry',
    lastName: 'Clark',
    email: 'henry.clark@globalenterprises.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-2002',
      bio: 'Sales Representative'
    }
  },
  {
    firstName: 'Ivy',
    lastName: 'Lewis',
    email: 'ivy.lewis@globalenterprises.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-2003',
      bio: 'Marketing Specialist'
    }
  },
  {
    firstName: 'Jack',
    lastName: 'Walker',
    email: 'jack.walker@globalenterprises.com',
    password: 'User123!',
    role: 'user',
    profile: {
      phone: '+1-555-2004',
      bio: 'Customer Success Manager'
    }
  }
];

// Seed function
const seedDatabase = async () => {
  try {
    console.log('🌱 Starting database seeding...');

    // Clear existing data
    console.log('🧹 Clearing existing data...');
    await TransferRequest.deleteMany({});
    await User.deleteMany({});
    await Organization.deleteMany({});

    // Create organizations
    console.log('🏢 Creating organizations...');
    const organizations = [];
    for (const orgData of organizationsData) {
      const org = await Organization.create(orgData);
      organizations.push(org);
      console.log(`   ✅ Created organization: ${org.name} (${org.code})`);
    }

    // Create users
    console.log('👥 Creating users...');
    const createdUsers = [];
    
    for (let i = 0; i < usersData.length; i++) {
      const userData = usersData[i];
      
      // Assign organization based on email domain
      let organizationId;
      if (userData.email.includes('techsolutions.com')) {
        organizationId = organizations[0]._id;
      } else if (userData.email.includes('globalenterprises.com')) {
        organizationId = organizations[1]._id;
      }

      const user = await User.create({
        ...userData,
        organization: organizationId,
        emailVerified: true,
        metadata: {
          ipAddress: '127.0.0.1',
          userAgent: 'Database Seeder'
        }
      });

      createdUsers.push(user);
      console.log(`   ✅ Created ${user.role}: ${user.firstName} ${user.lastName} (${user.email})`);

      // Update organization with super admin and admins
      if (user.role === 'super_admin') {
        await Organization.findByIdAndUpdate(organizationId, {
          superAdmin: user._id
        });
      } else if (user.role === 'admin') {
        await Organization.findByIdAndUpdate(organizationId, {
          $push: { admins: user._id }
        });
      }
    }

    // Assign users to admins
    console.log('🔗 Assigning users to admins...');
    const techAdmins = createdUsers.filter(u => 
      u.role === 'admin' && u.email.includes('techsolutions.com')
    );
    const globalAdmins = createdUsers.filter(u => 
      u.role === 'admin' && u.email.includes('globalenterprises.com')
    );

    const techUsers = createdUsers.filter(u => 
      u.role === 'user' && u.email.includes('techsolutions.com')
    );
    const globalUsers = createdUsers.filter(u => 
      u.role === 'user' && u.email.includes('globalenterprises.com')
    );

    // Assign Tech Solutions users to admins
    for (let i = 0; i < techUsers.length; i++) {
      const adminIndex = i % techAdmins.length;
      await User.findByIdAndUpdate(techUsers[i]._id, {
        assignedAdmin: techAdmins[adminIndex]._id
      });
      console.log(`   ✅ Assigned ${techUsers[i].firstName} ${techUsers[i].lastName} to admin ${techAdmins[adminIndex].firstName} ${techAdmins[adminIndex].lastName}`);
    }

    // Assign Global Enterprises users to admins
    for (let i = 0; i < globalUsers.length; i++) {
      const adminIndex = i % globalAdmins.length;
      await User.findByIdAndUpdate(globalUsers[i]._id, {
        assignedAdmin: globalAdmins[adminIndex]._id
      });
      console.log(`   ✅ Assigned ${globalUsers[i].firstName} ${globalUsers[i].lastName} to admin ${globalAdmins[adminIndex].firstName} ${globalAdmins[adminIndex].lastName}`);
    }

    // Create sample transfer requests
    console.log('📋 Creating sample transfer requests...');
    
    // Create a few sample transfer requests for Tech Solutions
    if (techAdmins.length >= 2 && techUsers.length >= 2) {
      const sampleTransfers = [
        {
          user: techUsers[0]._id,
          fromAdmin: techAdmins[0]._id,
          toAdmin: techAdmins[1]._id,
          organization: organizations[0]._id,
          requestedBy: techAdmins[0]._id,
          reason: 'User requested transfer to work on different project team',
          priority: 'medium',
          status: 'pending'
        },
        {
          user: techUsers[1]._id,
          fromAdmin: techAdmins[1]._id,
          toAdmin: techAdmins[2] ? techAdmins[2]._id : techAdmins[0]._id,
          organization: organizations[0]._id,
          requestedBy: techAdmins[1]._id,
          reason: 'Reorganization of development teams',
          priority: 'high',
          status: 'approved',
          approvedBy: createdUsers.find(u => u.role === 'super_admin' && u.email.includes('techsolutions.com'))._id,
          approvalReason: 'Approved for better team balance',
          processedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
          transferCompletedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000)
        }
      ];

      for (const transferData of sampleTransfers) {
        // Get user snapshots
        const user = await User.findById(transferData.user);
        const fromAdmin = await User.findById(transferData.fromAdmin);
        const toAdmin = await User.findById(transferData.toAdmin);

        const transfer = await TransferRequest.create({
          ...transferData,
          metadata: {
            userDataSnapshot: user.toJSON(),
            fromAdminSnapshot: fromAdmin.toJSON(),
            toAdminSnapshot: toAdmin.toJSON(),
            ipAddress: '127.0.0.1',
            userAgent: 'Database Seeder',
            transferMethod: 'manual'
          }
        });

        // If approved, update user's assigned admin
        if (transfer.status === 'approved') {
          await User.findByIdAndUpdate(transfer.user, {
            assignedAdmin: transfer.toAdmin
          });
        }

        console.log(`   ✅ Created transfer request: ${transfer.status} - ${user.firstName} ${user.lastName}`);
      }
    }

    console.log('\n🎉 Database seeding completed successfully!');
    console.log('\n📊 Summary:');
    console.log(`   Organizations: ${organizations.length}`);
    console.log(`   Total Users: ${createdUsers.length}`);
    console.log(`   Super Admins: ${createdUsers.filter(u => u.role === 'super_admin').length}`);
    console.log(`   Admins: ${createdUsers.filter(u => u.role === 'admin').length}`);
    console.log(`   Regular Users: ${createdUsers.filter(u => u.role === 'user').length}`);

    console.log('\n🔑 Login Credentials:');
    console.log('\n   Super Admins:');
    createdUsers.filter(u => u.role === 'super_admin').forEach(user => {
      console.log(`     ${user.email} / SuperAdmin123!`);
    });
    
    console.log('\n   Admins:');
    createdUsers.filter(u => u.role === 'admin').forEach(user => {
      console.log(`     ${user.email} / Admin123!`);
    });

    console.log('\n   Users:');
    createdUsers.filter(u => u.role === 'user').slice(0, 5).forEach(user => {
      console.log(`     ${user.email} / User123!`);
    });
    console.log('     ... and more');

  } catch (error) {
    console.error('❌ Error seeding database:', error);
  } finally {
    await mongoose.connection.close();
    console.log('\n🔌 Database connection closed');
    process.exit(0);
  }
};

// Run seeding
const runSeed = async () => {
  await connectDB();
  await seedDatabase();
};

// Check if script is run directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runSeed();
}

export default seedDatabase;
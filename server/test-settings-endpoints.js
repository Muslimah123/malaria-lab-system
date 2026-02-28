// 📁 server/test-settings-endpoints.js
// Simple test script to verify settings endpoints are working
const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const TEST_TOKEN = 'your-test-token-here'; 

async function testSettingsEndpoints() {
  console.log('Testing Settings Endpoints...\n');

  try {
    // Test 1: Health check
    console.log('1. Testing health endpoint...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log(` Health: ${healthResponse.status} - ${healthResponse.data.status}\n`);

    // Test 2: API root
    console.log('2. Testing API root...');
    const apiRootResponse = await axios.get(`${BASE_URL}/api`);
    console.log(`  API Root: ${apiRootResponse.status}`);
    console.log(`  Available endpoints:`, apiRootResponse.data.endpoints);
    console.log('');

    // Test 3: Settings profile endpoint (should return 401 without auth)
    console.log('3. Testing settings profile endpoint (no auth)...');
    try {
      await axios.get(`${BASE_URL}/api/settings/profile`);
      console.log(' Expected 401 but got success');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        console.log(' Settings profile: 401 Unauthorized (expected)');
      } else {
        console.log(`  Unexpected error: ${error.response?.status || error.message}`);
      }
    }
    console.log('');

    // Test 4: Settings user endpoint (should return 401 without auth)
    console.log('4. Testing settings user endpoint (no auth)...');
    try {
      await axios.get(`${BASE_URL}/api/settings/user`);
      console.log(' Expected 401 but got success');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        console.log('   Settings user: 401 Unauthorized (expected)');
      } else {
        console.log(`  Unexpected error: ${error.response?.status || error.message}`);
      }
    }
    console.log('');

    // Test 5: Check if settings routes are mounted
    console.log('5. Checking if settings routes are mounted...');
    const settingsResponse = await axios.get(`${BASE_URL}/api/settings/profile`, {
      headers: { 'Authorization': `Bearer ${TEST_TOKEN}` }
    }).catch(() => null);
    
    if (settingsResponse) {
      console.log(' Settings routes are mounted and accessible');
    } else {
      console.log(' Settings routes are not accessible (may not be mounted)');
    }

  } catch (error) {
    console.error(' Test failed:', error.message);
    if (error.response) {
      console.error('   Status:', error.response.status);
      console.error('   Data:', error.response.data);
    }
  }
}

// Run the test
testSettingsEndpoints();








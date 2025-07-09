// 📁 client/src/utils/validators.js
// High-level reusable validation functions for forms and uploads
// Can be used across multiple components or hooks for consistency and DRY code
// Reusable validation functions for forms and uploads

// Email validation
export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Password strength: min 8 chars, 1 number, 1 letter
export function isStrongPassword(pw) {
  return /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=]{8,}$/.test(pw);
}

// File type validation (e.g., images only)
export function isValidFileType(file, allowedTypes = ['image/jpeg', 'image/png']) {
  return file && allowedTypes.includes(file.type);
}

// File size validation (max in bytes)
export function isValidFileSize(file, maxSize = 5 * 1024 * 1024) {
  return file && file.size <= maxSize;
}

// Patient/Test ID validation (alphanumeric, 6-20 chars)
export function isValidId(id) {
  return /^[A-Za-z0-9\-]{6,20}$/.test(id);
}
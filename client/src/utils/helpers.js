// 📁 client/src/utils/helpers.js
// Pure utility functions for formatting and data manipulation

// Format a date string to 'YYYY-MM-DD HH:mm' (24h)
export function formatDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  return d.toLocaleString('sv-SE', { hour12: false }).replace('T', ' ').slice(0, 16);
}

// Capitalize the first letter of a string
export function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// Format file size in human-readable form
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Group array of objects by a key
export function groupBy(arr, key) {
  return arr.reduce((acc, obj) => {
    const group = obj[key] || 'Other';
    acc[group] = acc[group] || [];
    acc[group].push(obj);
    return acc;
  }, {});
}
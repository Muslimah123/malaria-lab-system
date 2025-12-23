// 📁 client/src/reportWebVitals.js
// Fixed version compatible with current web-vitals package

const reportWebVitals = (onPerfEntry) => {
  if (onPerfEntry && onPerfEntry instanceof Function) {
    import('web-vitals').then(({ onCLS, onFID, onFCP, onLCP, onTTFB }) => {
      onCLS(onPerfEntry);
      onFID(onPerfEntry);
      onFCP(onPerfEntry);
      onLCP(onPerfEntry);
      onTTFB(onPerfEntry);
    }).catch((error) => {
      // Fallback for older versions or if web-vitals fails to load
      console.warn('Web Vitals could not be loaded:', error);
      
      // Try the old API as fallback
      import('web-vitals').then((webVitals) => {
        // Check if the old API exists
        if (webVitals.getCLS) {
          webVitals.getCLS(onPerfEntry);
          webVitals.getFID(onPerfEntry);
          webVitals.getFCP(onPerfEntry);
          webVitals.getLCP(onPerfEntry);
          webVitals.getTTFB(onPerfEntry);
        } else {
          console.warn('Web Vitals API not available');
        }
      }).catch(() => {
        console.warn('Web Vitals package not available');
      });
    });
  }
};

export default reportWebVitals;
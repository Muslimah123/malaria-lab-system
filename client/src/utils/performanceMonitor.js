// 📁 client/src/utils/performanceMonitor.js
// Comprehensive Performance Monitoring System

// Performance thresholds
const THRESHOLDS = {
  SLOW_API_CALL: 15000, // ✅ UPDATED: 15s instead of 10s for slow API calls
  VERY_SLOW_API_CALL: 45000, // ✅ UPDATED: 45s threshold for very slow operations (matches YOLO ~30s + buffer)
  SLOW_RENDER: 100,
  SLOW_INTERACTION: 300,
  MEMORY_WARNING: 50 * 1024 * 1024, // 50MB
  MEMORY_CRITICAL: 100 * 1024 * 1024 // 100MB
};

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      apiCalls: [],
      renderTimes: [],
      memoryUsage: [],
      userInteractions: [],
      errors: []
    };
    
    this.startTime = Date.now();
    this.isMonitoring = true;
    
    // Start memory monitoring
    this.startMemoryMonitoring();
    
    // Start error monitoring
    this.startErrorMonitoring();
  }

  // Monitor API call performance
  startApiCall(endpoint, method = 'GET') {
    const startTime = performance.now();
    const callId = `api_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return {
      id: callId,
      endpoint,
      method,
      startTime,
      end: (success = true, error = null) => {
        const duration = performance.now() - startTime;
        const timestamp = Date.now();
        
        this.metrics.apiCalls.push({ 
          id: callId,
          endpoint, 
          method,
          duration, 
          timestamp,
          success,
          error: error?.message || null
        });
        
        // Log performance
        console.log(`API Call to ${method} ${endpoint}: ${duration.toFixed(2)}ms - ${success ? 'SUCCESS' : 'FAILED'}`);
        
        // Alert if too slow
        if (duration > THRESHOLDS.SLOW_API_CALL) {
          console.warn(`🐌 Slow API call detected: ${method} ${endpoint} took ${duration.toFixed(2)}ms`);
          this.recordError('SLOW_API_CALL', { endpoint, method, duration });
        }
        
        // Alert if failed
        if (!success) {
          console.error(`❌ API call failed: ${method} ${endpoint} - ${error?.message || 'Unknown error'}`);
          this.recordError('API_CALL_FAILED', { endpoint, method, error: error?.message });
        }
      }
    };
  }

  // Monitor component render performance
  measureRenderTime(componentName, renderFn) {
    const startTime = performance.now();
    const renderId = `render_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      const result = renderFn();
      const duration = performance.now() - startTime;
      
      this.metrics.renderTimes.push({ 
        id: renderId,
        componentName, 
        duration, 
        timestamp: Date.now() 
      });
      
      // Alert if too slow (60fps threshold = 16.67ms)
      if (duration > THRESHOLDS.SLOW_RENDER) {
        console.warn(`🐌 Slow render detected: ${componentName} took ${duration.toFixed(2)}ms`);
        this.recordError('SLOW_RENDER', { componentName, duration });
      }
      
      return result;
    } catch (error) {
      this.recordError('RENDER_ERROR', { componentName, error: error.message });
      throw error;
    }
  }

  // Monitor user interactions
  trackUserInteraction(action, details = {}) {
    const interaction = {
      action,
      details,
      timestamp: Date.now(),
      sessionDuration: Date.now() - this.startTime
    };
    
    this.metrics.userInteractions.push(interaction);
    
    // Log significant interactions
    if (['DIAGNOSIS_STARTED', 'IMAGE_UPLOADED', 'REPORT_GENERATED'].includes(action)) {
      console.log(`👤 User Action: ${action}`, details);
    }
  }

  // Record errors
  recordError(type, details = {}) {
    const error = {
      type,
      details,
      timestamp: Date.now(),
      userAgent: navigator.userAgent,
      url: window.location.href
    };
    
    this.metrics.errors.push(error);
    
    // Log errors
    console.error(`❌ Error recorded: ${type}`, details);
    
    // Send to monitoring service if critical
    if (['CRITICAL_ERROR', 'API_CALL_FAILED', 'RENDER_ERROR'].includes(type)) {
      this.sendErrorToMonitoring(error);
    }
  }

  // Memory monitoring
  startMemoryMonitoring() {
    if ('memory' in performance) {
      setInterval(() => {
        const memory = performance.memory;
        this.metrics.memoryUsage.push({
          used: memory.usedJSHeapSize,
          total: memory.totalJSHeapSize,
          limit: memory.jsHeapSizeLimit,
          timestamp: Date.now()
        });
        
        // Alert if memory usage is high
        const usagePercent = (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100;
        if (usagePercent > 80) {
          console.warn(`⚠️ High memory usage: ${usagePercent.toFixed(1)}%`);
          this.recordError('HIGH_MEMORY_USAGE', { usagePercent });
        }
      }, 10000); // Check every 10 seconds
    }
  }

  // Error monitoring
  startErrorMonitoring() {
    // Global error handler
    window.addEventListener('error', (event) => {
      this.recordError('GLOBAL_ERROR', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno
      });
    });

    // Unhandled promise rejection
    window.addEventListener('unhandledrejection', (event) => {
      this.recordError('UNHANDLED_PROMISE_REJECTION', {
        reason: event.reason?.message || event.reason
      });
    });
  }

  // Send error to monitoring service
  sendErrorToMonitoring(error) {
    // In production, you'd send this to your monitoring service
    // For now, we'll just log it
    console.log('📡 Sending error to monitoring service:', error);
    
    // Example: Send to your backend
    // fetch('/api/monitoring/errors', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify(error)
    // });
  }

  // Get performance summary
  getSummary() {
    const now = Date.now();
    const sessionDuration = now - this.startTime;
    
    // Calculate API performance
    const apiCalls = this.metrics.apiCalls;
    const successfulCalls = apiCalls.filter(call => call.success);
    const failedCalls = apiCalls.filter(call => !call.success);
    
    const apiAvg = successfulCalls.length > 0 
      ? successfulCalls.reduce((sum, call) => sum + call.duration, 0) / successfulCalls.length 
      : 0;
    
    const apiSuccessRate = apiCalls.length > 0 
      ? (successfulCalls.length / apiCalls.length) * 100 
      : 0;
    
    // Calculate render performance
    const renderTimes = this.metrics.renderTimes;
    const renderAvg = renderTimes.length > 0 
      ? renderTimes.reduce((sum, render) => sum + render.duration, 0) / renderTimes.length 
      : 0;
    
    // Calculate memory usage
    const memoryUsage = this.metrics.memoryUsage;
    const currentMemory = memoryUsage.length > 0 ? memoryUsage[memoryUsage.length - 1] : null;
    const memoryPercent = currentMemory 
      ? (currentMemory.used / currentMemory.limit) * 100 
      : 0;
    
    return {
      session: {
        startTime: this.startTime,
        duration: sessionDuration,
        durationFormatted: this.formatDuration(sessionDuration)
      },
      api: {
        totalCalls: apiCalls.length,
        successfulCalls: successfulCalls.length,
        failedCalls: failedCalls.length,
        successRate: apiSuccessRate,
        averageResponseTime: apiAvg,
        slowestCall: Math.max(...apiCalls.map(call => call.duration), 0),
        fastestCall: Math.min(...apiCalls.map(call => call.duration), Infinity)
      },
      rendering: {
        totalRenders: renderTimes.length,
        averageRenderTime: renderAvg,
        slowestRender: Math.max(...renderTimes.map(render => render.duration), 0),
        fastestRender: Math.min(...renderTimes.map(render => render.duration), Infinity)
      },
      memory: {
        currentUsage: currentMemory?.used || 0,
        currentTotal: currentMemory?.total || 0,
        currentLimit: currentMemory?.limit || 0,
        usagePercent: memoryPercent,
        averageUsage: memoryUsage.length > 0 
          ? memoryUsage.reduce((sum, mem) => sum + (mem.used / mem.limit) * 100, 0) / memoryUsage.length 
          : 0
      },
      user: {
        totalInteractions: this.metrics.userInteractions.length,
        recentInteractions: this.metrics.userInteractions.slice(-10)
      },
      errors: {
        totalErrors: this.metrics.errors.length,
        errorTypes: this.metrics.errors.reduce((acc, error) => {
          acc[error.type] = (acc[error.type] || 0) + 1;
          return acc;
        }, {}),
        recentErrors: this.metrics.errors.slice(-5)
      }
    };
  }

  // Get real-time metrics
  getRealTimeMetrics() {
    const summary = this.getSummary();
    const now = Date.now();
    
    // Get recent API calls (last 5 minutes)
    const recentApiCalls = this.metrics.apiCalls.filter(
      call => now - call.timestamp < 5 * 60 * 1000
    );
    
    // Get recent render times (last 5 minutes)
    const recentRenders = this.metrics.renderTimes.filter(
      render => now - render.timestamp < 5 * 60 * 1000
    );
    
    return {
      ...summary,
      realTime: {
        recentApiCalls: recentApiCalls.length,
        recentRenders: recentRenders.length,
        currentMemoryUsage: summary.memory.usagePercent,
        uptime: summary.session.durationFormatted
      }
    };
  }

  // Format duration
  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  // Export metrics for analysis
  exportMetrics() {
    return JSON.stringify({
      summary: this.getSummary(),
      rawData: this.metrics,
      exportTime: new Date().toISOString()
    }, null, 2);
  }

  // Clear old metrics (keep last 24 hours)
  cleanupOldMetrics() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
    
    this.metrics.apiCalls = this.metrics.apiCalls.filter(call => call.timestamp > cutoff);
    this.metrics.renderTimes = this.metrics.renderTimes.filter(render => render.timestamp > cutoff);
    this.metrics.memoryUsage = this.metrics.memoryUsage.filter(mem => mem.timestamp > cutoff);
    this.metrics.userInteractions = this.metrics.userInteractions.filter(interaction => interaction.timestamp > cutoff);
    this.metrics.errors = this.metrics.errors.filter(error => error.timestamp > cutoff);
  }

  // Start/stop monitoring
  start() {
    this.isMonitoring = true;
    console.log('🚀 Performance monitoring started');
  }

  stop() {
    this.isMonitoring = false;
    console.log('⏹️ Performance monitoring stopped');
  }

  // Reset all metrics
  reset() {
    this.metrics = {
      apiCalls: [],
      renderTimes: [],
      memoryUsage: [],
      userInteractions: [],
      errors: []
    };
    this.startTime = Date.now();
    console.log('🔄 Performance metrics reset');
  }
}

// Create singleton instance
export const performanceMonitor = new PerformanceMonitor();

// Auto-cleanup every hour
setInterval(() => {
  performanceMonitor.cleanupOldMetrics();
}, 60 * 60 * 1000);

// Export for use in components
export default performanceMonitor;

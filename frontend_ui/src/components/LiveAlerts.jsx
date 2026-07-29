import React from 'react';
import { ShieldAlert, AlertTriangle, Info } from 'lucide-react';

// 1. Mock Data Pipeline
const mockAlerts = [
  { id: 1, timestamp: '13:20:45', severity: 'critical', ip: '192.168.1.105', message: 'Multiple failed SSH logins detected' },
  { id: 2, timestamp: '13:21:12', severity: 'warning', ip: '10.0.0.42', message: 'Unusual outbound traffic spike' },
  { id: 3, timestamp: '13:22:05', severity: 'info', ip: '172.16.0.8', message: 'Standard port scan blocked' },
];

export default function LiveAlerts() {
  
  // 2. Dynamic Severity Engine
  const getSeverityConfig = (severity) => {
    switch (severity) {
      case 'critical':
        return { 
          icon: <ShieldAlert className="w-5 h-5 text-rose-500" />, 
          border: 'border-rose-500/50', bg: 'bg-rose-500/10', text: 'text-rose-500' 
        };
      case 'warning':
        return { 
          icon: <AlertTriangle className="w-5 h-5 text-amber-500" />, 
          border: 'border-amber-500/50', bg: 'bg-amber-500/10', text: 'text-amber-500' 
        };
      case 'info':
      default:
        return { 
          icon: <Info className="w-5 h-5 text-cyan-500" />, 
          border: 'border-cyan-500/50', bg: 'bg-cyan-500/10', text: 'text-cyan-500' 
        };
    }
  };

  // 3. UI Rendering
  return (
    <div className="w-full max-w-3xl border border-slate-800 bg-slate-900/50 rounded-lg p-4">
      {/* Header with pulsing indicator */}
      <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
        Live Network Alerts
      </h2>
      
      {/* Alert List */}
      <div className="flex flex-col gap-3">
        {mockAlerts.map((alert) => {
          const config = getSeverityConfig(alert.severity);
          
          return (
            <div key={alert.id} className={`flex items-start gap-4 p-3 rounded border ${config.border} ${config.bg}`}>
              {/* Icon Container */}
              <div className="mt-0.5">{config.icon}</div>
              
              {/* Alert Data Container */}
              <div className="flex-1">
                <div className="flex justify-between items-center mb-1">
                  <span className={`font-mono text-sm font-bold ${config.text}`}>
                    {alert.ip}
                  </span>
                  <span className="font-mono text-xs text-slate-500">
                    {alert.timestamp}
                  </span>
                </div>
                <p className="text-sm text-slate-300">{alert.message}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
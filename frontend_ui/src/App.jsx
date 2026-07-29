import React from 'react';
import SystemMetrics from './components/SystemMetrics';
import LiveAlerts from './components/LiveAlerts';
import SensorNodes from './components/SensorNodes'; // Import the new component

export default function App() {
  return (
    <div className="p-8 bg-slate-950 min-h-screen text-slate-100">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-2xl font-bold text-cyan-400 mb-6">
          The Midnight Protocol Dashboard
        </h1>
        
        {/* Top Telemetry Row */}
        <SystemMetrics />
        
        {/* Main Dashboard Grid */}
        {/* grid-cols-1 on mobile, 3 columns on large desktop screens */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Alerts take up 2 out of the 3 columns (66% width) */}
          <div className="lg:col-span-2">
            <LiveAlerts />
          </div>
          
          {/* Sensors take up 1 out of the 3 columns (33% width) */}
          <div className="lg:col-span-1">
            <SensorNodes />
          </div>
          
        </div>
        
      </div>
    </div>
  );
}
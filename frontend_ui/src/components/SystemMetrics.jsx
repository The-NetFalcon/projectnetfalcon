import React from 'react';
import { Cpu, HardDrive, Activity, Wifi } from 'lucide-react';

const metrics = [
  { id: 1, label: 'CPU Usage', value: '34.2%', status: 'optimal', icon: <Cpu className="w-5 h-5 text-cyan-400" /> },
  { id: 2, label: 'Memory Allocation', value: '6.4 / 16 GB', status: 'optimal', icon: <HardDrive className="w-5 h-5 text-cyan-400" /> },
  { id: 3, label: 'Packet Capture Rate', value: '1.4 MB/s', status: 'active', icon: <Activity className="w-5 h-5 text-emerald-400" /> },
  { id: 4, label: 'Sensor Nodes Online', value: '4 / 4', status: 'secure', icon: <Wifi className="w-5 h-5 text-emerald-400" /> },
];

export default function SystemMetrics() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full max-w-7xl mb-6">
      {metrics.map((metric) => (
        <div 
          key={metric.id} 
          className="border border-slate-800 bg-slate-900/50 rounded-lg p-4 flex items-center justify-between"
        >
          <div>
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">{metric.label}</p>
            <p className="text-xl font-bold font-mono text-slate-100 mt-1">{metric.value}</p>
          </div>
          <div className="p-3 bg-slate-800/50 rounded-md border border-slate-700/50">
            {metric.icon}
          </div>
        </div>
      ))}
    </div>
  );
}
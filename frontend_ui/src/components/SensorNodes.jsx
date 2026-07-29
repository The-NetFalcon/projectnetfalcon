import React from 'react';
import { Server, ShieldCheck, AlertCircle } from 'lucide-react';

// 1. Sensor Mock Data
const sensors = [
  { id: 1, name: 'DAFDN-Core-Alpha', role: 'Meta-Analysis', status: 'active', latency: '12ms' },
  { id: 2, name: 'Edge-Gateway-04', role: 'Ingestion', status: 'active', latency: '8ms' },
  { id: 3, name: 'DMZ-Firewall-01', role: 'Traffic Filter', status: 'warning', latency: '85ms' },
  { id: 4, name: 'Storage-Cluster', role: 'Cold Logs', status: 'active', latency: '15ms' }
];

export default function SensorNodes() {
  return (
    <div className="w-full border border-slate-800 bg-slate-900/50 rounded-lg p-4">
      {/* Header */}
      <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
        <Server className="w-5 h-5 text-slate-400" />
        Active Sensor Nodes
      </h2>
      
      {/* Sensor List */}
      <div className="flex flex-col gap-3">
        {sensors.map((node) => (
          <div key={node.id} className="flex items-center justify-between p-3 rounded border border-slate-800/80 bg-slate-800/20">
            
            {/* Node Info */}
            <div>
              <p className="font-mono text-sm font-bold text-slate-200">{node.name}</p>
              <p className="text-xs text-slate-500 mt-0.5">{node.role}</p>
            </div>
            
            {/* Status & Latency */}
            <div className="flex items-center gap-4">
              <span className="font-mono text-xs text-slate-400">{node.latency}</span>
              
              {node.status === 'active' ? (
                <ShieldCheck className="w-5 h-5 text-emerald-500" />
              ) : (
                <AlertCircle className="w-5 h-5 text-amber-500 animate-pulse" />
              )}
            </div>
            
          </div>
        ))}
      </div>
    </div>
  );
}
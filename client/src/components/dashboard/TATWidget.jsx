import React, { useState, useEffect } from 'react';
import { Timer, CheckCircle, AlertTriangle, TrendingUp } from 'lucide-react';
import apiService from '../../services/api';

const PRIORITY_COLORS = {
  urgent: { bar: 'bg-rose-500', text: 'text-rose-300', badge: 'bg-rose-500/20 border-rose-500/30 text-rose-300' },
  high:   { bar: 'bg-amber-500', text: 'text-amber-300', badge: 'bg-amber-500/20 border-amber-500/30 text-amber-300' },
  normal: { bar: 'bg-blue-500',  text: 'text-blue-300',  badge: 'bg-blue-500/20 border-blue-500/30 text-blue-300' },
  low:    { bar: 'bg-slate-400', text: 'text-slate-300', badge: 'bg-slate-500/20 border-slate-500/30 text-slate-300' },
};

const SLA_MINUTES = { urgent: 60, high: 120, normal: 240, low: 480 };

function fmtMinutes(mins) {
  if (mins == null || isNaN(mins)) return '—';
  if (mins < 60) return `${Math.round(mins)}m`;
  const h = Math.floor(mins / 60);
  const m = Math.round(mins % 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export default function TATWidget() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await apiService.analytics.getTAT();
        if (!cancelled && res?.data) setData(res.data);
      } catch {
        // silently ignore — TAT is non-critical dashboard widget
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="bg-white/5 border border-white/10 rounded-2xl p-5 animate-pulse">
        <div className="h-4 bg-white/10 rounded w-1/2 mb-4" />
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-3 bg-white/10 rounded" />)}
        </div>
      </div>
    );
  }

  if (!data) return null;

  const { avgTAT, totalCompleted, slaBreaches, slaBreachRate, byPriority } = data;
  const breachPct = Math.round((slaBreachRate || 0) * 100);
  const onTimePct = 100 - breachPct;

  return (
    <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/15 rounded-lg border border-blue-500/20">
            <Timer className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm">Turnaround Time</h3>
            <p className="text-white/40 text-xs">SLA compliance overview</p>
          </div>
        </div>
        <span className="text-white/30 text-xs">{totalCompleted} tests</span>
      </div>

      <div className="p-5 space-y-4">
        {/* Summary row */}
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="bg-white/5 rounded-xl p-3">
            <p className="text-white font-semibold text-lg">{fmtMinutes(avgTAT)}</p>
            <p className="text-white/40 text-xs mt-0.5">Avg TAT</p>
          </div>
          <div className="bg-white/5 rounded-xl p-3">
            <p className={`font-semibold text-lg ${onTimePct >= 80 ? 'text-emerald-400' : onTimePct >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
              {onTimePct}%
            </p>
            <p className="text-white/40 text-xs mt-0.5">On-time</p>
          </div>
          <div className="bg-white/5 rounded-xl p-3">
            <p className={`font-semibold text-lg ${slaBreaches === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
              {slaBreaches}
            </p>
            <p className="text-white/40 text-xs mt-0.5">Breaches</p>
          </div>
        </div>

        {/* On-time bar */}
        <div>
          <div className="flex justify-between text-xs text-white/40 mb-1">
            <span>SLA compliance</span>
            <span>{onTimePct}%</span>
          </div>
          <div className="h-2 bg-white/10 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${onTimePct >= 80 ? 'bg-emerald-500' : onTimePct >= 60 ? 'bg-amber-500' : 'bg-rose-500'}`}
              style={{ width: `${onTimePct}%` }}
            />
          </div>
        </div>

        {/* Per-priority breakdown */}
        {byPriority && Object.keys(byPriority).length > 0 && (
          <div className="space-y-2">
            <p className="text-white/40 text-xs uppercase tracking-wide">By Priority</p>
            {Object.entries(byPriority).map(([priority, stats]) => {
              const sla = SLA_MINUTES[priority] || 240;
              const avg = stats.avgTAT || 0;
              const pct = Math.min(100, Math.round((avg / sla) * 100));
              const colors = PRIORITY_COLORS[priority] || PRIORITY_COLORS.normal;
              const over = avg > sla;
              return (
                <div key={priority} className="flex items-center gap-3">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${colors.badge} w-14 text-center flex-shrink-0 capitalize`}>
                    {priority}
                  </span>
                  <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${over ? 'bg-rose-500' : colors.bar}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className={`text-xs font-medium w-12 text-right flex-shrink-0 ${over ? 'text-rose-400' : 'text-white/60'}`}>
                    {fmtMinutes(avg)}
                  </span>
                  {over && <AlertTriangle className="w-3 h-3 text-rose-400 flex-shrink-0" />}
                  {!over && <CheckCircle className="w-3 h-3 text-emerald-400 flex-shrink-0" />}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

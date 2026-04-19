import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ClipboardList, RefreshCw, AlertTriangle, Clock, CheckCircle,
  ChevronRight, Filter, Search, Zap, User
} from 'lucide-react';
import AppLayout from '../components/layout/AppLayout';
import apiService from '../services/api';

const PRIORITY_STYLE = {
  urgent: { bg: 'bg-rose-500/20 border-rose-500/30', text: 'text-rose-300', dot: 'bg-rose-400', label: 'Urgent' },
  high:   { bg: 'bg-orange-500/20 border-orange-500/30', text: 'text-orange-300', dot: 'bg-orange-400', label: 'High' },
  normal: { bg: 'bg-blue-500/20 border-blue-500/30', text: 'text-blue-300', dot: 'bg-blue-400', label: 'Normal' },
  low:    { bg: 'bg-slate-500/20 border-slate-500/30', text: 'text-slate-300', dot: 'bg-slate-400', label: 'Low' },
};

const STATUS_STYLE = {
  pending:    { text: 'text-amber-300',  label: 'Pending' },
  processing: { text: 'text-blue-300',   label: 'Processing' },
  completed:  { text: 'text-green-300',  label: 'Completed' },
  failed:     { text: 'text-rose-300',   label: 'Failed' },
};

function elapsed(date) {
  const mins = Math.floor((Date.now() - new Date(date)) / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function tatColor(mins) {
  if (mins >= 120) return 'text-rose-400';
  if (mins >= 60)  return 'text-amber-400';
  return 'text-green-400';
}

export default function WorklistPage() {
  const navigate = useNavigate();
  const [tests, setTests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');       // all | pending | processing | completed
  const [priority, setPriority] = useState('all');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const LIMIT = 20;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, limit: LIMIT };
      if (filter !== 'all')   params.status   = filter;
      if (priority !== 'all') params.priority = priority;
      if (search)             params.search   = search;

      const res = await apiService.tests.getAll(params);
      if (res.success) {
        setTests(res.data?.tests || res.data || []);
        setTotal(res.data?.pagination?.total || 0);
      }
    } catch (e) {
      console.error('Worklist load error:', e);
    } finally {
      setLoading(false);
    }
  }, [page, filter, priority, search]);

  useEffect(() => { load(); }, [load]);

  const filtered = tests.filter(t => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      t.testId?.toLowerCase().includes(q) ||
      t.patientId?.toLowerCase().includes(q) ||
      `${t.patient?.firstName} ${t.patient?.lastName}`.toLowerCase().includes(q)
    );
  });

  const stats = {
    pending:    tests.filter(t => t.status === 'pending').length,
    processing: tests.filter(t => t.status === 'processing').length,
    urgent:     tests.filter(t => t.priority === 'urgent').length,
  };

  return (
    <AppLayout title="Worklist" subtitle="Pending & in-progress tests">
      <div className="space-y-6">

        {/* Summary bar */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'Pending',    value: stats.pending,    color: 'amber',  icon: Clock },
            { label: 'Processing', value: stats.processing, color: 'blue',   icon: Zap },
            { label: 'Urgent',     value: stats.urgent,     color: 'rose',   icon: AlertTriangle },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className={`bg-${color}-500/10 border border-${color}-500/20 rounded-xl p-4 flex items-center gap-3`}>
              <Icon className={`w-6 h-6 text-${color}-400`} />
              <div>
                <div className={`text-2xl font-bold text-${color}-300`}>{value}</div>
                <div className="text-xs text-white/50">{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="bg-white/5 border border-white/10 rounded-xl p-4 flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30" />
            <input
              type="text"
              placeholder="Search test ID, patient…"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
              className="w-full bg-white/10 border border-white/20 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
            />
          </div>

          <div className="flex gap-1">
            {['all', 'pending', 'processing', 'completed'].map(s => (
              <button
                key={s}
                onClick={() => { setFilter(s); setPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${
                  filter === s ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/60 hover:bg-white/20'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex gap-1">
            {['all', 'urgent', 'high', 'normal', 'low'].map(p => (
              <button
                key={p}
                onClick={() => { setPriority(p); setPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${
                  priority === p ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/60 hover:bg-white/20'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          <button onClick={load} className="p-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors">
            <RefreshCw className={`w-4 h-4 text-white/60 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Table */}
        <div className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/5 text-white/50 text-xs uppercase tracking-wide">
                <th className="px-4 py-3 text-left">Test ID</th>
                <th className="px-4 py-3 text-left">Patient</th>
                <th className="px-4 py-3 text-left">Priority</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Submitted</th>
                <th className="px-4 py-3 text-left">Technician</th>
                <th className="px-4 py-3 text-left">TAT</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-white/30">Loading…</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-white/30">No tests found</td></tr>
              ) : filtered.map(test => {
                const prio  = PRIORITY_STYLE[test.priority] || PRIORITY_STYLE.normal;
                const st    = STATUS_STYLE[test.status] || STATUS_STYLE.pending;
                const isCompleted = test.status === 'completed';
                // For completed tests: TAT = processedAt - createdAt (actual time taken)
                // For pending/processing: TAT = now - createdAt (live elapsed time)
                const endTime = isCompleted && test.processedAt ? new Date(test.processedAt) : Date.now();
                const tatMins = Math.floor((endTime - new Date(test.createdAt)) / 60000);

                return (
                  <tr
                    key={test._id}
                    className="hover:bg-white/5 cursor-pointer transition-colors"
                    onClick={() => navigate(isCompleted ? `/results/${test.testId}` : `/tests`)}
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-white text-xs bg-white/10 px-2 py-0.5 rounded">
                        {test.testId}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-full bg-blue-500/20 flex items-center justify-center">
                          <User className="w-3.5 h-3.5 text-blue-400" />
                        </div>
                        <div>
                          <div className="text-white font-medium">
                            {test.patient ? `${test.patient.firstName} ${test.patient.lastName}` : test.patientId}
                          </div>
                          <div className="text-white/40 text-xs">{test.patientId}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs border ${prio.bg} ${prio.text}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${prio.dot}`} />
                        {prio.label}
                      </span>
                    </td>
                    <td className={`px-4 py-3 text-xs font-medium capitalize ${st.text}`}>
                      {st.label}
                    </td>
                    <td className="px-4 py-3 text-white/50 text-xs">{elapsed(test.createdAt)}</td>
                    <td className="px-4 py-3 text-white/60 text-xs">
                      {test.technician ? `${test.technician.firstName} ${test.technician.lastName}` : '—'}
                    </td>
                    <td className={`px-4 py-3 text-xs font-mono font-medium ${tatColor(tatMins)}`}>
                      {tatMins >= 60 ? `${Math.floor(tatMins / 60)}h ${tatMins % 60}m` : `${tatMins}m`}
                    </td>
                    <td className="px-4 py-3">
                      <ChevronRight className="w-4 h-4 text-white/30" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {total > LIMIT && (
            <div className="px-4 py-3 border-t border-white/10 flex items-center justify-between text-xs text-white/50">
              <span>Showing {(page - 1) * LIMIT + 1}–{Math.min(page * LIMIT, total)} of {total}</span>
              <div className="flex gap-2">
                <button
                  disabled={page === 1}
                  onClick={() => setPage(p => p - 1)}
                  className="px-3 py-1 bg-white/10 rounded hover:bg-white/20 disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  Prev
                </button>
                <button
                  disabled={page * LIMIT >= total}
                  onClick={() => setPage(p => p + 1)}
                  className="px-3 py-1 bg-white/10 rounded hover:bg-white/20 disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}

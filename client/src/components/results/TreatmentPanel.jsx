import React, { useState, useEffect } from 'react';
import { Pill, ChevronDown, CheckCircle, Clock, AlertTriangle, Edit2 } from 'lucide-react';
import apiService from '../../services/api';

const DRUGS = [
  'Artemether-Lumefantrine',
  'Artesunate',
  'Artesunate-Amodiaquine',
  'Dihydroartemisinin-Piperaquine',
  'Quinine',
  'Chloroquine',
  'Primaquine',
  'Other'
];

const OUTCOME_STYLES = {
  pending:           { color: 'text-amber-300',   bg: 'bg-amber-500/10 border-amber-500/20',  label: 'Pending' },
  improving:         { color: 'text-blue-300',    bg: 'bg-blue-500/10 border-blue-500/20',    label: 'Improving' },
  cured:             { color: 'text-green-300',   bg: 'bg-green-500/10 border-green-500/20',  label: 'Cured' },
  treatment_failure: { color: 'text-rose-300',    bg: 'bg-rose-500/10 border-rose-500/20',    label: 'Treatment Failure' },
  referred:          { color: 'text-purple-300',  bg: 'bg-purple-500/10 border-purple-500/20', label: 'Referred' },
  lost_to_followup:  { color: 'text-slate-300',   bg: 'bg-slate-500/10 border-slate-500/20',  label: 'Lost to Follow-up' },
};

export default function TreatmentPanel({ testId, diagnosisResult }) {
  const [treatment, setTreatment]     = useState(null);
  const [loading, setLoading]         = useState(true);
  const [showForm, setShowForm]       = useState(false);
  const [showOutcome, setShowOutcome] = useState(false);
  const [submitting, setSubmitting]   = useState(false);
  const [error, setError]             = useState(null);

  const [form, setForm] = useState({
    drug: '', drugOther: '', dosage: '', duration: '', route: 'oral', followUpDate: '', notes: ''
  });
  const [outcomeForm, setOutcomeForm] = useState({ outcome: '', followUpNotes: '' });

  const isPositive = diagnosisResult?.status === 'POSITIVE' ||
                     diagnosisResult?.manualReview?.overriddenStatus === 'POSITIVE';

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await apiService.api?.get(`/api/treatments/test/${testId}`).catch(() => null);
        if (res?.data?.success) setTreatment(res.data.data.treatment);
      } catch { /* no treatment yet */ }
      finally { setLoading(false); }
    };
    if (testId) load();
  }, [testId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!form.drug) return setError('Please select a drug');
    if (!form.dosage) return setError('Dosage is required');
    if (!form.duration) return setError('Duration is required');
    setSubmitting(true);
    try {
      // use axios directly since api.js doesn't have a treatments namespace yet
      const { api } = await import('../../services/api');
      const res = await api.post('/api/treatments', { testId, ...form });
      setTreatment(res.data.data.treatment);
      setShowForm(false);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to record treatment');
    } finally {
      setSubmitting(false);
    }
  };

  const handleOutcomeSubmit = async (e) => {
    e.preventDefault();
    if (!outcomeForm.outcome) return setError('Select an outcome');
    setSubmitting(true);
    try {
      const { api } = await import('../../services/api');
      const res = await api.patch(`/api/treatments/${treatment._id}/outcome`, outcomeForm);
      setTreatment(res.data.data.treatment);
      setShowOutcome(false);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update outcome');
    } finally {
      setSubmitting(false);
    }
  };

  // Only show for positive diagnoses
  if (!isPositive) return null;

  if (loading) return null;

  const outcomeStyle = treatment ? (OUTCOME_STYLES[treatment.outcome] || OUTCOME_STYLES.pending) : null;

  return (
    <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/15 rounded-lg border border-emerald-500/20">
            <Pill className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm">Treatment & Follow-up</h3>
            <p className="text-white/40 text-xs">Record prescribed treatment and track outcome</p>
          </div>
        </div>
        {!treatment && !showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 text-xs font-medium rounded-lg transition-colors"
          >
            + Record Treatment
          </button>
        )}
      </div>

      <div className="p-5">
        {/* Existing treatment */}
        {treatment && !showForm && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-white/40 text-xs uppercase tracking-wide">Drug</span>
                <p className="text-white font-medium mt-0.5">
                  {treatment.drug === 'Other' ? treatment.drugOther : treatment.drug}
                </p>
              </div>
              <div>
                <span className="text-white/40 text-xs uppercase tracking-wide">Dosage</span>
                <p className="text-white font-medium mt-0.5">{treatment.dosage}</p>
              </div>
              <div>
                <span className="text-white/40 text-xs uppercase tracking-wide">Duration</span>
                <p className="text-white mt-0.5">{treatment.duration}</p>
              </div>
              <div>
                <span className="text-white/40 text-xs uppercase tracking-wide">Route</span>
                <p className="text-white mt-0.5 capitalize">{treatment.route}</p>
              </div>
              {treatment.followUpDate && (
                <div>
                  <span className="text-white/40 text-xs uppercase tracking-wide">Follow-up</span>
                  <p className="text-white mt-0.5 flex items-center gap-1">
                    <Clock className="w-3 h-3 text-blue-400" />
                    {new Date(treatment.followUpDate).toLocaleDateString()}
                  </p>
                </div>
              )}
              <div>
                <span className="text-white/40 text-xs uppercase tracking-wide">Prescribed By</span>
                <p className="text-white mt-0.5 text-xs">
                  {treatment.prescribedBy ? `${treatment.prescribedBy.firstName} ${treatment.prescribedBy.lastName}` : '—'}
                </p>
              </div>
            </div>

            {treatment.notes && (
              <p className="text-white/60 text-xs bg-white/5 rounded-lg p-3">{treatment.notes}</p>
            )}

            {/* Outcome */}
            <div className="border-t border-white/10 pt-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-white/40 text-xs">Outcome:</span>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${outcomeStyle.bg} ${outcomeStyle.color}`}>
                  {outcomeStyle.label}
                </span>
              </div>
              <button
                onClick={() => { setShowOutcome(!showOutcome); setError(null); }}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                <Edit2 className="w-3 h-3" />Update Outcome
              </button>
            </div>

            {treatment.followUpNotes && (
              <p className="text-white/50 text-xs italic">{treatment.followUpNotes}</p>
            )}

            {/* Outcome form */}
            {showOutcome && (
              <form onSubmit={handleOutcomeSubmit} className="space-y-3 bg-white/5 rounded-xl p-4">
                <select
                  value={outcomeForm.outcome}
                  onChange={e => setOutcomeForm(f => ({ ...f, outcome: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400"
                >
                  <option value="">Select outcome…</option>
                  {Object.entries(OUTCOME_STYLES).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
                <textarea
                  placeholder="Follow-up notes (optional)"
                  value={outcomeForm.followUpNotes}
                  onChange={e => setOutcomeForm(f => ({ ...f, followUpNotes: e.target.value }))}
                  rows={2}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400 resize-none"
                />
                {error && <p className="text-rose-400 text-xs">{error}</p>}
                <div className="flex gap-2">
                  <button type="submit" disabled={submitting}
                    className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors">
                    {submitting ? 'Saving…' : 'Save Outcome'}
                  </button>
                  <button type="button" onClick={() => setShowOutcome(false)}
                    className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white text-sm rounded-lg transition-colors">
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </div>
        )}

        {/* New treatment form */}
        {showForm && (
          <form onSubmit={handleSubmit} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <label className="text-xs text-white/50 mb-1 block">Drug *</label>
                <select
                  value={form.drug}
                  onChange={e => setForm(f => ({ ...f, drug: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400"
                >
                  <option value="">Select drug…</option>
                  {DRUGS.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
              {form.drug === 'Other' && (
                <div className="col-span-2">
                  <input
                    placeholder="Specify drug name"
                    value={form.drugOther}
                    onChange={e => setForm(f => ({ ...f, drugOther: e.target.value }))}
                    className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
                  />
                </div>
              )}
              <div>
                <label className="text-xs text-white/50 mb-1 block">Dosage *</label>
                <input
                  placeholder="e.g. 80/480mg twice daily"
                  value={form.dosage}
                  onChange={e => setForm(f => ({ ...f, dosage: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
                />
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Duration *</label>
                <input
                  placeholder="e.g. 3 days"
                  value={form.duration}
                  onChange={e => setForm(f => ({ ...f, duration: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
                />
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Route</label>
                <select
                  value={form.route}
                  onChange={e => setForm(f => ({ ...f, route: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400"
                >
                  <option value="oral">Oral</option>
                  <option value="iv">IV</option>
                  <option value="im">IM</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Follow-up Date</label>
                <input
                  type="date"
                  value={form.followUpDate}
                  onChange={e => setForm(f => ({ ...f, followUpDate: e.target.value }))}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400"
                />
              </div>
              <div className="col-span-2">
                <label className="text-xs text-white/50 mb-1 block">Notes</label>
                <textarea
                  placeholder="Additional notes…"
                  value={form.notes}
                  onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                  rows={2}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-400 resize-none"
                />
              </div>
            </div>

            {error && <p className="text-rose-400 text-xs">{error}</p>}

            <div className="flex gap-2 pt-1">
              <button type="submit" disabled={submitting}
                className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors">
                {submitting ? 'Saving…' : 'Record Treatment'}
              </button>
              <button type="button" onClick={() => { setShowForm(false); setError(null); }}
                className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white text-sm rounded-lg transition-colors">
                Cancel
              </button>
            </div>
          </form>
        )}

        {/* Empty state */}
        {!treatment && !showForm && (
          <div className="text-center py-4">
            <Pill className="w-8 h-8 text-white/20 mx-auto mb-2" />
            <p className="text-white/30 text-sm">No treatment recorded yet</p>
          </div>
        )}
      </div>
    </div>
  );
}

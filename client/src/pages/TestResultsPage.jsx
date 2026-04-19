import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Download, Printer, ArrowLeft, User, TestTube, Calendar,
  RefreshCw, XCircle, Activity, AlertTriangle, Percent,
  CheckCircle, Microscope, Droplets, ImageIcon, TrendingUp,
  Zap, Brain, ShieldCheck
} from 'lucide-react';

import ImageAnnotation from '../components/results/ImageAnnotation';
import ConfirmationPanel from '../components/results/ConfirmationPanel';
import TreatmentPanel from '../components/results/TreatmentPanel';
import { PageLoader } from '../components/common/LoadingSpinner';
import diagnosisService from '../services/diagnosisService';

// ── helpers ──────────────────────────────────────────────────────────────────
const PARASITE_NAMES = {
  PF: 'Plasmodium Falciparum',
  PM: 'Plasmodium Malariae',
  PO: 'Plasmodium Ovale',
  PV: 'Plasmodium Vivax',
};
const fmtDate = (d) => d ? new Date(d).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : 'N/A';
const fmtTime = (d) => d ? new Date(d).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '';

// ── sub-components ────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, color = 'blue', sub }) {
  const colors = {
    rose:   'bg-rose-500/10 border-rose-500/20 text-rose-300',
    blue:   'bg-blue-500/10 border-blue-500/20 text-blue-300',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-300',
    amber:  'bg-amber-500/10 border-amber-500/20 text-amber-300',
    green:  'bg-green-500/10 border-green-500/20 text-green-300',
  };
  return (
    <div className={`rounded-xl border p-4 ${colors[color]}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium opacity-70 uppercase tracking-wide">{label}</span>
        <Icon className="w-4 h-4 opacity-60" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {sub && <div className="text-xs opacity-60 mt-0.5">{sub}</div>}
    </div>
  );
}

function InfoRow({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
      <span className="text-sm text-blue-300/70">{label}</span>
      <span className={`text-sm text-white font-medium ${mono ? 'font-mono bg-white/10 px-2 py-0.5 rounded text-xs' : ''}`}>
        {value || 'N/A'}
      </span>
    </div>
  );
}

// ── page ──────────────────────────────────────────────────────────────────────
const TestResultsPage = () => {
  const { testId } = useParams();
  const navigate = useNavigate();

  const [testResult, setTestResult] = useState(null);
  const [images, setImages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [dataFound, setDataFound] = useState(true);

  useEffect(() => {
    const load = async () => {
      if (!testId) { setError('Test ID is required'); setLoading(false); return; }
      try {
        setLoading(true);
        const res = await diagnosisService.getByTestId(testId);
        if (!res.success || !res.data?.result) { setDataFound(false); setLoading(false); return; }

        const r = res.data.result;
        // normalise confidence to 0-100
        if (r.mostProbableParasite?.confidence !== undefined) {
          r.confidence = r.mostProbableParasite.confidence > 1
            ? r.mostProbableParasite.confidence
            : r.mostProbableParasite.confidence * 100;
          if (r.mostProbableParasite.confidence <= 1)
            r.mostProbableParasite.confidence = r.mostProbableParasite.confidence * 100;
        } else if (r.confidence !== undefined && r.confidence <= 1) {
          r.confidence = r.confidence * 100;
        }
        setTestResult(r);

        try {
          const imgRes = await diagnosisService.getImages(testId);
          if (imgRes.success && imgRes.data?.images) setImages(imgRes.data.images);
        } catch { setImages([]); }

      } catch (e) {
        setError(e.message || 'Failed to load test result');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [testId]);

  const handleConfirmed = (rev) => {
    setTestResult(prev => ({
      ...prev,
      manualReview: {
        isReviewed:          true,
        signedByName:        rev.reviewedBy,
        reviewedAt:          rev.reviewedAt,
        verificationCode:    rev.verificationCode,
        reviewNotes:         rev.reviewNotes,
        reviewerConfidence:  rev.reviewerConfidence,
        overriddenStatus:    rev.finalStatus !== prev.status ? rev.finalStatus : undefined,
        detectionsEdited:    rev.detectionsEdited,
        parasiteCountReviewed:               rev.parasiteCountReviewed,
        wbcCountReviewed:                    rev.wbcCountReviewed,
        parasiteWbcRatioReviewed:            rev.parasiteWbcRatioReviewed,
        parasiteDensityPerUlReviewed:        rev.parasiteDensityPerUlReviewed,
        parasiteDensityIsPreliminaryReviewed: rev.parasiteDensityIsPreliminaryReviewed,
        parasiteDensityFlagReviewed:         rev.parasiteDensityFlagReviewed,
        parasiteDensityNoteReviewed:         rev.parasiteDensityNoteReviewed,
      }
    }));

    // Attach reviewed image URLs alongside the original AI-annotated ones (keep both)
    if (rev.detectionsEdited && rev.reviewedImages?.length > 0) {
      setImages(prev => prev.map(img => {
        const reviewed = rev.reviewedImages.find(r => r.imageId === img.imageId);
        if (!reviewed) return img;
        return { ...img, reviewedImageUrl: reviewed.reviewedImageUrl };
      }));
    }
  };

  const handleExport = async () => {
    try {
      setExporting(true);
      const blob = await diagnosisService.exportReport(testId, 'pdf');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `malaria-report-${testId}.pdf`;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a); URL.revokeObjectURL(url);
    } catch { alert('Export failed. Please try again.'); }
    finally { setExporting(false); }
  };

  // ── loading / error / no-data states ─────────────────────────────────────
  if (loading) return <PageLoader text="Loading test results..." />;

  if (error) return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center">
      <div className="text-center bg-white/10 backdrop-blur-md border border-white/20 rounded-2xl p-10 max-w-md">
        <XCircle className="w-14 h-14 text-rose-400 mx-auto mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Could not load results</h2>
        <p className="text-blue-200 mb-6 text-sm">{error}</p>
        <div className="flex gap-3 justify-center">
          <button onClick={() => navigate('/results')} className="px-5 py-2 bg-white text-blue-700 rounded-lg font-medium hover:bg-blue-50 transition-colors">Back</button>
          <button onClick={() => window.location.reload()} className="px-5 py-2 bg-white/10 border border-white/20 text-white rounded-lg hover:bg-white/20 transition-colors flex items-center gap-2"><RefreshCw className="w-4 h-4" />Retry</button>
        </div>
      </div>
    </div>
  );

  if (!dataFound || !testResult) return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center">
      <div className="text-center bg-white/10 backdrop-blur-md border border-white/20 rounded-2xl p-10 max-w-md">
        <div className="relative inline-block mb-4">
          <TestTube className="w-14 h-14 text-blue-400" />
          <Activity className="w-5 h-5 text-yellow-400 absolute -bottom-1 -right-1 animate-pulse" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Results Not Ready</h2>
        <p className="text-blue-200 text-sm mb-6">No result found for <span className="font-mono bg-white/10 px-2 py-0.5 rounded">{testId}</span>. Analysis may still be in progress.</p>
        <div className="flex gap-3 justify-center">
          <button onClick={() => navigate('/results')} className="px-5 py-2 bg-white text-blue-700 rounded-lg font-medium hover:bg-blue-50 transition-colors">Back</button>
          <button onClick={() => window.location.reload()} className="px-5 py-2 bg-white/10 border border-white/20 text-white rounded-lg hover:bg-white/20 transition-colors flex items-center gap-2"><RefreshCw className="w-4 h-4" />Refresh</button>
        </div>
      </div>
    </div>
  );

  // ── derived state ─────────────────────────────────────────────────────────
  const patient    = testResult.test?.patient;
  const technician = testResult.test?.technician;
  const rev        = testResult.manualReview;
  const reviewed   = rev?.isReviewed;

  const isInvalid  = testResult.status === 'INVALID_SAMPLE';
  const isSuspect  = testResult.status === 'SUSPICIOUS';
  const isPositive = !isInvalid && !isSuspect &&
                     (testResult.status === 'POSITIVE' || testResult.status === 'POS' || testResult.totalParasites > 0);
  const isNegative = !isInvalid && !isSuspect && !isPositive;

  const finalSeverity = rev?.overriddenSeverity || testResult.severity?.level;
  const parasite      = testResult.mostProbableParasite;
  const confidence    = testResult.confidence || 0;

  const parasiteCount = testResult.totalParasites ?? 0;
  const wbcCount      = testResult.totalWbcs ?? 0;
  const imageCount    = testResult.totalImagesAttempted || images.length || 0;
  const ratio         = testResult.parasiteWbcRatio ?? 0;
  // WHO MM-SOP-09 parasitaemia in p/µL — computed by the backend pre-save hook.
  const parasitemia              = testResult.parasitemia ?? 0;
  const parasitemiaFlag          = testResult.parasitemiaFlag ?? null;
  const parasitemiaIsPreliminary = testResult.parasitemiaIsPreliminary ?? false;
  const parasitemiaNote          = testResult.parasitemiaNote ?? null;

  // Status theme
  const theme = isPositive
    ? { bg: 'from-rose-600 to-rose-800',     badge: 'bg-rose-500/20 border-rose-400/40 text-rose-200',   icon: XCircle,     label: 'POSITIVE', dot: 'bg-rose-400' }
    : isNegative
    ? { bg: 'from-emerald-700 to-teal-800',  badge: 'bg-emerald-500/20 border-emerald-400/40 text-emerald-200', icon: CheckCircle, label: 'NEGATIVE', dot: 'bg-emerald-400' }
    : isSuspect
    ? { bg: 'from-orange-600 to-amber-800',  badge: 'bg-orange-500/20 border-orange-400/40 text-orange-200',   icon: AlertTriangle, label: 'SUSPICIOUS', dot: 'bg-orange-400' }
    : { bg: 'from-amber-600 to-orange-800',  badge: 'bg-amber-500/20 border-amber-400/40 text-amber-200',      icon: AlertTriangle, label: 'INVALID', dot: 'bg-amber-400' };

  const StatusIcon = theme.icon;

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900">

      {/* ── Top action bar ─────────────────────────────────────────────── */}
      <div className="sticky top-0 z-20 bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <button
            onClick={() => navigate('/results')}
            className="flex items-center gap-2 text-sm text-blue-300 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />Back to Results
          </button>

          <span className="font-mono text-xs text-white/40 hidden sm:block">{testId}</span>

          <div className="flex gap-2">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="flex items-center gap-2 px-4 py-1.5 bg-white text-slate-800 rounded-lg text-sm font-semibold hover:bg-blue-50 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              {exporting ? 'Exporting…' : 'Export PDF'}
            </button>
            <button
              onClick={() => window.print()}
              className="flex items-center gap-2 px-3 py-1.5 bg-white/10 border border-white/20 text-white rounded-lg text-sm hover:bg-white/20 transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

        {/* ── Result hero banner ─────────────────────────────────────────── */}
        <div className={`relative rounded-2xl bg-gradient-to-r ${theme.bg} overflow-hidden shadow-2xl`}>
          {/* subtle texture */}
          <div className="absolute inset-0 bg-gradient-to-b from-black/10 to-black/30" />
          <div className="absolute top-0 right-0 w-64 h-64 bg-white/5 rounded-full -translate-y-1/2 translate-x-1/2" />

          <div className="relative px-6 py-6 sm:px-8 sm:py-7">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">

              {/* Status side */}
              <div className="flex items-center gap-5">
                <div className="w-16 h-16 rounded-2xl bg-white/20 backdrop-blur-sm flex items-center justify-center border border-white/30 shrink-0">
                  <StatusIcon className="w-8 h-8 text-white" />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-bold border ${theme.badge}`}>
                      <span className={`w-2 h-2 rounded-full ${theme.dot} animate-pulse`} />
                      {theme.label}
                    </span>
                    {reviewed && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-white/20 text-white text-xs font-medium border border-white/30">
                        <ShieldCheck className="w-3 h-3" />Clinically Reviewed
                      </span>
                    )}
                  </div>
                  {isPositive && parasite && (
                    <p className="text-white text-lg font-semibold">
                      {PARASITE_NAMES[parasite.type] || parasite.type}
                    </p>
                  )}
                  {isPositive && parasite && (
                    <p className="text-white/70 text-sm">
                      {parasite.confidence?.toFixed(1)}% AI confidence
                      {finalSeverity && finalSeverity !== 'negative' && (
                        <span className="ml-3 font-medium text-white/90">· {testResult.severity?.note || `${finalSeverity} severity`}</span>
                      )}
                    </p>
                  )}
                  {isNegative && (
                    <p className="text-white text-lg font-semibold">No malaria parasites detected</p>
                  )}
                  {isSuspect && (
                    <p className="text-white text-sm mt-1 max-w-md">
                      Parasites detected but no WBCs found — images may not be valid blood smears
                    </p>
                  )}
                  {isInvalid && (
                    <p className="text-white text-sm mt-1">Uploaded images were not recognised as blood smear slides</p>
                  )}
                </div>
              </div>

              {/* Patient / test quick info */}
              <div className="sm:text-right text-sm space-y-1 shrink-0">
                {patient && (
                  <p className="text-white font-semibold text-base">
                    {patient.firstName} {patient.lastName}
                  </p>
                )}
                {patient && (
                  <p className="text-white/70">{patient.patientId} · {patient.age} yrs · <span className="capitalize">{patient.gender}</span></p>
                )}
                <p className="text-white/60 flex items-center gap-1 sm:justify-end">
                  <Calendar className="w-3 h-3" />
                  {fmtDate(testResult.createdAt)}
                  <span className="opacity-60 ml-1">{fmtTime(testResult.createdAt)}</span>
                </p>
                {technician && (
                  <p className="text-white/60 text-xs">
                    Technician: {technician.firstName} {technician.lastName}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ── Main grid ─────────────────────────────────────────────────── */}
        <div className="grid lg:grid-cols-3 gap-6">

          {/* ── Left column: stats + info ─────────────────────────────── */}
          <div className="space-y-5">

            {/* Metric cards */}
            <div className="grid grid-cols-2 gap-3">
              <StatCard icon={Microscope}  label="Parasites"   value={parasiteCount} color={isPositive && parasiteCount > 0 ? 'rose' : 'green'} />
              <StatCard icon={Droplets}    label="WBCs"        value={wbcCount}       color="blue" />
              <StatCard icon={ImageIcon}   label="Images"      value={imageCount}     color="purple" />
              <StatCard
                icon={TrendingUp}
                label="P/WBC Ratio"
                value={ratio.toFixed(2)}
                color={ratio >= 5 ? 'rose' : ratio >= 1 ? 'amber' : 'green'}
                sub={ratio >= 5 ? 'High density' : ratio >= 1 ? 'Low density' : 'Normal'}
              />
              <StatCard
                icon={Percent}
                label="Parasitemia"
                value={parasitemia > 0
                  ? `${Math.round(parasitemia).toLocaleString()} p/µL`
                  : (isPositive ? '—' : 'Neg.')}
                color={parasitemia >= 10000 ? 'rose' : parasitemia >= 1000 ? 'amber' : parasitemia > 0 ? 'green' : 'blue'}
                sub={parasitemiaIsPreliminary ? 'Unconfirmed estimate' : parasitemia > 0 ? 'WHO confirmed' : null}
              />
            </div>

            {/* Preliminary parasitemia flag warning */}
            {parasitemiaIsPreliminary && parasitemiaNote && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-amber-200 leading-relaxed">{parasitemiaNote}</p>
                </div>
              </div>
            )}

            {/* AI confidence bar */}
            <div className="bg-white/5 border border-white/10 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-blue-300 flex items-center gap-2">
                  <Brain className="w-4 h-4" />AI Confidence
                </span>
                <span className="text-white font-bold text-sm">{confidence.toFixed(1)}%</span>
              </div>
              <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-1000 ${
                    confidence >= 80 ? 'bg-gradient-to-r from-emerald-400 to-green-500' :
                    confidence >= 60 ? 'bg-gradient-to-r from-amber-400 to-yellow-500' :
                                       'bg-gradient-to-r from-rose-400 to-red-500'
                  }`}
                  style={{ width: `${Math.min(100, confidence)}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-white/30 mt-1">
                <span>Low</span><span>Medium</span><span>High</span>
              </div>
            </div>

            {/* Inference timing (only if present) */}
            {testResult.timing?.total_ms > 0 && (
              <div className="bg-white/5 border border-white/10 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-medium text-blue-300">Inference Timing</span>
                  <span className="ml-auto text-xs text-white/40 bg-white/10 px-2 py-0.5 rounded-full">
                    {testResult.modelType || 'ONNX'}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  {[
                    ['Preprocess',  testResult.timing.totalPreprocess_ms],
                    ['Inference',   testResult.timing.totalInference_ms],
                    ['Postprocess', testResult.timing.totalPostprocess_ms],
                  ].filter(([, ms]) => ms > 0).map(([label, ms]) => (
                    <div key={label} className="flex justify-between text-white/60">
                      <span>{label}</span>
                      <span>{`${ms.toFixed(0)} ms`}</span>
                    </div>
                  ))}
                  <div className="flex justify-between text-white font-semibold pt-1.5 border-t border-white/10">
                    <span>Total</span>
                    <span className="text-cyan-300">
                      {testResult.timing.total_ms >= 1000
                        ? `${(testResult.timing.total_ms / 1000).toFixed(2)} s`
                        : `${testResult.timing.total_ms.toFixed(0)} ms`}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Patient & test details */}
            <div className="bg-white/5 border border-white/10 rounded-xl p-4">
              {patient && (
                <>
                  <div className="flex items-center gap-2 mb-2">
                    <User className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-semibold text-white">Patient</span>
                  </div>
                  <div className="mb-3">
                    <InfoRow label="Name"      value={`${patient.firstName} ${patient.lastName}`} />
                    <InfoRow label="Patient ID" value={patient.patientId} mono />
                    <InfoRow label="Age"        value={`${patient.age} years`} />
                    <InfoRow label="Gender"     value={patient.gender} />
                    {patient.phoneNumber && <InfoRow label="Phone" value={patient.phoneNumber} />}
                    {patient.bloodType && <InfoRow label="Blood Type" value={patient.bloodType} />}
                  </div>
                  <div className="border-t border-white/10 pt-3 mt-1" />
                </>
              )}

              <div className="flex items-center gap-2 mb-2">
                <TestTube className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-semibold text-white">Test</span>
              </div>
              <InfoRow label="Test ID"     value={testId} mono />
              <InfoRow label="Date"        value={fmtDate(testResult.createdAt)} />
              <InfoRow label="Time"        value={fmtTime(testResult.createdAt)} />
              <InfoRow label="Sample Type" value={testResult.test?.sampleType || 'Blood Smear'} />
              <InfoRow label="Priority"    value={testResult.test?.priority || 'Normal'} />
              {technician && <InfoRow label="Technician" value={`${technician.firstName} ${technician.lastName}`} />}
              {testResult.apiResponse?.processingTime && (
                <InfoRow label="Processing" value={`${testResult.apiResponse.processingTime}s`} />
              )}
            </div>

          </div>

          {/* ── Right column: sign-off + images ──────────────────────── */}
          <div className="lg:col-span-2 space-y-6">

            {/* Clinical sign-off — passes images so the clinician can edit detections inline */}
            <ConfirmationPanel
              testId={testId}
              diagnosisResult={testResult}
              images={images}
              onConfirmed={handleConfirmed}
            />

            {/* Treatment & follow-up (positive cases only) */}
            <TreatmentPanel testId={testId} diagnosisResult={testResult} />

            {/* Annotated image viewer */}
            {images.length > 0 ? (
              <ImageAnnotation images={images} resultId={testResult._id} testId={testId} />
            ) : (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-10 text-center">
                <ImageIcon className="w-10 h-10 text-white/20 mx-auto mb-3" />
                <p className="text-white/40 text-sm">No annotated images available</p>
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};

export default TestResultsPage;

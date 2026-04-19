// src/components/results/ConfirmationPanel.jsx
import React, { useState, useCallback } from 'react';
import {
  CheckCircle, AlertTriangle, XCircle, Shield, Eye, EyeOff,
  ChevronDown, Lock, FileCheck, Edit3, ChevronUp, Target, Activity,
  AlertCircle, Plus,
} from 'lucide-react';
import diagnosisService from '../../services/diagnosisService';
import ReviewCanvas from './ReviewCanvas';

const CLASS_COLORS = { PF: '#ff3232', PM: '#ff8c00', PO: '#00dcdc', PV: '#6464ff', WBC: '#32c832' };

// Scrollable list of detections with flag / relabel summary
const DetectionList = ({ parasites, wbcs }) => {
  const flaggedP = parasites.filter(p => p.flagged);
  const flaggedW = wbcs.filter(w => w.flagged);
  const keptP    = parasites.filter(p => !p.flagged);
  const keptW    = wbcs.filter(w => !w.flagged);

  const Row = ({ label, color, flagged, source }) => (
    <div className={`flex items-center justify-between px-2 py-1 rounded text-xs ${flagged ? 'opacity-40 line-through' : ''}`}>
      <span className="font-mono" style={{ color }}>{label}</span>
      <div className="flex gap-1">
        {source === 'clinician' && <span className="px-1 py-0.5 rounded bg-yellow-500/20 text-yellow-300 text-[10px]">Added</span>}
        {flagged && <span className="px-1 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px]">FP</span>}
      </div>
    </div>
  );

  return (
    <div className="space-y-2 text-xs">
      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="p-2 bg-rose-500/10 border border-rose-500/20 rounded-lg">
          <div className="text-lg font-bold text-rose-400">{keptP.length}</div>
          <div className="text-rose-300">Parasites</div>
        </div>
        <div className="p-2 bg-green-500/10 border border-green-500/20 rounded-lg">
          <div className="text-lg font-bold text-green-400">{keptW.length}</div>
          <div className="text-green-300">WBCs</div>
        </div>
        <div className="p-2 bg-amber-500/10 border border-amber-500/20 rounded-lg">
          <div className="text-lg font-bold text-amber-400">{flaggedP.length + flaggedW.length}</div>
          <div className="text-amber-300">Flagged</div>
        </div>
      </div>
      <div className="max-h-40 overflow-y-auto space-y-0.5 pr-1">
        {parasites.map(p => (
          <Row key={`p-${p.parasiteId}`}
            label={`#${p.parasiteId} ${p.type} ${(p.confidence * 100).toFixed(0)}%`}
            color={CLASS_COLORS[p.type]}
            flagged={p.flagged}
            source={p.source} />
        ))}
        {wbcs.map(w => (
          <Row key={`w-${w.wbcId}`}
            label={`W${w.wbcId} WBC ${(w.confidence * 100).toFixed(0)}%`}
            color={CLASS_COLORS.WBC}
            flagged={w.flagged}
            source={w.source} />
        ))}
      </div>
    </div>
  );
};

const ConfirmationPanel = ({ testId, diagnosisResult, images = [], onConfirmed }) => {
  const reviewed = diagnosisResult?.manualReview?.isReviewed;

  const [decision, setDecision]       = useState('confirm');
  const [severity, setSeverity]       = useState('');
  const [notes, setNotes]             = useState('');
  const [confidence, setConfidence]   = useState('medium');
  const [password, setPassword]       = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting]   = useState(false);
  const [error, setError]             = useState(null);

  // Detection editing state
  const [editMode, setEditMode]       = useState(false);
  const [selectedImageIdx, setSelectedImageIdx] = useState(0);
  const [detectionEdits, setDetectionEdits] = useState({}); // keyed by imageId

  const aiStatus = diagnosisResult?.status;
  const currentImage = images[selectedImageIdx] || null;

  const handleDetectionsChange = useCallback((imageId, edits) => {
    setDetectionEdits(prev => ({ ...prev, [imageId]: edits }));
  }, []);

  // Stable callback keyed by imageId — avoids creating a new function reference
  // on every render, which would re-trigger ReviewCanvas's onDetectionsChange effect.
  const currentImageId = currentImage?.imageId;
  const stableOnDetectionsChange = useCallback(
    (edits) => handleDetectionsChange(currentImageId, edits),
    [currentImageId, handleDetectionsChange]
  );

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (!notes.trim()) { setError('Clinical notes are required before signing off.'); return; }
    if (!password)     { setError('Password is required to sign off.'); return; }

    const overriddenStatus =
      decision === 'override_positive' ? 'POSITIVE' :
      decision === 'override_negative' ? 'NEGATIVE' :
      undefined;

    // Merge detection edits across all images
    const hasEdits = Object.keys(detectionEdits).length > 0;
    let reviewedDetections = [], reviewedWbcs = [], flaggedParasiteIds = [], flaggedWbcIds = [], imagePaths = [];

    if (hasEdits) {
      images.forEach(img => {
        const edits = detectionEdits[img.imageId];
        if (!edits) return;
        // Tag each detection with its imageId for the Flask renderer
        const tag = d => ({ ...d, imageId: img.imageId });
        reviewedDetections.push(...(edits.reviewedDetections || []).map(tag));
        reviewedWbcs.push(      ...(edits.reviewedWbcs       || []).map(tag));
        flaggedParasiteIds.push(...(edits.flaggedParasiteIds  || []));
        flaggedWbcIds.push(      ...(edits.flaggedWbcIds      || []));
        if (img.originalUrl) {
          // Convert browser URL back to server path — the original upload path
          imagePaths.push({ imageId: img.imageId, originalPath: img._originalPath || img.originalUrl });
        }
      });
    }

    try {
      setSubmitting(true);
      const payload = {
        reviewNotes:        notes,
        overriddenStatus,
        overriddenSeverity: severity || undefined,
        reviewerConfidence: confidence,
        password,
        ...(hasEdits && { reviewedDetections, reviewedWbcs, flaggedParasiteIds, flaggedWbcIds, imagePaths }),
      };

      const response = await diagnosisService.addManualReview(testId, payload);

      if (response.success) {
        onConfirmed(response.data.result);
      } else {
        setError(response.message || 'Sign-off failed. Please try again.');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Sign-off failed. Please check your password.');
    } finally {
      setSubmitting(false);
    }
  };

  // ── Already reviewed ──────────────────────────────────────────────────────
  if (reviewed) {
    const rev = diagnosisResult.manualReview;
    const finalStatus = rev.overriddenStatus || diagnosisResult.status;
    return (
      <div className="bg-gradient-to-br from-green-500/15 via-green-500/10 to-green-600/5 border border-green-500/40 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex items-center mb-4">
          <div className="p-2 bg-green-500/20 rounded-lg mr-3 border border-green-500/30">
            <FileCheck className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-green-300">Clinically Reviewed &amp; Signed Off</h3>
            {rev.detectionsEdited && (
              <span className="text-xs text-yellow-300 flex items-center gap-1 mt-0.5">
                <Edit3 className="w-3 h-3" /> Detection-level edits applied
              </span>
            )}
          </div>
        </div>

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-green-200">Reviewed by:</span>
            <span className="text-white font-medium">{rev.signedByName || 'N/A'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-green-200">Date:</span>
            <span className="text-white">{rev.reviewedAt ? new Date(rev.reviewedAt).toLocaleString() : 'N/A'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-green-200">Final Result:</span>
            <span className={`font-bold ${finalStatus === 'POSITIVE' ? 'text-rose-300' : 'text-green-300'}`}>{finalStatus}</span>
          </div>
          {rev.overriddenSeverity && (
            <div className="flex justify-between">
              <span className="text-green-200">Severity:</span>
              <span className="text-white capitalize">{rev.overriddenSeverity}</span>
            </div>
          )}
          <div className="flex justify-between">
            <span className="text-green-200">Confidence:</span>
            <span className="text-white capitalize">{rev.reviewerConfidence}</span>
          </div>
          {rev.detectionsEdited && (
            <>
              <div className="border-t border-green-500/20 pt-2 mt-2" />
              <p className="text-green-200 text-xs font-medium">Reviewed Counts</p>
              <div className="flex justify-between text-xs">
                <span className="text-green-200">Parasites (reviewed):</span>
                <span className="text-white">{rev.parasiteCountReviewed ?? '—'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-green-200">WBCs (reviewed):</span>
                <span className="text-white">{rev.wbcCountReviewed ?? '—'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-green-200">Density (reviewed):</span>
                <span className="text-white">
                  {rev.parasiteDensityPerUlReviewed != null ? `${rev.parasiteDensityPerUlReviewed.toLocaleString()} p/µL` : '—'}
                  {rev.parasiteDensityIsPreliminaryReviewed && <span className="text-amber-300 ml-1">[{rev.parasiteDensityFlagReviewed}]</span>}
                </span>
              </div>
            </>
          )}
        </div>

        {rev.reviewNotes && (
          <div className="mt-4 p-3 bg-white/10 rounded-lg border border-white/20">
            <p className="text-green-200 text-xs font-medium mb-1">Clinical Notes:</p>
            <p className="text-white text-sm">{rev.reviewNotes}</p>
          </div>
        )}
        {rev.verificationCode && (
          <div className="mt-4 flex items-center space-x-2 bg-white/5 rounded-lg p-2 border border-white/10">
            <Shield className="w-4 h-4 text-green-400 shrink-0" />
            <div>
              <p className="text-green-200 text-xs">Verification Code</p>
              <p className="text-white text-xs font-mono">{rev.verificationCode}</p>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ── Sign-off form ─────────────────────────────────────────────────────────
  return (
    <div className="bg-gradient-to-br from-white/15 via-white/10 to-white/5 border border-white/30 rounded-2xl p-6 backdrop-blur-xl space-y-5">

      {/* Header */}
      <div className="flex items-center">
        <div className="p-2 bg-blue-500/20 rounded-lg mr-3 border border-blue-500/30">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h3 className="text-lg font-bold text-white">Clinical Sign-off</h3>
          <p className="text-blue-200 text-xs">Review the AI suggestion, edit detections if needed, then confirm</p>
        </div>
      </div>

      {/* Notice */}
      <div className="flex items-start space-x-2 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
        <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
        <p className="text-amber-200 text-xs">
          This system is a <strong>decision support tool</strong>. Review the AI result and annotated images below,
          correct any false positives or missed detections, then sign off.
        </p>
      </div>

      {/* AI suggestion */}
      <div className="p-3 bg-white/5 border border-white/20 rounded-lg">
        <p className="text-blue-200 text-xs font-medium mb-2">AI Suggestion</p>
        <div className="flex items-center justify-between">
          <span className={`text-sm font-bold px-3 py-1 rounded-full border ${
            aiStatus === 'POSITIVE'   ? 'text-rose-200 bg-rose-500/20 border-rose-500/30' :
            aiStatus === 'SUSPICIOUS' ? 'text-orange-200 bg-orange-500/20 border-orange-500/30' :
                                        'text-green-300 bg-green-500/20 border-green-500/30'
          }`}>{aiStatus}</span>
          {diagnosisResult?.mostProbableParasite && (
            <span className="text-white text-xs">
              {diagnosisResult.mostProbableParasite.fullName || diagnosisResult.mostProbableParasite.type}
              {' — '}
              {((diagnosisResult.mostProbableParasite.confidence <= 1
                ? diagnosisResult.mostProbableParasite.confidence * 100
                : diagnosisResult.mostProbableParasite.confidence
              ).toFixed(1))}% confidence
            </span>
          )}
        </div>
      </div>

      {/* ── Detection editing section ── */}
      <div className="border border-white/20 rounded-xl overflow-hidden">
        <button
          type="button"
          onClick={() => setEditMode(v => !v)}
          className="w-full flex items-center justify-between px-4 py-3 bg-white/5 hover:bg-white/10 transition-colors text-left"
        >
          <div className="flex items-center gap-2">
            <Edit3 className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-medium text-white">Edit Detections</span>
            <span className="text-xs text-blue-300">
              — flag false positives, relabel species, add missed parasites/WBCs
            </span>
          </div>
          <div className="flex items-center gap-2">
            {Object.keys(detectionEdits).length > 0 && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">
                Edited
              </span>
            )}
            {editMode ? <ChevronUp className="w-4 h-4 text-blue-300" /> : <ChevronDown className="w-4 h-4 text-blue-300" />}
          </div>
        </button>

        {editMode && (
          <div className="p-4 space-y-4 border-t border-white/10">
            {/* Image tabs (if multiple images) */}
            {images.length > 1 && (
              <div className="flex gap-1 overflow-x-auto pb-1">
                {images.map((img, i) => (
                  <button key={img.imageId || i}
                    onClick={() => setSelectedImageIdx(i)}
                    className={`flex-shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedImageIdx === i
                        ? 'bg-blue-600/40 border-blue-400/60 text-white'
                        : 'bg-white/5 border-white/10 text-blue-200 hover:bg-white/10'
                    }`}>
                    Image {i + 1}
                    {detectionEdits[img.imageId] && <span className="ml-1 text-yellow-400">•</span>}
                  </button>
                ))}
              </div>
            )}

            {/* Canvas for the selected image */}
            {currentImage ? (
              <>
                <ReviewCanvas
                  image={currentImage}
                  onDetectionsChange={stableOnDetectionsChange}
                />
                {/* Detection list summary */}
                {detectionEdits[currentImage.imageId] && (
                  <DetectionList
                    parasites={detectionEdits[currentImage.imageId].reviewedDetections || []}
                    wbcs={detectionEdits[currentImage.imageId].reviewedWbcs || []}
                  />
                )}
              </>
            ) : (
              <p className="text-blue-300 text-xs text-center py-6">No images available to edit.</p>
            )}

            <p className="text-blue-300/70 text-xs">
              Changes are applied on sign-off. The system will re-render the annotated image and
              recompute parasitemia from your reviewed detection list.
            </p>
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Decision */}
        <div>
          <label className="block text-blue-200 text-xs font-medium mb-2">Your Clinical Decision *</label>
          <div className="grid grid-cols-1 gap-2">
            {[
              { value: 'confirm',           label: 'Confirm AI Result',   icon: CheckCircle, color: 'blue' },
              { value: 'override_positive', label: 'Override → POSITIVE', icon: XCircle,     color: 'rose' },
              { value: 'override_negative', label: 'Override → NEGATIVE', icon: CheckCircle, color: 'green' },
            ].map(({ value, label, icon: Icon, color }) => (
              <label key={value}
                className={`flex items-center space-x-3 p-3 rounded-lg border cursor-pointer transition-all ${
                  decision === value
                    ? `bg-${color}-500/20 border-${color}-500/40`
                    : 'bg-white/5 border-white/10 hover:bg-white/10'
                }`}>
                <input type="radio" name="decision" value={value}
                  checked={decision === value}
                  onChange={() => setDecision(value)}
                  className="sr-only" />
                <Icon className={`w-4 h-4 ${decision === value ? `text-${color}-400` : 'text-gray-400'}`} />
                <span className={`text-sm ${decision === value ? 'text-white font-medium' : 'text-blue-200'}`}>{label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Severity */}
        {(decision === 'confirm' && aiStatus === 'POSITIVE') || decision === 'override_positive' ? (
          <div>
            <label className="block text-blue-200 text-xs font-medium mb-1">Severity Assessment</label>
            <div className="relative">
              <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="w-full bg-white/10 border border-white/20 text-white rounded-lg px-3 py-2 text-sm appearance-none focus:outline-none focus:border-blue-400">
                <option value="" className="bg-gray-800">— Select severity —</option>
                <option value="mild"     className="bg-gray-800">Mild</option>
                <option value="moderate" className="bg-gray-800">Moderate</option>
                <option value="severe"   className="bg-gray-800">Severe</option>
              </select>
              <ChevronDown className="w-4 h-4 text-blue-300 absolute right-3 top-2.5 pointer-events-none" />
            </div>
          </div>
        ) : null}

        {/* Confidence */}
        <div>
          <label className="block text-blue-200 text-xs font-medium mb-1">Your Confidence Level *</label>
          <div className="flex space-x-2">
            {['low', 'medium', 'high'].map(level => (
              <button key={level} type="button" onClick={() => setConfidence(level)}
                className={`flex-1 py-2 rounded-lg text-xs font-medium border transition-all capitalize ${
                  confidence === level
                    ? 'bg-blue-500/30 border-blue-400/60 text-white'
                    : 'bg-white/5 border-white/10 text-blue-200 hover:bg-white/10'
                }`}>{level}</button>
            ))}
          </div>
        </div>

        {/* Clinical notes */}
        <div>
          <label className="block text-blue-200 text-xs font-medium mb-1">Clinical Notes *</label>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={3}
            placeholder="Document your clinical observations, reasoning, and any relevant patient context..."
            className="w-full bg-white/10 border border-white/20 text-white placeholder-blue-300/50 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400 resize-none" />
        </div>

        {/* Password */}
        <div>
          <label className="block text-blue-200 text-xs font-medium mb-1">
            <Lock className="w-3 h-3 inline mr-1" />Your Login Password *
          </label>
          <p className="text-blue-300/70 text-xs mb-1">Re-enter your system login password to authenticate this sign-off</p>
          <div className="relative">
            <input type={showPassword ? 'text' : 'password'} value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Your system login password"
              className="w-full bg-white/10 border border-white/20 text-white placeholder-blue-300/50 rounded-lg px-3 py-2 pr-10 text-sm focus:outline-none focus:border-blue-400" />
            <button type="button" onClick={() => setShowPassword(v => !v)}
              className="absolute right-3 top-2.5 text-blue-300 hover:text-white">
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {error && (
          <div className="flex items-center space-x-2 bg-rose-500/10 border border-rose-500/30 rounded-lg p-3">
            <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <p className="text-rose-200 text-xs">{error}</p>
          </div>
        )}

        <button type="submit" disabled={submitting}
          className="w-full py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white font-bold rounded-xl transition-all hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2">
          <Shield className="w-4 h-4" />
          <span>{submitting ? 'Signing off...' : 'Sign & Confirm Diagnosis'}</span>
        </button>
      </form>
    </div>
  );
};

export default ConfirmationPanel;

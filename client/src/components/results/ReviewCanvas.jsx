// Interactive annotation canvas for clinician review.
// Clinicians can: flag false-positive boxes, relabel parasite species,
// draw new parasite/WBC boxes, and see counts update live.
import React, { useRef, useEffect, useState, useCallback } from 'react';
import {
  MousePointer, PenLine, Trash2, Tag, ZoomIn, ZoomOut,
  RotateCcw, Eye, EyeOff, CheckCircle, AlertCircle,
} from 'lucide-react';

const CLASS_COLORS = {
  PF:  '#ff3232',
  PM:  '#ff8c00',
  PO:  '#00dcdc',
  PV:  '#6464ff',
  WBC: '#32c832',
};
const CLINICIAN_TINT = '#ffc800';
const FLAGGED_COLOR  = '#ff3232';
const PARASITE_TYPES = ['PF', 'PM', 'PO', 'PV'];

// Convert hex color to rgba string
const hex2rgba = (hex, a = 1) => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${a})`;
};

export default function ReviewCanvas({ image, onDetectionsChange }) {
  // image = { originalUrl, annotations: { parasites:[{parasiteId,type,confidence,boundingBox,source?}], wbcs:[{wbcId?,type,confidence,boundingBox,source?}] } }

  const canvasRef  = useRef(null);
  const imgRef     = useRef(null);       // loaded HTMLImageElement
  const scaleRef   = useRef(1);          // canvas px / original image px
  const offsetRef  = useRef({ x: 0, y: 0 });

  const [zoom, setZoom]       = useState(1);
  const [tool, setTool]       = useState('select');   // 'select' | 'draw'
  const [drawClass, setDrawClass] = useState('PF');   // class for new drawn boxes
  const [drawTarget, setDrawTarget] = useState('parasite'); // 'parasite' | 'wbc'

  // Detection state
  const [parasites, setParasites] = useState([]);   // { parasiteId, type, confidence, bbox:[x1,y1,x2,y2], source, flagged, relabelOpen }
  const [wbcs, setWbcs]           = useState([]);   // { wbcId, confidence, bbox, source, flagged }
  const [selected, setSelected]   = useState(null); // { kind:'parasite'|'wbc', id }
  const [relabelOpen, setRelabelOpen] = useState(null); // parasiteId

  // Draw-mode state
  const drawStart = useRef(null);
  const [drawing, setDrawing]  = useState(false);
  const [drawRect, setDrawRect] = useState(null);

  const [showWbcs, setShowWbcs] = useState(true);

  // ── Initialise from props ────────────────────────────────────────────────
  useEffect(() => {
    if (!image) return;
    const ann = image.annotations || {};

    const pList = (ann.parasites || []).map((p, i) => ({
      parasiteId: p.parasiteId ?? i + 1,
      type:       p.type || 'PF',
      confidence: p.confidence ?? 0,
      bbox: p.boundingBox
        ? [p.boundingBox.x1, p.boundingBox.y1, p.boundingBox.x2, p.boundingBox.y2]
        : [0, 0, 0, 0],
      source:  p.source || 'model',
      flagged: false,
    }));

    const wList = (ann.wbcs || []).map((w, i) => ({
      wbcId:      w.wbcId ?? i + 1,
      confidence: w.confidence ?? 0,
      bbox: w.boundingBox
        ? [w.boundingBox.x1, w.boundingBox.y1, w.boundingBox.x2, w.boundingBox.y2]
        : [0, 0, 0, 0],
      source:  w.source || 'model',
      flagged: false,
    }));

    setParasites(pList);
    setWbcs(wList);
    setSelected(null);
    setRelabelOpen(null);
  // Only re-initialise when the actual image changes, not on every parent re-render.
  // Using originalUrl as a stable key prevents drawn boxes from being wiped when
  // the parent updates state (e.g. onDetectionsChange → setDetectionEdits).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [image?.originalUrl]);

  // ── Notify parent whenever detections change ─────────────────────────────
  useEffect(() => {
    if (!onDetectionsChange) return;
    const kept   = parasites.filter(p => !p.flagged);
    const keptW  = wbcs.filter(w => !w.flagged);
    // Renumber after edits
    const renumbered = kept.map((p, i) => ({ ...p, parasiteId: i + 1 }));
    const renumberedW = keptW.map((w, i) => ({ ...w, wbcId: i + 1 }));
    onDetectionsChange({
      reviewedDetections: renumbered,
      reviewedWbcs:       renumberedW,
      flaggedParasiteIds: parasites.filter(p => p.flagged).map(p => p.parasiteId),
      flaggedWbcIds:      wbcs.filter(w => w.flagged).map(w => w.wbcId),
    });
  }, [parasites, wbcs, onDetectionsChange]);

  // ── Canvas rendering ─────────────────────────────────────────────────────
  const render = useCallback(() => {
    const canvas = canvasRef.current;
    const img    = imgRef.current;
    if (!canvas || !img) return;

    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw image
    const scale = scaleRef.current * zoom;
    const ox = offsetRef.current.x;
    const oy = offsetRef.current.y;
    ctx.drawImage(img, ox, oy, img.naturalWidth * scale, img.naturalHeight * scale);

    const toCanvas = ([x, y]) => [ox + x * scale, oy + y * scale];

    // Scale line widths and font to match the OpenCV output at this display size.
    // OpenCV drew 2px box lines and ~13px text at full image resolution;
    // scaleRef.current maps image pixels → canvas pixels, so we apply the same ratio.
    const s         = scaleRef.current * zoom;
    const boxLW     = Math.max(0.8, 2 * s);             // mirrors _BOX_THICK = 2
    const textPx    = Math.max(9,  Math.round(13 * s)); // mirrors _FONT_SCALE = 0.42
    const font      = `${textPx}px sans-serif`;
    const outlineLW = Math.max(1.5, (2 + 2) * s);       // mirrors font_thick + 2 stroke

    const drawBox = (bbox, color, label, flagged, isSelected, isClinician) => {
      const [x1c, y1c] = toCanvas([bbox[0], bbox[1]]);
      const [x2c, y2c] = toCanvas([bbox[2], bbox[3]]);
      const w = x2c - x1c;
      const h = y2c - y1c;

      ctx.save();

      if (flagged) {
        ctx.setLineDash([5 * s, 4 * s]);
        ctx.strokeStyle = FLAGGED_COLOR;
        ctx.lineWidth   = boxLW;
        ctx.globalAlpha = 0.6;
        ctx.strokeRect(x1c, y1c, w, h);
        ctx.beginPath();
        ctx.moveTo(x1c, y1c); ctx.lineTo(x2c, y2c);
        ctx.moveTo(x2c, y1c); ctx.lineTo(x1c, y2c);
        ctx.stroke();
      } else {
        ctx.setLineDash([]);
        if (isClinician) {
          ctx.strokeStyle = CLINICIAN_TINT;
          ctx.lineWidth   = Math.max(0.5, s);
          ctx.strokeRect(x1c - 1, y1c - 1, w + 2, h + 2);
        }
        ctx.strokeStyle = isSelected ? '#ffffff' : color;
        ctx.lineWidth   = isSelected ? boxLW * 1.4 : boxLW;
        ctx.strokeRect(x1c, y1c, w, h);

        // Label — placed above the box (below if near top edge), matching OpenCV logic
        ctx.font = font;
        const th = textPx;
        const lx = x1c;
        const ly = y1c > th + 6 * s ? y1c - 4 * s : y2c + th + 2 * s;

        // Outline then fill, mirrors cv2 double-putText approach
        ctx.lineWidth   = outlineLW;
        ctx.strokeStyle = '#000000';
        ctx.strokeText(label, lx, ly);
        ctx.fillStyle   = isSelected ? '#ffffff' : color;
        ctx.fillText(label, lx, ly);
      }
      ctx.restore();
    };

    // WBCs
    if (showWbcs) {
      wbcs.forEach(w => {
        const isSel = selected?.kind === 'wbc' && selected.id === w.wbcId;
        drawBox(
          w.bbox,
          CLASS_COLORS.WBC,
          `W${w.wbcId} ${w.confidence.toFixed(2)}${w.source === 'clinician' ? ' [C]' : ''}`,
          w.flagged,
          isSel,
          w.source === 'clinician',
        );
      });
    }

    // Parasites
    parasites.forEach(p => {
      const isSel = selected?.kind === 'parasite' && selected.id === p.parasiteId;
      drawBox(
        p.bbox,
        CLASS_COLORS[p.type] || '#aaaaaa',
        `#${p.parasiteId} ${p.type} ${p.confidence.toFixed(2)}${p.source === 'clinician' ? ' [C]' : ''}`,
        p.flagged,
        isSel,
        p.source === 'clinician',
      );
    });

    // Live draw preview
    if (drawing && drawRect) {
      const [x1c, y1c] = toCanvas([drawRect.x1, drawRect.y1]);
      const [x2c, y2c] = toCanvas([drawRect.x2, drawRect.y2]);
      ctx.save();
      ctx.setLineDash([4 * s, 3 * s]);
      ctx.strokeStyle = drawTarget === 'wbc' ? CLASS_COLORS.WBC : CLASS_COLORS[drawClass];
      ctx.lineWidth   = boxLW;
      ctx.strokeRect(x1c, y1c, x2c - x1c, y2c - y1c);
      ctx.restore();
    }
  }, [parasites, wbcs, selected, zoom, drawing, drawRect, showWbcs, drawClass, drawTarget]);

  // Re-render on any state change
  useEffect(() => { render(); }, [render]);

  // ── Load image, size canvas ──────────────────────────────────────────────
  useEffect(() => {
    // Prefer the AI-annotated image as background — same coordinate space as
    // the AI view so clinician-drawn boxes align perfectly with the baked labels.
    const imgSrc = image?.annotatedUrl || image?.originalUrl || image?.url;
    if (!imgSrc) return;
    const htmlImg  = new Image();
    htmlImg.crossOrigin = 'anonymous';
    htmlImg.onload = () => {
      imgRef.current = htmlImg;
      const canvas  = canvasRef.current;
      if (!canvas) return;
      const maxW    = canvas.parentElement?.clientWidth  || 800;
      const maxH    = 540;
      const scale   = Math.min(maxW / htmlImg.naturalWidth, maxH / htmlImg.naturalHeight, 1);
      scaleRef.current      = scale;
      canvas.width          = maxW;
      canvas.height         = maxH;
      offsetRef.current     = {
        x: (maxW - htmlImg.naturalWidth  * scale) / 2,
        y: (maxH - htmlImg.naturalHeight * scale) / 2,
      };
      render();
    };
    htmlImg.src = imgSrc;
  }, [image?.annotatedUrl, image?.originalUrl, image?.url]);

  // ── Hit-test helper ──────────────────────────────────────────────────────
  const hitTest = useCallback((cx, cy) => {
    const scale = scaleRef.current * zoom;
    const ox    = offsetRef.current.x;
    const oy    = offsetRef.current.y;
    const ix    = (cx - ox) / scale;  // image coords
    const iy    = (cy - oy) / scale;

    // Parasites (check in reverse so top-drawn = first hit)
    for (let i = parasites.length - 1; i >= 0; i--) {
      const [x1, y1, x2, y2] = parasites[i].bbox;
      if (ix >= x1 && ix <= x2 && iy >= y1 && iy <= y2)
        return { kind: 'parasite', id: parasites[i].parasiteId };
    }
    if (showWbcs) {
      for (let i = wbcs.length - 1; i >= 0; i--) {
        const [x1, y1, x2, y2] = wbcs[i].bbox;
        if (ix >= x1 && ix <= x2 && iy >= y1 && iy <= y2)
          return { kind: 'wbc', id: wbcs[i].wbcId };
      }
    }
    return null;
  }, [parasites, wbcs, zoom, showWbcs]);

  // ── Canvas-to-image coords ───────────────────────────────────────────────
  const toImageCoords = useCallback((cx, cy) => {
    const scale = scaleRef.current * zoom;
    const ox    = offsetRef.current.x;
    const oy    = offsetRef.current.y;
    return [(cx - ox) / scale, (cy - oy) / scale];
  }, [zoom]);

  // ── Mouse events ─────────────────────────────────────────────────────────
  const handleMouseDown = useCallback((e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    const cx   = e.clientX - rect.left;
    const cy   = e.clientY - rect.top;

    if (tool === 'select') {
      const hit = hitTest(cx, cy);
      setSelected(hit);
      setRelabelOpen(null);
    } else if (tool === 'draw') {
      const [ix, iy] = toImageCoords(cx, cy);
      drawStart.current = { ix, iy };
      setDrawing(true);
      setDrawRect({ x1: ix, y1: iy, x2: ix, y2: iy });
    }
  }, [tool, hitTest, toImageCoords]);

  const handleMouseMove = useCallback((e) => {
    if (!drawing || !drawStart.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const cx   = e.clientX - rect.left;
    const cy   = e.clientY - rect.top;
    const [ix, iy] = toImageCoords(cx, cy);
    setDrawRect({
      x1: Math.min(drawStart.current.ix, ix),
      y1: Math.min(drawStart.current.iy, iy),
      x2: Math.max(drawStart.current.ix, ix),
      y2: Math.max(drawStart.current.iy, iy),
    });
  }, [drawing, toImageCoords]);

  const handleMouseUp = useCallback((e) => {
    if (!drawing || !drawRect) { setDrawing(false); return; }
    const minSize = 8;
    const w = drawRect.x2 - drawRect.x1;
    const h = drawRect.y2 - drawRect.y1;

    if (w > minSize && h > minSize) {
      const bbox = [
        Math.round(drawRect.x1), Math.round(drawRect.y1),
        Math.round(drawRect.x2), Math.round(drawRect.y2),
      ];
      if (drawTarget === 'parasite') {
        setParasites(prev => {
          const nextId = prev.length > 0 ? Math.max(...prev.map(p => p.parasiteId)) + 1 : 1;
          return [...prev, { parasiteId: nextId, type: drawClass, confidence: 1.0, bbox, source: 'clinician', flagged: false }];
        });
      } else {
        setWbcs(prev => {
          const nextId = prev.length > 0 ? Math.max(...prev.map(w => w.wbcId)) + 1 : 1;
          return [...prev, { wbcId: nextId, confidence: 1.0, bbox, source: 'clinician', flagged: false }];
        });
      }
    }
    setDrawing(false);
    setDrawRect(null);
    drawStart.current = null;
  }, [drawing, drawRect, drawTarget, drawClass]);

  // ── Detection actions ────────────────────────────────────────────────────
  const toggleFlag = (kind, id) => {
    if (kind === 'parasite') setParasites(prev => prev.map(p => p.parasiteId === id ? { ...p, flagged: !p.flagged } : p));
    else                     setWbcs(prev =>      prev.map(w => w.wbcId      === id ? { ...w, flagged: !w.flagged } : w));
    setSelected(null);
  };

  const relabel = (parasiteId, newType) => {
    setParasites(prev => prev.map(p => p.parasiteId === parasiteId ? { ...p, type: newType } : p));
    setRelabelOpen(null);
  };

  const removeClinicianBox = (kind, id) => {
    if (kind === 'parasite') setParasites(prev => prev.filter(p => p.parasiteId !== id));
    else                     setWbcs(prev =>      prev.filter(w => w.wbcId      !== id));
    setSelected(null);
  };

  // ── Counts ───────────────────────────────────────────────────────────────
  const keptParasites = parasites.filter(p => !p.flagged);
  const keptWbcs      = wbcs.filter(w => !w.flagged);
  const flaggedCount  = parasites.filter(p => p.flagged).length + wbcs.filter(w => w.flagged).length;

  // Selected box details
  const selParasite = selected?.kind === 'parasite' ? parasites.find(p => p.parasiteId === selected.id) : null;
  const selWbc      = selected?.kind === 'wbc'      ? wbcs.find(w => w.wbcId === selected.id)          : null;
  const selBox      = selParasite || selWbc;

  return (
    <div className="flex flex-col gap-4">

      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Tool selector */}
        <div className="flex rounded-lg overflow-hidden border border-white/20">
          <button
            onClick={() => setTool('select')}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors ${tool === 'select' ? 'bg-blue-600 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}
          >
            <MousePointer className="w-3.5 h-3.5" /> Select
          </button>
          <button
            onClick={() => setTool('draw')}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors ${tool === 'draw' ? 'bg-blue-600 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}
          >
            <PenLine className="w-3.5 h-3.5" /> Draw
          </button>
        </div>

        {/* Draw target + class (only when draw tool active) */}
        {tool === 'draw' && (
          <>
            <div className="flex rounded-lg overflow-hidden border border-white/20">
              <button onClick={() => setDrawTarget('parasite')}
                className={`px-3 py-2 text-xs font-medium transition-colors ${drawTarget === 'parasite' ? 'bg-rose-600 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}>
                Parasite
              </button>
              <button onClick={() => setDrawTarget('wbc')}
                className={`px-3 py-2 text-xs font-medium transition-colors ${drawTarget === 'wbc' ? 'bg-green-700 text-white' : 'bg-white/5 text-blue-200 hover:bg-white/10'}`}>
                WBC
              </button>
            </div>
            {drawTarget === 'parasite' && (
              <div className="flex gap-1">
                {PARASITE_TYPES.map(t => (
                  <button key={t} onClick={() => setDrawClass(t)}
                    className={`px-2 py-1 rounded text-xs font-bold border transition-colors ${drawClass === t ? 'text-white border-transparent' : 'text-blue-200 border-white/20 hover:bg-white/10'}`}
                    style={drawClass === t ? { background: CLASS_COLORS[t] } : {}}>
                    {t}
                  </button>
                ))}
              </div>
            )}
          </>
        )}

        {/* Zoom */}
        <div className="flex items-center gap-1 ml-auto border border-white/20 rounded-lg overflow-hidden">
          <button onClick={() => setZoom(z => Math.max(0.5, z - 0.25))} className="px-2 py-2 bg-white/5 hover:bg-white/10 text-white"><ZoomOut className="w-3.5 h-3.5" /></button>
          <span className="px-2 text-xs text-blue-200 min-w-10 text-center">{Math.round(zoom * 100)}%</span>
          <button onClick={() => setZoom(z => Math.min(4, z + 0.25))}   className="px-2 py-2 bg-white/5 hover:bg-white/10 text-white"><ZoomIn  className="w-3.5 h-3.5" /></button>
          <button onClick={() => setZoom(1)} className="px-2 py-2 bg-white/5 hover:bg-white/10 text-xs text-blue-200">1:1</button>
        </div>

        {/* Toggle WBCs */}
        <button onClick={() => setShowWbcs(v => !v)}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-white/20 bg-white/5 hover:bg-white/10 text-xs text-blue-200">
          {showWbcs ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          WBCs
        </button>
      </div>

      {/* ── Canvas ── */}
      <div className="relative rounded-xl overflow-hidden border border-white/20 bg-gray-900/50">
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          className="block w-full"
          style={{ cursor: tool === 'draw' ? 'crosshair' : 'default' }}
        />

        {/* Selected box action popup */}
        {selBox && (
          <div className="absolute top-3 right-3 bg-gray-900/90 border border-white/20 rounded-xl p-3 backdrop-blur-md text-xs text-white min-w-40 space-y-2">
            <p className="font-bold text-white">
              {selParasite ? `#${selParasite.parasiteId} ${selParasite.type}` : `W${selWbc.wbcId} WBC`}
            </p>
            <p className="text-blue-300">{(selBox.confidence * 100).toFixed(0)}% conf · {selBox.source}</p>

            {/* Flag / unflag */}
            <button
              onClick={() => toggleFlag(selected.kind, selected.id)}
              className={`w-full flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-xs font-medium transition-colors ${selBox.flagged ? 'bg-green-600/30 text-green-300 hover:bg-green-600/50' : 'bg-rose-600/30 text-rose-300 hover:bg-rose-600/50'}`}
            >
              {selBox.flagged
                ? <><CheckCircle className="w-3.5 h-3.5" /> Restore</>
                : <><AlertCircle className="w-3.5 h-3.5" /> Flag as False Positive</>}
            </button>

            {/* Relabel (parasites only) */}
            {selParasite && !selParasite.flagged && (
              <div>
                <button
                  onClick={() => setRelabelOpen(v => v === selParasite.parasiteId ? null : selParasite.parasiteId)}
                  className="w-full flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-xs font-medium bg-blue-600/30 text-blue-300 hover:bg-blue-600/50 transition-colors"
                >
                  <Tag className="w-3.5 h-3.5" /> Relabel
                </button>
                {relabelOpen === selParasite.parasiteId && (
                  <div className="flex gap-1 mt-1 flex-wrap">
                    {PARASITE_TYPES.map(t => (
                      <button key={t} onClick={() => relabel(selParasite.parasiteId, t)}
                        className="px-2 py-0.5 rounded text-xs font-bold text-white"
                        style={{ background: CLASS_COLORS[t] }}>
                        {t}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Delete clinician-added boxes */}
            {selBox.source === 'clinician' && (
              <button
                onClick={() => removeClinicianBox(selected.kind, selected.id)}
                className="w-full flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-xs font-medium bg-gray-600/40 text-gray-300 hover:bg-gray-600/60 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" /> Remove
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── Live counts ── */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: 'Kept Parasites', value: keptParasites.length,                          color: 'rose' },
          { label: 'Kept WBCs',      value: keptWbcs.length,                               color: 'green' },
          { label: 'Flagged',        value: flaggedCount,                                   color: 'amber' },
          { label: 'Clinician Added',value: [...parasites,...wbcs].filter(d=>d.source==='clinician').length, color: 'blue' },
        ].map(({ label, value, color }) => (
          <div key={label} className={`text-center p-3 rounded-xl bg-${color}-500/10 border border-${color}-500/20`}>
            <div className={`text-2xl font-bold text-${color}-400`}>{value}</div>
            <div className={`text-xs text-${color}-300 mt-0.5`}>{label}</div>
          </div>
        ))}
      </div>

      {/* ── Legend ── */}
      <div className="flex flex-wrap gap-3 text-xs text-blue-200">
        {Object.entries(CLASS_COLORS).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1">
            <span className="w-3 h-3 rounded-sm inline-block border border-white/20" style={{ background: c }} />
            {k}
          </span>
        ))}
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm inline-block border" style={{ borderColor: CLINICIAN_TINT }} />
          Clinician-added [C]
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm inline-block border border-dashed border-red-500" />
          Flagged (FP)
        </span>
      </div>
    </div>
  );
}

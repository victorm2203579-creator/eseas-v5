import csv
import io
import json
from urllib.parse import urlparse

from flask import (Blueprint, render_template, request, jsonify,
                   redirect, url_for, flash, Response, abort)
from flask_login import login_required, current_user

from models import db, ScanResult
from models.notification import NotificationService
from extensions import limiter

analyzer = Blueprint('analyzer', __name__, url_prefix='/analyzer')

_PAGE_SIZE = 20


# ── helpers ──────────────────────────────────────────────────

def _is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url if '://' in url else 'http://' + url)
        return bool(p.netloc)
    except Exception:
        return False


def _api_keys():
    from flask import current_app
    return (
        current_app.config.get('VIRUSTOTAL_API_KEY') or '',
        current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY') or '',
    )


_predictor_cache = None

def _load_predictor():
    """Lazy-import and cache predictor — only loads once per process."""
    global _predictor_cache
    if _predictor_cache is not None:
        return _predictor_cache
    try:
        from ml_engine.predictor import (
            predict_url, integrate_virustotal,
            integrate_google_safe_browsing, combine_results, load_model,
            generate_explanation,
        )
        load_model()
        _predictor_cache = (
            predict_url, integrate_virustotal,
            integrate_google_safe_browsing, combine_results, generate_explanation,
        )
        return _predictor_cache
    except Exception:
        return None, None, None, None, None


# ── routes ───────────────────────────────────────────────────

@analyzer.route('/')
@login_required
def index():
    recent = (ScanResult.query
              .filter_by(user_id=current_user.id)
              .order_by(ScanResult.scanned_at.desc())
              .limit(10).all())
    return render_template('analyzer/index.html', recent_scans=recent)


@analyzer.route('/scan', methods=['POST'])
@login_required
@limiter.limit('30 per minute')
def scan():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or request.form.get('url', '')).strip()

    if not url:
        return jsonify({'error': 'No URL provided.'}), 400

    if not _is_valid_url(url):
        return jsonify({'error': 'Invalid URL format.'}), 400

    # Normalise scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    predict_url, integrate_vt, integrate_gsb, combine, gen_explanation = _load_predictor()

    # ── ML prediction ────────────────────────────────────────
    if predict_url is None:
        return jsonify({'error': 'ML engine unavailable. Run train_model.py first.'}), 503

    try:
        ml_result = predict_url(url)
    except Exception as e:
        return jsonify({'error': f'Prediction error: {str(e)[:120]}'}), 500

    # ── External APIs ────────────────────────────────────────
    vt_key, gsb_key = _api_keys()
    try:
        vt_result = integrate_vt(url, vt_key)
    except Exception:
        vt_result = {'error': 'VirusTotal lookup timed out'}
    try:
        gsb_result = integrate_gsb(url, gsb_key)
    except Exception:
        gsb_result = {'error': 'Safe Browsing lookup timed out'}

    # ── Combine ──────────────────────────────────────────────
    final = combine(ml_result, vt_result, gsb_result)

    # ── Explanation ──────────────────────────────────────────
    explanation = {}
    if gen_explanation:
        try:
            explanation = gen_explanation(
                final['features'], final['feature_flags'],
                final['score'], final['label']
            )
        except Exception:
            explanation = {}

    # ── Persist ──────────────────────────────────────────────
    scan_rec = ScanResult(
        user_id          = current_user.id,
        url              = url,
        final_score      = final['score'],
        final_label      = final['label'],
        ml_score         = final.get('ml_score', final['score']),
        vt_detections    = vt_result.get('detections'),
        vt_total_engines = vt_result.get('total_engines'),
        gsb_threat_type  = gsb_result.get('threat_type'),
        domain_age       = final['features'].get('domain_age_days'),
        features_json    = json.dumps(final['features']),
        explanation_json = json.dumps(explanation) if explanation else None,
        recommendation   = final['recommendation'],
    )
    db.session.add(scan_rec)

    # Update user risk score (rolling average)
    scores = [s.final_score for s in
              current_user.scans.order_by(ScanResult.scanned_at.desc()).limit(10).all()]
    scores.append(final['score'])
    current_user.risk_score = round(sum(scores) / len(scores), 1)

    db.session.commit()

    # ── Notify user on dangerous/suspicious results ───────────
    if final['label'] == 'Dangerous':
        short = url if len(url) <= 60 else url[:57] + '…'
        NotificationService.create(
            current_user.id, 'danger',
            'Dangerous URL Detected',
            f'High-risk URL blocked: {short} — Score {final["score"]}/100',
            link=f'/analyzer/scan/{scan_rec.id}',
        )
    elif final['label'] == 'Suspicious':
        short = url if len(url) <= 60 else url[:57] + '…'
        NotificationService.create(
            current_user.id, 'warning',
            'Suspicious URL Flagged',
            f'Proceed with caution: {short} — Score {final["score"]}/100',
            link=f'/analyzer/scan/{scan_rec.id}',
        )

    # ── Response ─────────────────────────────────────────────
    return jsonify({
        'scan_id':        scan_rec.id,
        'url':            url,
        'score':          final['score'],
        'label':          final['label'],
        'risk_color':     scan_rec.risk_color,
        'features':       final['features'],
        'feature_flags':  final['feature_flags'],
        'feature_labels': final['feature_labels'],
        'recommendation': final['recommendation'],
        'explanation':    explanation,
        'vt': {
            'detections':    vt_result.get('detections', 0),
            'total_engines': vt_result.get('total_engines', 0),
            'threat_names':  vt_result.get('threat_names', []),
            'permalink':     vt_result.get('permalink', ''),
            'error':         vt_result.get('error'),
        },
        'gsb': {
            'threat_type': gsb_result.get('threat_type'),
            'platform':    gsb_result.get('platform'),
            'error':       gsb_result.get('error'),
        },
        'domain_age': final['features'].get('domain_age_days', -1),
        'model_available': final.get('model_available', False),
    })


@analyzer.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    label_filter = request.args.get('label', '').strip()
    search = request.args.get('q', '').strip()

    query = ScanResult.query.filter_by(user_id=current_user.id)

    if label_filter in ('Safe', 'Suspicious', 'Dangerous'):
        query = query.filter_by(final_label=label_filter)

    if search:
        query = query.filter(ScanResult.url.ilike(f'%{search}%'))

    pagination = (query
                  .order_by(ScanResult.scanned_at.desc())
                  .paginate(page=page, per_page=_PAGE_SIZE, error_out=False))

    return render_template('analyzer/history.html',
                           pagination=pagination,
                           scans=pagination.items,
                           label_filter=label_filter,
                           search=search)


@analyzer.route('/scan/<int:scan_id>')
@login_required
def detail(scan_id):
    scan = ScanResult.query.filter_by(
        id=scan_id, user_id=current_user.id).first_or_404()
    try:
        from ml_engine.feature_extractor import _FEATURE_LABELS as fl
        feature_labels = fl
    except Exception:
        feature_labels = {}
    return render_template('analyzer/detail.html',
                           scan=scan,
                           feature_labels=feature_labels)


@analyzer.route('/scan/<int:scan_id>/explanation')
@login_required
def scan_explanation(scan_id):
    """Return the stored explanation JSON for a scan (used by admin/user modals)."""
    scan = ScanResult.query.filter_by(id=scan_id).first_or_404()
    # Admins can see any scan; regular users only their own
    from models.user import User
    viewer = User.query.get(current_user.id)
    if not viewer.is_admin and scan.user_id != current_user.id:
        abort(403)

    expl = scan.explanation
    if not expl:
        # Re-generate on the fly from stored features
        try:
            from ml_engine.predictor import generate_explanation
            from ml_engine.feature_extractor import get_feature_flag
            feats = scan.features
            flags = {k: get_feature_flag(k, v) for k, v in feats.items()}
            expl = generate_explanation(feats, flags, int(scan.final_score), scan.final_label)
        except Exception:
            expl = {}

    return jsonify({
        'scan_id':    scan.id,
        'url':        scan.url,
        'score':      scan.final_score,
        'label':      scan.final_label,
        'risk_color': scan.risk_color,
        'explanation': expl,
    })


@analyzer.route('/export')
@login_required
def export():
    scans = (ScanResult.query
             .filter_by(user_id=current_user.id)
             .order_by(ScanResult.scanned_at.desc())
             .all())

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['id', 'url', 'score', 'label', 'ml_score',
                         'vt_detections', 'vt_total_engines',
                         'gsb_threat', 'domain_age', 'scanned_at'])
        yield buf.getvalue()
        buf.seek(0); buf.truncate()

        for s in scans:
            writer.writerow([
                s.id, s.url, s.final_score, s.final_label,
                s.ml_score, s.vt_detections, s.vt_total_engines,
                s.gsb_threat_type, s.domain_age,
                s.scanned_at.strftime('%Y-%m-%d %H:%M:%S'),
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=scan_history.csv'},
    )


@analyzer.route('/scan/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    scan = ScanResult.query.filter_by(
        id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'ok': True})


@analyzer.route('/quick-scan', methods=['POST'])
@login_required
def quick_scan():
    """Topbar quick scan — returns minimal JSON {label, risk_score}."""
    data = request.get_json(force=True, silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'No URL'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if not _is_valid_url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    predict_url, integrate_vt, integrate_gsb, combine, _ = _load_predictor()
    if predict_url is None:
        return jsonify({'error': 'ML engine unavailable'}), 503

    try:
        ml_result  = predict_url(url)
        vt_key, gsb_key = _api_keys()
        vt_result  = integrate_vt(url, vt_key)
        gsb_result = integrate_gsb(url, gsb_key)
        final      = combine(ml_result, vt_result, gsb_result)

        scan_rec = ScanResult(
            user_id=current_user.id, url=url,
            final_score=final['score'], final_label=final['label'],
            ml_score=final.get('ml_score', final['score']),
            vt_detections=vt_result.get('detections'),
            vt_total_engines=vt_result.get('total_engines'),
            gsb_threat_type=gsb_result.get('threat_type'),
            domain_age=final['features'].get('domain_age_days'),
            features_json=__import__('json').dumps(final['features']),
            recommendation=final['recommendation'],
        )
        db.session.add(scan_rec)
        scores = [s.final_score for s in
                  current_user.scans.order_by(ScanResult.scanned_at.desc()).limit(10).all()]
        scores.append(final['score'])
        current_user.risk_score = round(sum(scores) / len(scores), 1)
        db.session.commit()

        return jsonify({'label': final['label'], 'risk_score': final['score']})
    except Exception as exc:
        return jsonify({'error': str(exc)[:120]}), 500

import csv
import io
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (Blueprint, render_template, request, jsonify,
                   redirect, url_for, flash, Response, abort)
from flask_login import login_required, current_user

from models import db, ScanResult
from models.notification import NotificationService
from extensions import limiter
from security.concurrency_guard import prevent_concurrent

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
@prevent_concurrent('url_scan')  # Threat 13: prevent duplicate concurrent scans
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

    predict_url_fn, integrate_vt, integrate_gsb, combine, gen_explanation = _load_predictor()

    if predict_url_fn is None:
        return jsonify({'error': 'ML engine unavailable. Run train_model.py first.'}), 503

    # Extract domain
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc
    except Exception:
        domain = url

    # ── Run ALL analyses in parallel (ML + APIs simultaneously) ──
    # ML feature extraction (WHOIS, SSL, DNS) runs alongside VT/GSB so we don't
    # pay its cost sequentially. Hard 8s per-future timeout keeps total ≤ ~9s.
    analysis_results = {}
    ml_result = None

    vt_key, gsb_key = _api_keys()
    # NOTE: deliberately NOT using "with ThreadPoolExecutor(...) as executor:" here.
    # The context manager's __exit__ calls shutdown(wait=True), which blocks until
    # EVERY submitted thread finishes — even ones we've already given up on via
    # future.result(timeout=8). A single hung thread (e.g. a slow WHOIS/scraper call)
    # would silently double the real wall-clock time of every scan. shutdown(wait=False)
    # lets us move on immediately; the straggler thread finishes on its own in the background.
    executor = ThreadPoolExecutor(max_workers=8)
    try:
        futures = {}

        # ML prediction — fast=True uses only lexical URL features (instant, no network calls).
        # Network intelligence (WHOIS, SSL, DNS) already comes from the parallel modules below.
        futures['_ml'] = executor.submit(predict_url_fn, url, True)

        # Threat feeds
        try:
            from ml_engine.threat_feeds import query_all_threat_feeds
            futures['threat_feeds'] = executor.submit(query_all_threat_feeds, url, domain)
        except Exception:
            pass

        # SSL analysis
        try:
            from ml_engine.ssl_checker import check_ssl_certificate
            futures['ssl_analysis'] = executor.submit(check_ssl_certificate, domain)
        except Exception:
            pass

        # Redirect analysis
        try:
            from ml_engine.redirect_analyzer import analyze_redirect_chain
            futures['redirect_analysis'] = executor.submit(analyze_redirect_chain, url)
        except Exception:
            pass

        # Typosquatting
        try:
            from ml_engine.typosquatting import check_typosquatting
            futures['typosquatting'] = executor.submit(check_typosquatting, domain)
        except Exception:
            pass

        # VirusTotal
        try:
            futures['virustotal'] = executor.submit(integrate_vt, url, vt_key)
        except Exception:
            pass

        # Google Safe Browsing
        try:
            futures['google_safe_browsing'] = executor.submit(integrate_gsb, url, gsb_key)
        except Exception:
            pass

        # Collect all with 7s hard cap per future
        for key, future in futures.items():
            try:
                result = future.result(timeout=7)
                if key == '_ml':
                    ml_result = result
                else:
                    analysis_results[key] = result
            except Exception:
                if key != '_ml':
                    analysis_results[key] = None
    finally:
        executor.shutdown(wait=False)

    if ml_result is None:
        # ML timed out or errored — use empty fallback so heuristics still work
        ml_result = {'score': 0, 'label': 'Safe', 'features': {}, 'feature_flags': {},
                     'feature_labels': {}, 'recommendation': '', 'model_available': False}

    # ── Prepare data for scoring ─────────────────────────────
    analysis_results['url'] = url  # pass raw URL into scoring engine for heuristics
    vt_result = analysis_results.get('virustotal') or {}
    gsb_result = analysis_results.get('google_safe_browsing') or {}

    # Add ML prediction to results
    if ml_result:
        analysis_results['ml_prediction'] = ml_result.get('ml_score', ml_result.get('score', 0)) / 100.0

    # Normalize VirusTotal key names for scoring engine
    if vt_result:
        analysis_results['virustotal'] = {
            'detection_count': vt_result.get('detections', 0),
            'total_scanners': vt_result.get('total_engines', 70),
            'is_malicious': vt_result.get('is_malicious', False),
        }

    # ── CRITICAL OVERRIDE: VirusTotal detection ─────────────────────
    # If VirusTotal flags ANY threat, force minimum score regardless of other layers
    vt_detections = vt_result.get('detections', 0)
    vt_total = vt_result.get('total_engines', 70)

    # ── Compute unified risk score ───────────────────────────
    try:
        from ml_engine.scoring_engine import compute_final_risk_score
        final_risk = compute_final_risk_score(analysis_results)
    except Exception:
        # Fallback to old combining method if scoring engine fails
        final = combine(ml_result, vt_result, gsb_result)
        final_risk = {
            'final_score': final['score'],
            'risk_level': final['label'],
            'risk_color': 'orange',
            'confidence': 'Low',
            'layers_used': 3,
            'layer_breakdown': {},
            'override_applied': False,
            'override_reason': None,
            'recommendation': final['recommendation']
        }

    # Use new scoring if available, else fallback
    final = combine(ml_result, vt_result, gsb_result)

    # ── FALLBACK: If scoring engine failed or has insufficient data, use ML result ─────
    # The scoring engine requires good data from VT/GSB. If those APIs fail, fall back to ML.
    if final_risk['final_score'] == 0 and final['score'] > 0:
        # Scoring engine returned Safe but ML says otherwise - use ML result
        final_risk['final_score'] = final['score']
        final_risk['risk_level'] = final['label']
        final_risk['override_applied'] = True
        final_risk['override_reason'] = 'ML fallback: Scoring engine had insufficient data'

        # Map label to color
        if final['score'] <= 20:
            final_risk['risk_color'] = 'green'
        elif final['score'] <= 40:
            final_risk['risk_color'] = 'yellow'
        elif final['score'] <= 60:
            final_risk['risk_color'] = 'orange'
        elif final['score'] <= 80:
            final_risk['risk_color'] = 'red-orange'
        else:
            final_risk['risk_color'] = 'red'

    # ── CRITICAL EMERGENCY OVERRIDE ─────────────────────────
    # If VirusTotal has ANY detections, enforce a minimum score floor
    if vt_detections > 0:
        if vt_detections >= 15:
            min_vt_score = 90
        elif vt_detections >= 10:
            min_vt_score = 85
        elif vt_detections >= 5:
            min_vt_score = 78
        elif vt_detections >= 3:
            min_vt_score = 70
        elif vt_detections >= 2:
            min_vt_score = 62
        else:
            min_vt_score = 52  # 1 engine flagged

        # Force minimum score
        if final_risk['final_score'] < min_vt_score:
            final_risk['final_score'] = min_vt_score
            final_risk['override_applied'] = True
            final_risk['override_reason'] = f'CRITICAL: VirusTotal detected {vt_detections}/{vt_total} threats'

            # Update risk level based on new score
            if final_risk['final_score'] <= 20:
                final_risk['risk_level'] = 'Safe'
                final_risk['risk_color'] = 'green'
            elif final_risk['final_score'] <= 40:
                final_risk['risk_level'] = 'Low Risk'
                final_risk['risk_color'] = 'yellow'
            elif final_risk['final_score'] <= 60:
                final_risk['risk_level'] = 'Suspicious'
                final_risk['risk_color'] = 'orange'
            elif final_risk['final_score'] <= 80:
                final_risk['risk_level'] = 'High Risk'
                final_risk['risk_color'] = 'red-orange'
            else:
                final_risk['risk_level'] = 'Phishing'
                final_risk['risk_color'] = 'red'

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
        final_score      = final_risk['final_score'],
        final_label      = final_risk['risk_level'],
        ml_score         = final.get('ml_score', final['score']),
        vt_detections    = vt_result.get('detections'),
        vt_total_engines = vt_result.get('total_engines'),
        gsb_threat_type  = gsb_result.get('threat_type'),
        domain_age       = final['features'].get('domain_age_days'),
        features_json    = json.dumps(final['features']),
        explanation_json = json.dumps(explanation) if explanation else None,
        recommendation   = final_risk['recommendation'],
    )
    db.session.add(scan_rec)

    # Update user risk score (rolling average)
    scores = [s.final_score for s in
              current_user.scans.order_by(ScanResult.scanned_at.desc()).limit(10).all()]
    scores.append(final_risk['final_score'])
    current_user.risk_score = round(sum(scores) / len(scores), 1)

    db.session.commit()

    # ── Notify user on dangerous/suspicious results ───────────
    if final_risk['risk_level'] in ('Phishing', 'High Risk'):
        short = url if len(url) <= 60 else url[:57] + '…'
        NotificationService.create(
            current_user.id, 'danger',
            'Dangerous URL Detected',
            f'High-risk URL: {short} — Score {final_risk["final_score"]}/100',
            link=f'/analyzer/scan/{scan_rec.id}',
        )
    elif final_risk['risk_level'] == 'Suspicious':
        short = url if len(url) <= 60 else url[:57] + '…'
        NotificationService.create(
            current_user.id, 'warning',
            'Suspicious URL Flagged',
            f'Proceed with caution: {short} — Score {final_risk["final_score"]}/100',
            link=f'/analyzer/scan/{scan_rec.id}',
        )

    # Map scoring engine colors to Bootstrap classes
    color_map = {
        'green': 'success',
        'yellow': 'warning',
        'orange': 'warning',
        'red-orange': 'danger',
        'red': 'danger'
    }
    bootstrap_color = color_map.get(final_risk['risk_color'], 'secondary')

    # ── Response ─────────────────────────────────────────────
    return jsonify({
        'scan_id':        scan_rec.id,
        'url':            url,
        'score':          final_risk['final_score'],
        'label':          final_risk['risk_level'],
        'risk_color':     bootstrap_color,
        'confidence':     final_risk['confidence'],
        'accuracy':       final_risk.get('accuracy', scan_rec.accuracy),
        'layers_used':    final_risk['layers_used'],
        'layer_breakdown': final_risk['layer_breakdown'],
        'override_applied': final_risk['override_applied'],
        'override_reason': final_risk['override_reason'],
        'features':       final['features'],
        'feature_flags':  final['feature_flags'],
        'feature_labels': final['feature_labels'],
        'recommendation': final_risk['recommendation'],
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
        'threat_feeds': analysis_results.get('threat_feeds', {}),
        'ssl_analysis': analysis_results.get('ssl_analysis', {}),
        'redirect_analysis': analysis_results.get('redirect_analysis', {}),
        'typosquatting': analysis_results.get('typosquatting', {}),
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
    # Threat 8: Direct filter by ownership instead of post-fetch check (IDOR prevention)
    if current_user.is_admin():
        scan = ScanResult.query.filter_by(id=scan_id).first_or_404()
    else:
        scan = ScanResult.query.filter_by(
            id=scan_id, user_id=current_user.id
        ).first_or_404()

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
@limiter.limit('10 per minute; 50 per hour')  # Threat 10: Rate limit expensive export
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

from datetime import datetime, timezone
from models.user import db


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                        nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)

    # Combined final verdict
    final_score = db.Column(db.Float, nullable=False, default=0.0)
    final_label = db.Column(db.String(20), nullable=False, default='Safe')

    # ML result
    ml_score = db.Column(db.Float, nullable=True)

    # VirusTotal
    vt_detections    = db.Column(db.Integer, nullable=True)
    vt_total_engines = db.Column(db.Integer, nullable=True)

    # Google Safe Browsing
    gsb_threat_type = db.Column(db.String(80), nullable=True)

    # WHOIS domain age (days)
    domain_age = db.Column(db.Integer, nullable=True)

    # All 16 extracted features as JSON
    features_json = db.Column(db.Text, nullable=True)

    # Structured explanation JSON (why the score was given)
    explanation_json = db.Column(db.Text, nullable=True)

    recommendation = db.Column(db.Text, nullable=True)
    scanned_at = db.Column(db.DateTime,
                           default=lambda: datetime.now(timezone.utc),
                           index=True)

    user = db.relationship('User', backref=db.backref(
        'scans', lazy='dynamic', cascade='all, delete-orphan'))

    # ── properties ──────────────────────────────────────────

    @property
    def risk_color(self) -> str:
        """Bootstrap colour token for this result."""
        if self.final_score >= 70:
            return 'danger'
        if self.final_score >= 40:
            return 'warning'
        return 'success'

    @property
    def risk_icon(self) -> str:
        icons = {
            'danger':  'fa-circle-xmark',
            'warning': 'fa-triangle-exclamation',
            'success': 'fa-circle-check',
        }
        return icons.get(self.risk_color, 'fa-circle-question')

    @property
    def short_url(self) -> str:
        """Truncate URL for display (max 60 chars)."""
        return self.url if len(self.url) <= 60 else self.url[:57] + '…'

    @property
    def features(self) -> dict:
        import json
        if self.features_json:
            try:
                return json.loads(self.features_json)
            except Exception:
                pass
        return {}

    @property
    def explanation(self) -> dict:
        import json
        if self.explanation_json:
            try:
                return json.loads(self.explanation_json)
            except Exception:
                pass
        return {}

    @property
    def accuracy(self) -> int:
        """Estimate analysis confidence (%) from stored signal columns."""
        acc = 38
        # VT signal
        if self.vt_total_engines and self.vt_total_engines > 0:
            acc += 7
            det = self.vt_detections or 0
            if det >= 10:   acc += 12
            elif det >= 5:  acc += 9
            elif det >= 2:  acc += 6
            elif det >= 1:  acc += 4
        # GSB signal
        if self.gsb_threat_type is not None:
            acc += 8 if self.gsb_threat_type not in ('clean', '') else 5
        # ML agreement
        if self.ml_score is not None:
            ml = self.ml_score
            verdict_high = self.final_score >= 60
            ml_high = ml >= 60
            acc += 8 if (verdict_high == ml_high) else 3
        # Feature data richness
        feat_count = len(self.features)
        if feat_count >= 10:  acc += 8
        elif feat_count >= 5: acc += 4
        # Domain age available
        if self.domain_age is not None and self.domain_age > 0:
            acc += 4
        return min(97, max(40, int(acc)))

    def __repr__(self):
        return f'<ScanResult id={self.id} score={self.final_score} label={self.final_label!r}>'

from datetime import datetime, timezone
import time

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, abort, session, current_app)
from flask_login import (login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import check_password_hash

from extensions import mail, limiter
from models import db, User, UserSession, PrivilegeChange
from routes.auth_forms import (RegistrationForm, LoginForm,
                                ResetRequestForm, ResetPasswordForm,
                                UpdateProfileForm)
from routes.decorators import admin_required
from security.auth_guard import (
    validate_password_strength,
    LoginAttemptTracker,
    anti_enumeration_delay,
)
from security.input_sanitizer import sanitize_string

from flask_mail import Message

# Initialize login attempt tracker
login_tracker = LoginAttemptTracker(db)

# ──────────────────────────────────────────
auth = Blueprint('auth', __name__, url_prefix='/auth')
admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')
# ──────────────────────────────────────────


# ─── helpers ──────────────────────────────

def _record_session(user):
    """Persist a login session record."""
    sess = UserSession(
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:256],
    )
    db.session.add(sess)


def _send_welcome_email(user):
    try:
        msg = Message(
            subject='Welcome to ESEAS',
            sender=mail.default_sender,
            recipients=[user.email],
        )
        msg.html = render_template('emails/welcome.html', user=user)
        mail.send(msg)
    except Exception:
        pass  # email failure must not break registration


def _send_reset_email(user):
    token = user.get_reset_token()
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    try:
        msg = Message(
            subject='ESEAS — Password Reset Request',
            sender=mail.default_sender,
            recipients=[user.email],
        )
        msg.html = render_template('emails/reset.html',
                                   user=user, reset_url=reset_url)
        mail.send(msg)
    except Exception:
        pass


# ─── auth routes ──────────────────────────

@auth.route('/')
def index():
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour')  # Prevent registration spam
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dash.user_dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # ── Validate password strength ─────────────────────────────────
        is_valid, reason = validate_password_strength(form.password.data)
        if not is_valid:
            flash(f'Password too weak: {reason}', 'danger')
            return render_template('auth/register.html', form=form)

        # ── Check if email already exists ──────────────────────────────
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html', form=form)

        # ── Create user with validated inputs ──────────────────────────
        user = User(
            name=sanitize_string(form.name.data.strip(), max_length=120),
            email=form.email.data.lower().strip(),
            role='user',
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        _send_welcome_email(user)

        # Auto-login after registration
        login_user(user)
        user.last_login = datetime.now(timezone.utc)
        _record_session(user)
        db.session.commit()
        session['_ua'] = request.headers.get('User-Agent', '')[:200]
        session['_last_activity'] = datetime.utcnow().isoformat()
        session.modified = True

        flash(f'Welcome to ESEAS, {user.name}! Your account has been created.', 'success')
        return redirect(url_for('user_dash.user_dashboard'))

    return render_template('auth/register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit('15 per minute; 60 per hour')  # Login rate limit
def login():
    if current_user.is_authenticated:
        _dest = ('admin_dash.admin_dashboard' if current_user.is_admin()
                 else 'user_dash.user_dashboard')
        return redirect(url_for(_dest))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data

        # ── Check account lockout ──────────────────────────────────────
        if login_tracker.is_user_locked(email=email):
            anti_enumeration_delay()
            remaining = login_tracker.get_lockout_remaining_time(email=email)
            flash(f'Account temporarily locked. Try again in {remaining} seconds.', 'danger')
            return render_template('auth/login.html', form=form)

        # ── Fetch user (may be None) ──────────────────────────────────
        user = User.query.filter_by(email=email).first()

        # ── Constant-time password check (prevents timing attacks) ──────
        # Always check password even if user not found (prevents enumeration)
        dummy_hash = 'pbkdf2:sha256:260000$dummy$dummydummydummydummydummydummydummydummydummydummydummydummydummy'
        stored_hash = user.password_hash if user else dummy_hash

        password_correct = check_password_hash(stored_hash, password)

        # ── Unified error message (prevents user enumeration) ──────────
        if not user or not password_correct:
            # Record failed attempt
            if user:
                login_tracker.record_failed_attempt(user_id=user.id)

            # Anti-enumeration delay
            anti_enumeration_delay()

            # Same error regardless of whether email exists or password wrong
            flash('Invalid email or password.', 'danger')
            return render_template('auth/login.html', form=form)

        # ── Check if user is active ────────────────────────────────────
        if not user.is_active:
            anti_enumeration_delay()
            flash('Invalid email or password.', 'danger')
            return render_template('auth/login.html', form=form)

        # ── Successful login ───────────────────────────────────────────
        login_tracker.record_successful_login(user.id)
        login_user(user, remember=form.remember_me.data)
        user.last_login = datetime.now(timezone.utc)
        _record_session(user)
        db.session.commit()

        # ── Session Regeneration (Threat 7: prevent session fixation) ────
        session['_ua'] = request.headers.get('User-Agent', '')[:200]
        session['_last_activity'] = datetime.utcnow().isoformat()
        session.modified = True

        flash(f'Welcome back, {user.name}!', 'success')
        return redirect(url_for(
            'admin_dash.admin_dashboard' if user.is_admin() else 'user_dash.user_dashboard'))

    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    # mark latest open session as closed
    sess = (UserSession.query
            .filter_by(user_id=current_user.id, logged_out_at=None)
            .order_by(UserSession.logged_in_at.desc())
            .first())
    if sess:
        sess.logged_out_at = datetime.now(timezone.utc)
        db.session.commit()

    logout_user()
    flash('You have been signed out.', 'info')
    return redirect(url_for('auth.login'))


@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            email=form.email.data.lower().strip()).first()
        if user:
            _send_reset_email(user)
        # always show the same message to prevent email enumeration
        flash('If that email is registered you will receive a reset link shortly.',
              'info')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_request.html', form=form)


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    user = User.verify_reset_token(token)
    if not user:
        flash('The reset link is invalid or has expired (30-minute limit).', 'warning')
        return redirect(url_for('auth.reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        # ── Validate password strength ─────────────────────────────────
        is_valid, reason = validate_password_strength(form.password.data)
        if not is_valid:
            flash(f'Password too weak: {reason}', 'danger')
            return render_template('auth/reset_password.html', form=form)

        user.set_password(form.password.data)
        user.failed_login_attempts = 0  # Reset lockout on password change
        user.locked_until = None
        db.session.commit()
        flash('Your password has been updated. Please sign in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', form=form)


@auth.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')

    if not check_password_hash(current_user.password_hash, current_pw):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('auth.profile'))

    if new_pw != confirm_pw:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('auth.profile'))

    is_valid, reason = validate_password_strength(new_pw)
    if not is_valid:
        flash(f'Password too weak: {reason}', 'danger')
        return redirect(url_for('auth.profile'))

    current_user.set_password(new_pw)
    current_user.failed_login_attempts = 0
    db.session.commit()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('auth.profile'))


@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm(original_email=current_user.email,
                             obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data.strip()
        current_user.email = form.email.data.lower().strip()
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('auth.profile'))

    recent_sessions = (UserSession.query
                       .filter_by(user_id=current_user.id)
                       .order_by(UserSession.logged_in_at.desc())
                       .limit(5).all())

    return render_template('auth/profile.html',
                           form=form,
                           recent_sessions=recent_sessions)


# ─── admin routes ─────────────────────────

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    privilege_changes = PrivilegeChange.query.order_by(
        PrivilegeChange.timestamp.desc()
    ).limit(20).all()
    return render_template('admin/users.html', users=all_users, privilege_changes=privilege_changes)


@admin_bp.route('/users/<int:user_id>/profile')
@login_required
@admin_required
def user_profile(user_id):
    user = db.get_or_404(User, user_id)
    recent_sessions = (UserSession.query
                       .filter_by(user_id=user.id)
                       .order_by(UserSession.logged_in_at.desc())
                       .limit(5).all())
    return render_template('admin/user_detail.html',
                           target_user=user,
                           recent_sessions=recent_sessions)


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't deactivate your own account.", 'warning')
        return redirect(url_for('admin_bp.users'))
    if user.is_primary_admin:
        flash("The primary admin account cannot be deactivated.", 'danger')
        return redirect(url_for('admin_bp.users'))
    user.is_active = not user.is_active
    db.session.commit()
    state = 'activated' if user.is_active else 'deactivated'
    flash(f'{user.name} has been {state}.', 'success')
    return redirect(url_for('admin_bp.users'))


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    # Only primary admin can change roles (restrict to dedicated revoke/promote endpoints)
    if not current_user.is_primary_admin:
        flash("Only the primary admin can change user roles.", 'danger')
        return redirect(url_for('admin_bp.users'))

    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't change your own role.", 'warning')
        return redirect(url_for('admin_bp.users'))

    old_role = user.role
    new_role = request.form.get('role', 'user')
    if new_role not in ('user', 'admin'):
        abort(400)

    user.role = new_role

    # Record privilege change based on direction
    if old_role == 'user' and new_role == 'admin':
        user.promoted_by = current_user.id
        user.promoted_at = datetime.now(timezone.utc)
        action = 'promoted'
    elif old_role == 'admin' and new_role == 'user':
        user.demoted_at = datetime.now(timezone.utc)
        action = 'demoted'
    else:
        action = None

    db.session.commit()

    if action:
        privilege_change = PrivilegeChange(
            user_id=user_id,
            changed_by=current_user.id,
            action=action
        )
        db.session.add(privilege_change)
        db.session.commit()
        current_app.logger.info(f"User {current_user.id} {action} user {user_id}")

    flash(f"{user.name}'s role changed to {new_role}.", 'success')
    return redirect(url_for('admin_bp.users'))


@admin_bp.route('/users/<int:user_id>/promote-admin', methods=['POST'])
@login_required
@admin_required
def promote_admin(user_id):
    """Promote a regular user to admin. Only primary admin can do this."""
    if not current_user.is_primary_admin:
        flash("Only the primary admin can promote users to admin.", 'danger')
        return redirect(url_for('admin_bp.users'))

    user = db.get_or_404(User, user_id)

    if user.role == 'admin':
        flash(f"{user.name} is already an admin.", 'warning')
        return redirect(url_for('admin_bp.users'))

    # Promote the user
    user.role = 'admin'
    user.promoted_by = current_user.id
    user.promoted_at = datetime.now(timezone.utc)
    user.demoted_at = None  # Clear any previous demotion

    db.session.commit()

    # Record privilege change
    privilege_change = PrivilegeChange(
        user_id=user_id,
        changed_by=current_user.id,
        action='promoted',
        reason=request.form.get('reason', '') if request.form else ''
    )
    db.session.add(privilege_change)
    db.session.commit()

    current_app.logger.info(f"User {current_user.id} promoted user {user_id} to admin")
    flash(f"{user.name} has been promoted to admin.", 'success')
    return redirect(url_for('admin_bp.users'))


@admin_bp.route('/users/<int:user_id>/revoke-admin', methods=['POST'])
@login_required
@admin_required
def revoke_admin(user_id):
    """Revoke admin privileges from a user. Only primary admin can do this."""
    if not current_user.is_primary_admin:
        flash("Only the primary admin can revoke admin privileges.", 'danger')
        return redirect(url_for('admin_bp.users'))

    user = db.get_or_404(User, user_id)

    if user.is_primary_admin:
        flash("Cannot revoke admin privileges from the primary admin.", 'danger')
        return redirect(url_for('admin_bp.users'))

    if user.role != 'admin':
        flash(f"{user.name} is not currently an admin.", 'warning')
        return redirect(url_for('admin_bp.users'))

    # Demote the user
    user.role = 'user'
    user.demoted_at = datetime.now(timezone.utc)

    db.session.commit()

    # Record privilege change
    privilege_change = PrivilegeChange(
        user_id=user_id,
        changed_by=current_user.id,
        action='demoted',
        reason=request.form.get('reason', '') if request.form else ''
    )
    db.session.add(privilege_change)
    db.session.commit()

    current_app.logger.info(f"User {current_user.id} revoked admin privileges from user {user_id}")
    flash(f"{user.name} has been demoted to regular user.", 'success')
    return redirect(url_for('admin_bp.users'))

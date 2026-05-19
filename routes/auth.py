from datetime import datetime, timezone

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, abort)
from flask_login import (login_user, logout_user,
                         login_required, current_user)

from extensions import mail, limiter
from models import db, User, UserSession
from routes.auth_forms import (RegistrationForm, LoginForm,
                                ResetRequestForm, ResetPasswordForm,
                                UpdateProfileForm)
from routes.decorators import admin_required

from flask_mail import Message

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
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data.strip(),
            email=form.email.data.lower().strip(),
            role='user',
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        _send_welcome_email(user)
        flash('Account created! Please sign in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if current_user.is_authenticated:
        _dest = ('admin_dash.admin_dashboard' if current_user.is_admin()
                 else 'dashboard.index')
        return redirect(url_for(_dest))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            email=form.email.data.lower().strip()).first()

        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.now(timezone.utc)
            _record_session(user)
            db.session.commit()

            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for(
                'admin_dash.admin_dashboard' if user.is_admin() else 'dashboard.index'))

        flash('Invalid email or password.', 'danger')

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
    return redirect(url_for('index'))


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
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated. Please sign in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', form=form)


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
    return render_template('admin/users.html', users=all_users)


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
    user.is_active = not user.is_active
    db.session.commit()
    state = 'activated' if user.is_active else 'deactivated'
    flash(f'{user.name} has been {state}.', 'success')
    return redirect(url_for('admin_bp.users'))


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't change your own role.", 'warning')
        return redirect(url_for('admin_bp.users'))
    new_role = request.form.get('role', 'user')
    if new_role not in ('user', 'admin'):
        abort(400)
    user.role = new_role
    db.session.commit()
    flash(f"{user.name}'s role changed to {new_role}.", 'success')
    return redirect(url_for('admin_bp.users'))

from app import app
from models import db, User


def seed():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email='admin@eseas.dev').first():
            admin = User(name='Admin User', email='admin@eseas.dev', role='admin')
            admin.set_password('Admin@1234')
            db.session.add(admin)
            print('Created admin user: admin@eseas.dev / Admin@1234')

        if not User.query.filter_by(email='user@eseas.dev').first():
            user = User(name='Test User', email='user@eseas.dev', role='user')
            user.set_password('User@1234')
            db.session.add(user)
            print('Created test user: user@eseas.dev / User@1234')

        db.session.commit()
        print('Database seeded successfully.')


if __name__ == '__main__':
    seed()

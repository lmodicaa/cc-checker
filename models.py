from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Config(db.Model):
    """Configuración del sistema"""
    __tablename__ = 'config'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Config {self.key}={self.value}>'

class User(db.Model):
    """Usuarios con keys de acceso"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    checks_today = db.Column(db.Integer, default=0, nullable=False)
    last_check_date = db.Column(db.Date, nullable=True)
    max_checks = db.Column(db.Integer, default=50, nullable=False)  # Límite personalizado por key
    device_fingerprint = db.Column(db.String(255), nullable=True)
    last_ip = db.Column(db.String(45), nullable=True)
    
    # Relación con historial
    checks = db.relationship('CheckHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.name} ({self.key[:20]}...)>'

class CheckHistory(db.Model):
    """Historial de verificaciones de tarjetas"""
    __tablename__ = 'check_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    payment_method_id = db.Column(db.String(100), nullable=True)
    card_last4 = db.Column(db.String(4), nullable=True)
    card_brand = db.Column(db.String(20), nullable=True)
    card_type = db.Column(db.String(20), nullable=True)
    card_country = db.Column(db.String(2), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # approved, declined, error
    mode = db.Column(db.String(10), default='auth', nullable=False)  # auth, charge
    error_code = db.Column(db.String(100), nullable=True)
    response_time = db.Column(db.Float, nullable=True)  # en segundos
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<CheckHistory {self.id} - {self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'card_last4': self.card_last4,
            'card_brand': self.card_brand,
            'status': self.status,
            'mode': self.mode,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'response_time': self.response_time
        }



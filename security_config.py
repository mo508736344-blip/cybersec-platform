"""
إعدادات الأمان والحماية للمنصة
"""

import os
import hashlib
import secrets
from datetime import datetime, timedelta

class SecurityConfig:
    """إعدادات الأمان الرئيسية"""
    
    # مفاتيح التشفير
    SECRET_KEY = secrets.token_hex(32)
    
    # إعدادات كلمات المرور
    PASSWORD_HASHES = {
        hashlib.sha256("cybersec2024".encode()).hexdigest(): "admin",
        hashlib.sha256("security123".encode()).hexdigest(): "user", 
        hashlib.sha256("learning456".encode()).hexdigest(): "guest"
    }
    
    # إعدادات الجلسة
    SESSION_TIMEOUT = 3600  # ساعة واحدة
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 دقائق
    
    # إعدادات التسجيل
    LOG_FILE = "security_logs.json"
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    
    # إعدادات الشبكة
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
    DEFAULT_PORT = 5000
    
    # رسائل الأمان
    SECURITY_MESSAGES = {
        'unauthorized': 'غير مصرح لك بالوصول لهذه الصفحة',
        'session_expired': 'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مرة أخرى',
        'too_many_attempts': 'تم حظرك مؤقتاً بسبب كثرة المحاولات الخاطئة',
        'educational_only': 'هذه الأداة للأغراض التعليمية فقط'
    }
    
    @staticmethod
    def validate_password(password):
        """التحقق من صحة كلمة المرور"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return SecurityConfig.PASSWORD_HASHES.get(password_hash)
    
    @staticmethod
    def is_session_valid(login_time):
        """التحقق من صلاحية الجلسة"""
        if not login_time:
            return False
        
        session_age = datetime.now().timestamp() - login_time
        return session_age < SecurityConfig.SESSION_TIMEOUT
    
    @staticmethod
    def log_security_event(event_type, details=None):
        """تسجيل الأحداث الأمنية"""
        import json
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details or {},
            'user': os.getenv('USERNAME', 'unknown'),
            'computer': os.getenv('COMPUTERNAME', 'unknown')
        }
        
        try:
            with open(SecurityConfig.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        except Exception:
            pass  # فشل التسجيل لا يجب أن يوقف التطبيق

class AntiTampering:
    """حماية من التلاعب"""
    
    @staticmethod
    def check_file_integrity():
        """فحص سلامة الملفات المهمة"""
        critical_files = ['app.py', 'protected_core.py', 'security_config.py']
        
        for file in critical_files:
            if not os.path.exists(file):
                return False, f"ملف مفقود: {file}"
        
        return True, "جميع الملفات سليمة"
    
    @staticmethod
    def obfuscate_sensitive_data(data):
        """إخفاء البيانات الحساسة"""
        if isinstance(data, str):
            if len(data) > 6:
                return data[:3] + "*" * (len(data) - 6) + data[-3:]
            else:
                return "*" * len(data)
        return data

class RateLimiter:
    """محدد معدل الطلبات"""
    
    def __init__(self):
        self.attempts = {}
        self.blocked_ips = {}
    
    def is_allowed(self, ip_address):
        """التحقق من السماح للـ IP"""
        current_time = datetime.now()
        
        # فحص الحظر
        if ip_address in self.blocked_ips:
            if current_time < self.blocked_ips[ip_address]:
                return False
            else:
                del self.blocked_ips[ip_address]
        
        # فحص عدد المحاولات
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        
        # إزالة المحاولات القديمة
        self.attempts[ip_address] = [
            attempt for attempt in self.attempts[ip_address]
            if current_time - attempt < timedelta(minutes=15)
        ]
        
        # فحص تجاوز الحد المسموح
        if len(self.attempts[ip_address]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
            self.blocked_ips[ip_address] = current_time + timedelta(
                seconds=SecurityConfig.LOCKOUT_DURATION
            )
            return False
        
        return True
    
    def record_attempt(self, ip_address):
        """تسجيل محاولة جديدة"""
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        
        self.attempts[ip_address].append(datetime.now())

# إنشاء instance عام
rate_limiter = RateLimiter()

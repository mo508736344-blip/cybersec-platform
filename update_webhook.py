#!/usr/bin/env python3
"""
تحديث سريع لرفع التعديلات على GitHub
"""

import os
import subprocess

def update_github():
    """رفع التحديثات على GitHub"""
    
    print("🔄 جاري رفع التحديثات...")
    
    try:
        # إضافة الملفات المحدثة
        subprocess.run(['git', 'add', 'app.py'], check=True)
        
        # إنشاء commit
        subprocess.run(['git', 'commit', '-m', 'Update webhook functionality for visitor tracking'], check=True)
        
        # رفع على GitHub
        subprocess.run(['git', 'push'], check=True)
        
        print("✅ تم رفع التحديثات بنجاح!")
        print("🔄 Render سيقوم بإعادة النشر تلقائياً خلال دقائق")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ خطأ في Git: {e}")
        print("💡 جرب رفع الملف يدوياً على GitHub")
    except FileNotFoundError:
        print("❌ Git غير مثبت")
        print("💡 ارفع ملف app.py يدوياً على GitHub")

if __name__ == "__main__":
    update_github()

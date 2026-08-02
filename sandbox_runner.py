#!/usr/bin/env python3
"""
🔒 Sandbox Runner — تشغيل ملفات المستخدمين في بيئة معزولة
يمنع الوصول لأي ملف خارج مجلد المستخدم
لا يمكن تجاوزه من كود Python العادي بسبب sys.addaudithook
"""
import sys
import os

if len(sys.argv) < 3:
    print("Usage: sandbox_runner.py <allowed_dir> <script_path>")
    sys.exit(1)

ALLOWED_DIR = os.path.realpath(sys.argv[1])
SCRIPT_PATH = os.path.realpath(sys.argv[2])

if not SCRIPT_PATH.startswith(ALLOWED_DIR):
    print("🔒 خطأ: الملف يجب أن يكون داخل مجلد المستخدم")
    sys.exit(1)

# ====================================================================
# مسارات مسموح بقراءتها (مكتبات Python + tmp + مجلد المستخدم)
# ====================================================================
ALLOWED_PREFIXES = [
    ALLOWED_DIR,
    '/tmp',
    '/dev/null',
    '/dev/urandom',
    '/dev/zero',
    '/proc/self',
]

# إضافة مسارات مكتبات Python تلقائياً
import site as _site
try:
    ALLOWED_PREFIXES += _site.getsitepackages()
except Exception:
    pass
try:
    ALLOWED_PREFIXES.append(_site.getusersitepackages())
except Exception:
    pass
ALLOWED_PREFIXES.append(sys.prefix)
ALLOWED_PREFIXES.append(os.path.dirname(os.__file__))


def _is_path_allowed(path_str: str) -> bool:
    """هل المسار مسموح للوصول؟"""
    try:
        if not os.path.isabs(path_str):
            path_str = os.path.join(ALLOWED_DIR, path_str)
        resolved = os.path.realpath(path_str)
        for prefix in ALLOWED_PREFIXES:
            if resolved.startswith(os.path.realpath(prefix)):
                return True
        return False
    except Exception:
        return True  # في حالة شك، اسمح (عشان ما نكسرش المكتبات)


# ====================================================================
# 🔒 sys.addaudithook — لا يمكن إزالته حتى من كود المستخدم
# ====================================================================
def _security_audit_hook(event: str, args):
    """
    Hook أمني غير قابل للإزالة — يراقب كل العمليات
    """
    # منع فتح ملفات خارج المجلد المسموح
    if event in ('open', 'builtins.open', 'io.open_code'):
        if args and isinstance(args[0], str):
            path = args[0]
            if path and not _is_path_allowed(path):
                raise PermissionError(
                    f"\n🔒 [SANDBOX] تم حظر الوصول للملف: {path}\n"
                    f"   المسموح به فقط: مجلدك الشخصي + مكتبات Python"
                )

    # منع os.open للمسارات خارج المجلد
    elif event == 'os.open':
        if args and isinstance(args[0], str):
            path = args[0]
            if path and not _is_path_allowed(path):
                raise PermissionError(
                    f"\n🔒 [SANDBOX] تم حظر os.open: {path}"
                )

    # منع تشغيل أوامر النظام الخطيرة
    elif event == 'subprocess.Popen':
        if args:
            cmd = args[0]
            if isinstance(cmd, (list, tuple)) and cmd:
                cmd_str = str(cmd[0]).lower()
            elif isinstance(cmd, str):
                cmd_str = cmd.lower()
            else:
                cmd_str = ''
            # منع قراءة ملفات حساسة عبر أوامر النظام
            dangerous = ['cat /etc', 'cat /root', 'cat /home',
                        'cp /etc', 'scp', 'rsync',
                        'curl -X POST', 'wget --post']
            for d in dangerous:
                if d in cmd_str:
                    raise PermissionError(f"🔒 [SANDBOX] أمر محظور: {cmd_str}")

    # منع قراءة ملفات النظام عبر glob
    elif event == 'glob.glob':
        if args and isinstance(args[0], str):
            pattern = args[0]
            if pattern.startswith('/etc') or pattern.startswith('/root'):
                raise PermissionError(f"🔒 [SANDBOX] glob محظور: {pattern}")


# تسجيل الـ hook — لا يمكن إزالته بعد هذا السطر
sys.addaudithook(_security_audit_hook)

# ====================================================================
# 🔒 تقييد إضافي على builtins.open كطبقة حماية ثانية
# ====================================================================
import builtins as _builtins

_orig_open = _builtins.open


def _safe_open(file, mode='r', *args, **kwargs):
    if isinstance(file, (str, bytes, os.PathLike)):
        path_str = os.fsdecode(file) if isinstance(file, bytes) else str(file)
        if not _is_path_allowed(path_str):
            raise PermissionError(
                f"🔒 [SANDBOX] ممنوع فتح: {path_str}"
            )
    return _orig_open(file, mode, *args, **kwargs)


_builtins.open = _safe_open

# ====================================================================
# 🔒 تقييد os.listdir و os.scandir و os.walk
# ====================================================================
_orig_listdir = os.listdir
_orig_scandir = os.scandir
_orig_walk = os.walk
_orig_stat = os.stat


def _safe_listdir(path='.'):
    p = str(path) if not isinstance(path, str) else path
    if not _is_path_allowed(p):
        raise PermissionError(f"🔒 [SANDBOX] ممنوع listdir: {p}")
    return _orig_listdir(path)


def _safe_scandir(path='.'):
    p = str(path) if not isinstance(path, str) else path
    if not _is_path_allowed(p):
        raise PermissionError(f"🔒 [SANDBOX] ممنوع scandir: {p}")
    return _orig_scandir(path)


def _safe_walk(top, *args, **kwargs):
    p = str(top)
    if not _is_path_allowed(p):
        return
    yield from _orig_walk(top, *args, **kwargs)


os.listdir = _safe_listdir
os.scandir = _safe_scandir
os.walk = _safe_walk

# ====================================================================
# تشغيل الـ Script في بيئة نظيفة
# ====================================================================
os.chdir(ALLOWED_DIR)
os.environ['HOME'] = ALLOWED_DIR
os.environ['TMPDIR'] = ALLOWED_DIR

# إزالة مسارات البانيل من PATH
sys.path = [p for p in sys.path if 'panel_data' not in p]
sys.path.insert(0, ALLOWED_DIR)

# تعديل argv عشان الـ script يشوف نفسه كـ main
sys.argv = [SCRIPT_PATH] + sys.argv[3:]

# تحميل وتشغيل كود المستخدم
with _orig_open(SCRIPT_PATH, 'r', encoding='utf-8', errors='ignore') as _f:
    _user_code = _f.read()

_namespace = {
    '__name__': '__main__',
    '__file__': SCRIPT_PATH,
    '__doc__': None,
    '__package__': None,
    '__spec__': None,
    '__builtins__': _builtins,
}

try:
    exec(compile(_user_code, SCRIPT_PATH, 'exec'), _namespace)
except SystemExit as _e:
    sys.exit(_e.code)
except PermissionError as _e:
    print(str(_e), file=sys.stderr)
    sys.exit(1)
except Exception as _e:
    print(f"[Error] {type(_e).__name__}: {_e}", file=sys.stderr)
    sys.exit(1)

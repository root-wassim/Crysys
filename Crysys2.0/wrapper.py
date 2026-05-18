"""
wrapper.py — Crysys 2.0 Python-to-C Bridge
Wraps subprocess calls to the compiled crysys_cli.exe engine.
"""
import os
import subprocess
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_PATH = os.path.join(BASE_DIR, "engine", "crysys_cli.exe")


def _run_cli(*args, stdin_data=None, timeout=30):
    """Run the CLI and return (stdout, stderr, returncode)."""
    cmd = [CLI_PATH] + list(args)
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=BASE_DIR,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Operation timed out", 1
    except FileNotFoundError:
        return "", f"crysys_cli.exe not found. Run build.py first.", 1
    except Exception as e:
        return "", str(e), 1


def encrypt_text(algo: str, text: str, key: str = "", **kwargs) -> dict:
    """Encrypt plain text using the specified algorithm."""
    args = ["-a", algo, "-m", "encrypt"]
    if key:
        args += ["-k", key]
    _add_extra_args(args, algo, kwargs)
    stdout, stderr, code = _run_cli(*args, stdin_data=text)
    if code != 0 or not stdout:
        return {"success": False, "error": stderr or "Unknown error", "output": ""}
    return {"success": True, "output": stdout, "error": ""}


def decrypt_text(algo: str, text: str, key: str = "", **kwargs) -> dict:
    """Decrypt cipher text using the specified algorithm."""
    args = ["-a", algo, "-m", "decrypt"]
    if key:
        args += ["-k", key]
    _add_extra_args(args, algo, kwargs)
    stdout, stderr, code = _run_cli(*args, stdin_data=text)
    if code != 0 or not stdout:
        return {"success": False, "error": stderr or "Unknown error", "output": ""}
    return {"success": True, "output": stdout, "error": ""}


def hash_text(algo: str, text: str) -> dict:
    """Hash text using md5 or sha256."""
    args = ["-a", algo, "-m", "hash"]
    stdout, stderr, code = _run_cli(*args, stdin_data=text)
    if code != 0 or not stdout:
        return {"success": False, "error": stderr or "Unknown error", "output": ""}
    return {"success": True, "output": stdout, "error": ""}


def keygen(algo: str, **kwargs) -> dict:
    """Generate keys for asymmetric algorithms."""
    args = ["-a", algo, "-m", "keygen"]
    if kwargs.get("prime"):
        args += ["-q", str(kwargs["prime"])]
    if kwargs.get("generator"):
        args += ["-g", str(kwargs["generator"])]
    stdout, stderr, code = _run_cli(*args)
    if code != 0 or not stdout:
        return {"success": False, "error": stderr or "Unknown error", "output": ""}
    return {"success": True, "output": stdout, "error": ""}


def analyze_text(algo: str, text: str, **kwargs) -> dict:
    """Run cryptanalysis on text."""
    args = ["-a", algo, "-m", "analyze"]
    if kwargs.get("key_len"):
        args += ["-l", str(kwargs["key_len"])]
    if kwargs.get("probable_word"):
        args += ["-w", kwargs["probable_word"]]
    stdout, stderr, code = _run_cli(*args, stdin_data=text)
    if code != 0 or not stdout:
        return {"success": False, "error": stderr or "Unknown error", "output": ""}
    return {"success": True, "output": stdout, "error": ""}


def encrypt_file(algo: str, file_bytes: bytes, key: str = "", **kwargs) -> dict:
    """Encrypt file contents."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f_in:
        f_in.write(file_bytes)
        in_path = f_in.name
    out_path = in_path + ".enc"
    try:
        args = ["-a", algo, "-m", "encrypt", "-i", in_path, "-o", out_path]
        if key:
            args += ["-k", key]
        _add_extra_args(args, algo, kwargs)
        stdout, stderr, code = _run_cli(*args)
        if os.path.exists(out_path):
            with open(out_path, "rb") as f:
                return {"success": True, "output": f.read().decode("utf-8", errors="replace"), "error": ""}
        elif stdout:
            return {"success": True, "output": stdout, "error": ""}
        else:
            return {"success": False, "error": stderr or "No output produced", "output": ""}
    finally:
        for p in [in_path, out_path]:
            if os.path.exists(p):
                os.unlink(p)


def decrypt_file(algo: str, file_bytes: bytes, key: str = "", **kwargs) -> dict:
    """Decrypt file contents."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f_in:
        f_in.write(file_bytes)
        in_path = f_in.name
    out_path = in_path + ".dec"
    try:
        args = ["-a", algo, "-m", "decrypt", "-i", in_path, "-o", out_path]
        if key:
            args += ["-k", key]
        _add_extra_args(args, algo, kwargs)
        stdout, stderr, code = _run_cli(*args)
        if os.path.exists(out_path):
            with open(out_path, "rb") as f:
                return {"success": True, "output": f.read().decode("utf-8", errors="replace"), "error": ""}
        elif stdout:
            return {"success": True, "output": stdout, "error": ""}
        else:
            return {"success": False, "error": stderr or "No output produced", "output": ""}
    finally:
        for p in [in_path, out_path]:
            if os.path.exists(p):
                os.unlink(p)


def _add_extra_args(args: list, algo: str, kwargs: dict):
    """Append algorithm-specific CLI arguments."""
    if algo == "caesar":
        args += ["-s", str(kwargs.get("shift", 3))]
    elif algo == "affine":
        args += ["-p", str(kwargs.get("a_param", 1)), "-b", str(kwargs.get("b_param", 0))]
    elif algo == "hill":
        args += ["-n", str(kwargs.get("matrix_size", 2))]
    if kwargs.get("prime"):
        args += ["-q", str(kwargs["prime"])]
    if kwargs.get("generator"):
        args += ["-g", str(kwargs["generator"])]


def engine_available() -> bool:
    """Check if the compiled engine exists."""
    return os.path.isfile(CLI_PATH)

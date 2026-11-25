"""slacktokens.py :: Extract personal tokens and authentication cookie from the Slack app.

A tool for providing programmatic access to the [Slack](https://slack.com/) ecosystem.
This project is not endorsed or authorised in any way by Slack Technologies LLC.

The Slack API is how all Slack clients, including the official desktop app and third-party
bots, read and write data that constitutes the Slack user experience. All clients much
provide authorisation to access the API.

As of July 2021, individual user access to the Slack API (as opposed to bot access) is
granted by providing a personal token (beginning with `xoxc-`) and a cookie called `d`.
Each Slack Workspace has its own personal token, but the cookie is the same for all.

If you use the Slack desktop app, these details will be stored on your local machine.
This script extracts them from the app's local store so you can use them for purposes not
provided for by the app itself.

Calling `get_tokens_and_cookie()` will return the necessary authorisation details as a
Python dictionary, in the following format:

```
{
  'tokens': [
    'Workspace URL': { token: <personal-token>, name: <friendly name of Workspace> }
    ]
  'cookie': { 'name': 'd', 'value': <value-of-d-cookie> }
}
```

The tokens are extracted by querying the Slack app's HTML Web Storage database. The tokens
are stored in the `localStorage` object, in a `LevelDB` database.

The cookie is extracted from the Slack app's cookie store. The cookie of interest is
stored encrypted, so a modified version of `pycookiecheat` is used to decrypt the
contents. The decryption process will prompt you for your user password, which is used
only to pull out the cookie store encryption secret from your keychain.

"""

__author__ = "Heath Raftery <heath@empirical.ee>"

def _parse_local_config(raw):
  import json

  if not raw:
    raise ValueError("localConfig is empty")

  # Chromium localStorage values often include a one-byte prefix.
  if raw[:1] in (b"\x00", b"\x01", b"\x02"):
    data = raw[1:]
  else:
    data = raw

  # If there are lots of NUL bytes, it's likely UTF-16LE.
  if data.count(0) > len(data) // 4:
    encodings = ("utf-16-le", "utf-8")
  else:
    encodings = ("utf-8", "utf-16-le")

  last_err = None
  for enc in encodings:
    try:
      text = data.decode(enc)
    except UnicodeDecodeError as e:
      last_err = e
      continue

    # Strict first, then relaxed to allow control characters in strings.
    for strict in (True, False):
      try:
        return json.loads(text, strict=strict)
      except json.JSONDecodeError as e:
        last_err = e

    # Some formats wrap or pad the JSON; attempt to extract the object.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
      snippet = text[start:end + 1]
      for strict in (True, False):
        try:
          return json.loads(snippet, strict=strict)
        except json.JSONDecodeError as e:
          last_err = e

  if last_err:
    raise last_err
  raise ValueError("localConfig not parseable")

def get_tokens_and_cookie():
  """Return a dictionary containing the Slack personal tokens and cookie."""
  return { 'tokens': get_tokens(), 'cookie': get_cookie() }

def get_tokens(use_copy=True):
  """Return a dictionary containing the token and name for each Slack Workspace.

  Args:
    use_copy: If True (default), copy the LevelDB to a temporary directory
              before opening it and delete the copy afterwards. This avoids
              lock conflicts when Slack is running. Set to False to open the
              live database directly, which requires Slack to be quit first.
  """
  import leveldb
  import sys
  import pathlib
  import shutil
  import tempfile

  if sys.platform == "darwin":
    # leveldb location in MacOS depends on whether the application was installed from
    # the App Store or direct download. To find out, we simply check for existence.
    LEVELDB_PATH='~/Library/Application Support/Slack/Local Storage/leveldb'
    if not pathlib.Path(LEVELDB_PATH).expanduser().exists():
      LEVELDB_PATH='~/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/Local Storage/leveldb'
  elif sys.platform.startswith("linux"):
    LEVELDB_PATH='~/.config/Slack/Local Storage/leveldb'
  else:
    raise OSError("slacktokens only works on macOS or Linux.")

  src = pathlib.Path(LEVELDB_PATH).expanduser()
  tmpdir = None

  if use_copy:
    tmpdir = tempfile.mkdtemp(prefix="slacktokens-")
    db_path = pathlib.Path(tmpdir) / src.name
    shutil.copytree(src, db_path)
  else:
    db_path = src

  db = None
  try:
    db = leveldb.LevelDB(str(db_path))
  except Exception as e:
    if "lock" in str(e):
      raise RuntimeError("Slack's Local Storage database appears to be locked. Have you quit Slack?") from e
    else:
      raise
  else:
    try:
      cfg = next(v for k,v in db.RangeIter() if bytearray(b'localConfig_v2') in k)
    except StopIteration as e:
      raise RuntimeError("Slack's Local Storage not recognised: localConfig not found. Aborting.") from e

    try:
      d = _parse_local_config(cfg)
    except Exception as e:
      raise RuntimeError("Slack's Local Storage not recognised: localConfig not in expected format. Aborting.") from e

    tokens = {}
    for v in d['teams'].values():
      tokens[v['url']] = { 'token': v['token'], 'name': v['name'] }

    return tokens
  finally:
    if db:
      del db # attempt to clean up our lock
    if tmpdir:
      shutil.rmtree(tmpdir, ignore_errors=True)


def get_cookie():
  """Return a dictionary containing the name and value of the authentication cookie."""
  import sys

  # On Linux, decrypt the cookie ourselves via the libsecret `secret-tool` CLI
  # instead of going through pycookiecheat. pycookiecheat's only reliable Linux
  # keyring path needs system PyGObject (`gi`), which can't be pip-installed into
  # an isolated venv (e.g. `uv run`, pipx). Without it, pycookiecheat silently
  # falls back to the hard-coded "peanuts" default key and mis-decrypts the
  # cookie (UnicodeDecodeError on the resulting garbage). For a keyring-encrypted
  # (v11) cookie, secret-tool reads the real "Slack Safe Storage" secret directly.
  if sys.platform.startswith("linux"):
    return { 'name': 'd', 'value': _get_linux_cookie_value() }

  # macOS: pycookiecheat talks to the Keychain via the `security` binary, which
  # works fine without any extra system bindings.
  import pycookiecheat
  cookies = pycookiecheat.chrome_cookies("http://slack.com", browser="Slack")

  return { 'name': 'd', 'value': cookies['d'] }


def _get_linux_cookie_value():
  """Decrypt Slack's `d` cookie on Linux using the libsecret keyring secret.

  Slack (Electron/Chromium) stores the `d` cookie AES-128-CBC encrypted in
  ~/.config/Slack/Cookies. The key is PBKDF2(secret, "saltysalt", 1, 16). The
  prefix names the secret: "v10" is Chromium's fixed "peanuts", used when the app
  runs without a keyring (the basic password store); "v11" is the "Slack Safe
  Storage" password in the login keyring. Newer Chromium (cookie DB version >= 24)
  also prepends a 32-byte SHA256(host_key) to the plaintext, which must be stripped.
  """
  import hashlib
  import pathlib
  import shutil
  import sqlite3
  import subprocess
  import tempfile
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

  cookies_db = pathlib.Path("~/.config/Slack/Cookies").expanduser()
  if not cookies_db.exists():
    raise RuntimeError(f"Slack cookie database not found at {cookies_db}.")

  with tempfile.TemporaryDirectory(prefix="slacktokens-") as tmp:
    tmp_db = pathlib.Path(tmp) / "Cookies"
    shutil.copy2(cookies_db, tmp_db)  # copy to dodge the running app's SQLite lock
    con = sqlite3.connect(str(tmp_db))
    try:
      row = con.execute("SELECT encrypted_value FROM cookies "
                        "WHERE name='d' AND host_key='.slack.com'").fetchone()
      ver = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
    finally:
      con.close()

  if not row:
    raise RuntimeError("No `d` cookie for .slack.com found. Sign in to the Slack app.")
  encrypted = row[0]
  db_version = int(ver[0]) if ver else 0

  prefix = encrypted[:3]
  if prefix == b"v10":
    password = b"peanuts"
  elif prefix == b"v11":
    if not shutil.which("secret-tool"):
      raise RuntimeError("`secret-tool` not found. Install libsecret-tools (Debian/Ubuntu) "
                         "or libsecret (Arch/Fedora) to read the Slack keyring secret.")
    try:
      password = subprocess.check_output(
        ["secret-tool", "lookup", "application", "Slack"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      password = b""
    if not password:
      raise RuntimeError("No 'Slack Safe Storage' secret found in the keyring. Has the Slack "
                         "desktop app run at least once, and is your login keyring unlocked?")
  else:
    raise RuntimeError(f"Unexpected cookie encryption prefix {prefix!r}; expected v10/v11.")

  key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
  decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
  decrypted = decryptor.update(encrypted[3:]) + decryptor.finalize()
  decrypted = decrypted[:-decrypted[-1]]  # strip PKCS7 padding
  if db_version >= 24:
    decrypted = decrypted[32:]  # strip SHA256(host_key) domain-bound prefix
  try:
    return decrypted.decode("utf8")
  except UnicodeDecodeError as e:
    raise RuntimeError("Decrypted cookie is not valid text (wrong key). If you recently "
                       "reinstalled Slack, unlock your login keyring and retry.") from e

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import errno
import grp
import hashlib
import hmac
import json
import logging
import os
import platform
import pwd
import random
import re
import shutil
import stat
import string
import subprocess
import time
import types
from datetime import datetime

import OpenSSL
from six import iteritems

import errors

logger = logging.getLogger(__name__)


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise errors.Error(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def chown(path, user, group=None, follow_symlinks=False):
    """
    Changes the ownership of the path.
    :param path:
    :param user:
    :param group:
    :return:
    """
    if group is None:
        group = user

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given file by copying it to a new file
    Copy is preferred to move. Move can keep processes working with the opened file after move operation.

    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        with open(path, 'r') as src:
            fhnd, fname = unique_file(backup_path, chmod)
            with fhnd:
                shutil.copyfileobj(src, fhnd)
                backup_path = fname
    return backup_path


def dir_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given directory
    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        backup_path = safe_new_dir(backup_path, mode=chmod)
        os.rmdir(backup_path)
        shutil.copytree(path, backup_path)
    return backup_path


def delete_file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the current file by moving it to a new file
    :param path:
    :param mode:
    :param chmod:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = file_backup(path, chmod=chmod, backup_dir=backup_dir)
        os.remove(path)
    return backup_path


def safe_create_with_backup(path, mode='w', chmod=0o644):
    """
    Safely creates a new file, backs up the old one if existed
    :param path:
    :param mode:
    :param chmod:
    :return:
    """
    backup_path = delete_file_backup(path, chmod)
    return safe_open(path, mode, chmod), backup_path


def safe_open(path, mode="w", chmod=None, buffering=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.

    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    return os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args),
        mode, *fdopen_args)


def safe_new_dir(path, mode=0o755):
    """
    Creates a new unique directory. If the given directory already exists,
    linear incrementation is used to create a new one.


    :param path:
    :param mode:
    :return:
    """
    path, tail = os.path.split(path)
    return _unique_dir(
        path, dirname_pat=(lambda count: "%s_%04d" % (tail, count)),
        count=0, mode=mode)


def _unique_dir(path, dirname_pat, count, mode):
    while True:
        current_path = os.path.join(path, dirname_pat(count))
        try:
            os.makedirs(current_path, mode)
            return os.path.abspath(current_path)

        except OSError as exception:
            # "Dir exists," is okay, try a different name.
            if exception.errno != errno.EEXIST:
                raise
        count += 1


def _unique_file(path, filename_pat, count, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=mode),\
                os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path, mode=0o777):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int mode: File mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    filename, extension = os.path.splitext(tail)
    return _unique_file(
        path, filename_pat=(lambda count: "%s_%04d%s" % (filename, count, extension if not None else '')),
        count=0, mode=mode)


def unique_lineage_name(path, filename, mode=0o777):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int mode: file mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=mode), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, mode=mode)


def safely_remove(path):
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def random_password(length):
    """
    Generates a random password which consists of digits, lowercase and uppercase characters
    :param length:
    :return:
    """
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + "_") for _ in range(length))


def merge(dst, src, path=None, abort_conflict=False):
    """
    Deep merges dictionary object b into a.
    :param dst:
    :param src:
    :return:
    """
    if dst is None: return None
    if src is None: return dst

    if path is None: path = []
    for key in src:
        if key in dst:
            if isinstance(dst[key], dict) and isinstance(src[key], dict):
                merge(dst[key], src[key], path + [str(key)], abort_conflict)
            elif dst[key] == src[key]:
                pass # same leaf value
            elif abort_conflict:
                raise ValueError('Conflict at %s' % '.'.join(path + [str(key)]))
            else:
                dst[key] = src[key]
        else:
            dst[key] = src[key]
    return dst


def gen_ss_cert(key, domains, not_before=None,
                validity=(7 * 24 * 60 * 60), force_san=True):
    """Generate new self-signed certificate.

    :type domains: `list` of `unicode`
    :param OpenSSL.crypto.PKey key:
    :param bool force_san:

    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.

    """
    assert domains, "Must provide one or more hostnames for the cert."
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(int(binascii.hexlify(OpenSSL.rand.bytes(16)), 16))
    cert.set_version(2)

    extensions = [
        OpenSSL.crypto.X509Extension(
            b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    ]

    cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    if force_san or len(domains) > 1:
        extensions.append(OpenSSL.crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=b", ".join(b"DNS:" + d.encode() for d in domains)
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert


def get_file_mtime(file):
    return os.path.getmtime(file)


def get_os_info(filepath="/etc/os-release"):
    """
    Get OS name and version

    :param str filepath: File path of os-release file
    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    if os.path.isfile(filepath):
        # Systemd os-release parsing might be viable
        os_name, os_version = get_systemd_os_info(filepath=filepath)
        if os_name:
            return (os_name, os_version)

    # Fallback to platform module
    return get_python_os_info()


def get_os_info_ua(filepath="/etc/os-release"):
    """
    Get OS name and version string for User Agent

    :param str filepath: File path of os-release file
    :returns: os_ua
    :rtype: `str`
    """

    if os.path.isfile(filepath):
        os_ua = _get_systemd_os_release_var("PRETTY_NAME", filepath=filepath)
        if not os_ua:
            os_ua = _get_systemd_os_release_var("NAME", filepath=filepath)
        if os_ua:
            return os_ua

    # Fallback
    return " ".join(get_python_os_info())


def get_systemd_os_info(filepath="/etc/os-release"):
    """
    Parse systemd /etc/os-release for distribution information

    :param str filepath: File path of os-release file
    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    os_name = _get_systemd_os_release_var("ID", filepath=filepath)
    os_version = _get_systemd_os_release_var("VERSION_ID", filepath=filepath)

    return (os_name, os_version)


def get_systemd_os_like(filepath="/etc/os-release"):
    """
    Get a list of strings that indicate the distribution likeness to
    other distributions.

    :param str filepath: File path of os-release file
    :returns: List of distribution acronyms
    :rtype: `list` of `str`
    """

    return _get_systemd_os_release_var("ID_LIKE", filepath).split(" ")


def _get_systemd_os_release_var(varname, filepath="/etc/os-release"):
    """
    Get single value from systemd /etc/os-release

    :param str varname: Name of variable to fetch
    :param str filepath: File path of os-release file
    :returns: requested value
    :rtype: `str`
    """

    var_string = varname+"="
    if not os.path.isfile(filepath):
        return ""
    with open(filepath, 'r') as fh:
        contents = fh.readlines()

    for line in contents:
        if line.strip().startswith(var_string):
            # Return the value of var, normalized
            return _normalize_string(line.strip()[len(var_string):])
    return ""


def _normalize_string(orig):
    """
    Helper function for _get_systemd_os_release_var() to remove quotes
    and whitespaces around the string (strip/trim)
    """
    return orig.replace('"', '').replace("'", "").strip()


def get_python_os_info():
    """
    Get Operating System type/distribution and major version
    using python platform module

    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """
    info = platform.system_alias(
        platform.system(),
        platform.release(),
        platform.version()
    )
    os_type, os_ver, _ = info
    os_type = os_type.lower()
    if os_type.startswith('linux'):
        info = platform.linux_distribution()
        # On arch, platform.linux_distribution() is reportedly ('','',''),
        # so handle it defensively
        if info[0]:
            os_type = info[0]
        if info[1]:
            os_ver = info[1]
    elif os_type.startswith('darwin'):
        os_ver = subprocess.Popen(
            ["sw_vers", "-productVersion"],
            stdout=subprocess.PIPE
        ).communicate()[0].rstrip('\n')
    elif os_type.startswith('freebsd'):
        # eg "9.3-RC3-p1"
        os_ver = os_ver.partition("-")[0]
        os_ver = os_ver.partition(".")[0]
    elif platform.win32_ver()[1]:
        os_ver = platform.win32_ver()[1]
    else:
        # Cases known to fall here: Cygwin python
        os_ver = ''
    return os_type, os_ver

# Just make sure we don't get pwned... Make sure that it also doesn't
# start with a period or have two consecutive periods <- this needs to
# be done in addition to the regex
EMAIL_REGEX = re.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$")


def safe_email(email):
    """Scrub email address before using it."""
    if EMAIL_REGEX.match(email) is not None:
        return not email.startswith(".") and ".." not in email
    else:
        logger.warning("Invalid email address: %s.", email)
        return False


def get_utc_sec():
    return time.time()


def silent_close(c):
    try:
        if c is not None:
            c.close()
    except:
        pass


def hmac_obj(key, data):
    return hmac.new(key, data, hashlib.sha256)


def flush_json(js, filepath):
    """
    Flushes JSON state file / configuration to the file name using move strategy
    :param js:
    :param filepath:
    :return:
    """
    abs_filepath = os.path.abspath(filepath)
    fw, tmp_filepath = unique_file(abs_filepath, mode=0o644)
    with fw:
        json.dump(js, fp=fw, indent=2)
        fw.flush()

    shutil.move(tmp_filepath, abs_filepath)


def strip(x):
    """
    Strips string x (if non empty) or each string in x if it is a list
    :param x:
    :return:
    """
    if x is None:
        return None
    if isinstance(x, types.ListType):
        return [y.strip() if y is not None else y for y in x]
    else:
        return x.strip()


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def json_valueize_key(key):
    """
    Sanitizes JSON keys
    Allows only string keys, numerical keys
    :param key:
    :return:
    """
    if isinstance(key, types.StringTypes):
        return key
    if isinstance(key, (types.BooleanType, types.IntType, types.LongType, types.FloatType)):
        return key
    return '%s' % key


def json_valueize(value):
    """
    Normalizes value to JSON serializable element.
    Tries to serialize value to JSON, if it fails, it is converted to the string.
    :param value:
    :return:
    """
    if isinstance(value, types.StringTypes):
        return value
    if isinstance(value, (types.BooleanType, types.IntType, types.LongType, types.FloatType)):
        return value

    # Try JSON serialize
    try:
        json.dumps(value)
        return value
    except TypeError:
        pass

    # Tuple - convert to list
    if isinstance(value, types.TupleType):
        value = list(value)

    # Special support for lists and dictionaries
    # Preserve type, encode sub-values
    if isinstance(value, types.ListType):
        return [json_valueize(x) for x in value]

    elif isinstance(value, types.DictionaryType):
        return {json_valueize_key(key): json_valueize(value[key]) for key in value}

    else:
        return '%s' % value


def args_to_dict(log, *args):
    """
    Transforms arguments to the log
    :param log:
    :param args:
    :return:
    """
    if args is None:
        return

    for idx, arg in enumerate(args):
        val = json_valueize(arg)
        log['arg%d' % idx] = val


def kwargs_to_dict(js, **kwargs):
    """
    Translates kwargs to the dict entries
    :param log:
    :param kwargs:
    :return:
    """
    if kwargs is None:
        return

    for key, value in iteritems(kwargs):
        val = json_valueize(value)
        js[json_valueize_key(key)] = val


def unix_time(dt):
    """
    Converts date time to the epoch time in seconds
    :param dt: datetime
    :return:
    """
    epoch = datetime.utcfromtimestamp(0)
    return float((dt - epoch).total_seconds())


"""A single 64 MiB, explicitly owned macOS image for real ENOSPC fixtures.

No arbitrary mount/device argument is accepted. All filling uses an admitted,
retained directory FD. Detach uses the freshly revalidated owned mountpoint,
never a remembered device number; ambiguous cleanup refuses without force.
"""
import errno
import os
from pathlib import Path
import plistlib
import stat
import sys
import time
import uuid

import mixed_audit_native as shared
import durable_boundaries_native as durable

LIMIT = 64 * 1024 * 1024
MIN_VOLUME = 16 * 1024 * 1024
require = shared.require


def file_identity(value):
    return [value.st_dev, value.st_ino]


def creation_argv(filesystem, image, label):
    require(filesystem in ("hfs", "apfs"), "unsupported closed fixture filesystem")
    if filesystem == "apfs":
        return ["/usr/bin/hdiutil", "create", "-size", "64m", "-type", "UDIF", "-fs", "APFS",
                "-uid", str(os.geteuid()), "-gid", str(os.getegid()), "-mode", "0700",
                "-volname", label, "-nospotlight", str(image)]
    return ["/usr/bin/hdiutil", "create", "-size", "64m", "-type", "UDIF", "-fs", "Journaled HFS+",
            "-volname", label, "-nospotlight", str(image)]


def volume_geometry(value, host_dev):
    require(value["dev"] != host_dev, "refusing to fill the host filesystem")
    require(MIN_VOLUME <= value["total"] <= LIMIT, "unexpected test volume capacity")
    require(0 < value["block"] <= 1024 * 1024, "invalid test volume block size")
    return value


def inventory_images(info):
    require(isinstance(info, dict), "invalid attachment inventory")
    images = info.get("images")
    require(isinstance(images, list), "invalid attachment inventory")
    for item in images:
        require(isinstance(item, dict) and isinstance(item.get("image-path"), str)
                and isinstance(item.get("system-entities"), list), "invalid image inventory row")
        require(all(isinstance(entity, dict) for entity in item["system-entities"]), "invalid image entity inventory")
    return images


def image_relation(info, image, mount):
    images = inventory_images(info)
    matches = [item for item in images if item.get("image-path") == str(image)]
    require(len(matches) == 1, "owned image attachment is absent or ambiguous")
    mounted = [item.get("mount-point") for item in matches[0].get("system-entities", [])
               if item.get("mount-point")]
    require(mounted == [str(mount)], "owned image has an unexpected mounted entity")
    for item in images:
        if item is matches[0]:
            continue
        require(not any(entity.get("mount-point") == str(mount)
                        for entity in item.get("system-entities", [])), "mount belongs to another image")
    return matches[0]


def write_until_enospc(fd, limit=LIMIT, deadline_seconds=20):
    """No sparse writes, fallback target, or unbounded attempt after a full write.

    A large write can fail before all residual blocks are used. On ENOSPC only,
    reduce the request to one filesystem block; the final evidence is a genuine
    kernel ENOSPC from write/fsync, never RLIMIT_FSIZE or a permission error.
    """
    require(0 < limit <= LIMIT, "invalid aggregate fill bound")
    block = os.fstatvfs(fd).f_frsize
    require(0 < block <= 1024 * 1024, "invalid filler block size")
    written, request = 0, 1024 * 1024
    started = time.monotonic()
    while written < limit:
        require(time.monotonic() - started <= deadline_seconds, "bounded fill deadline reached")
        size = min(request, limit - written)
        try:
            count = os.write(fd, b"F" * size)
            require(0 < count <= size, "invalid filler write result")
            written += count
            os.fsync(fd)
        except OSError as error:
            require(error.errno == errno.ENOSPC, "fill failed for an errno other than ENOSPC: " + str(error))
            if request > block:
                request = block
                continue
            return {"errno": error.errno, "errno_name": "ENOSPC", "written_bytes": written,
                    "write_limit": limit, "final_request_bytes": size,
                    "elapsed_seconds": time.monotonic() - started}
    raise AssertionError("aggregate fill bound reached without ENOSPC")


class OwnedFullVolume:
    def __init__(self, root, filesystem="hfs"):
        require(filesystem in ("hfs", "apfs"), "unsupported closed fixture filesystem")
        self.filesystem = filesystem
        self.root = root
        self.id = str(uuid.uuid4())
        self.image = root / ("enospc-" + self.id + ".dmg")
        self.mount = root / ("mount-" + self.id)
        self.label = "TirithFixture-" + self.id
        tool_root = root / "tool-env"
        tool_root.mkdir(mode=0o700)
        self.env = shared.isolated_env(tool_root)
        self.rows, self.events = [], []
        self.image_fd = self.mount_fd = None
        self.image_identity = self.mount_identity = self.volume_uuid = None
        self.host_dev = root.stat().st_dev
        self.filler_identity = None
        self.create_attempted = False
        self.create_finished = False
        self.attach_attempted = False
        self.attach_finished = False
        self.detached = False

    def tool(self, name, argv):
        job = shared.Job(name, argv, self.root, self.env, timeout=45)
        row = shared.finish([job])[0]
        self.rows.append(row)
        durable.clean(row, 0)
        return row

    def plist(self, name, argv):
        return plistlib.loads(self.tool(name, argv)["stdout"].encode())

    def info(self):
        return self.plist("image-inventory", ["/usr/bin/hdiutil", "info", "-plist"])

    def assert_image(self):
        require(self.image_fd is not None, "image was not retained")
        opened, current = os.fstat(self.image_fd), self.image.lstat()
        require(stat.S_ISREG(current.st_mode) and file_identity(opened) == self.image_identity
                and file_identity(current) == self.image_identity, "owned image inode changed")
        require(opened.st_size <= LIMIT + 1024 * 1024, "owned image exceeded fixed size bound")

    def geometry(self):
        current = os.fstat(self.mount_fd)
        fs = os.fstatvfs(self.mount_fd)
        return volume_geometry({"dev": current.st_dev, "total": fs.f_blocks * fs.f_frsize,
                                "available": fs.f_bavail * fs.f_frsize, "block": fs.f_frsize}, self.host_dev)

    def check_filesystem(self, value):
        require(self.filesystem != "apfs" or value.get("FilesystemType") == "apfs", "APFS volume type was not established")

    def check_mount_permissions(self, value):
        if self.filesystem == "apfs":
            require(value.st_uid == os.geteuid() and value.st_gid == os.getegid()
                    and stat.S_IMODE(value.st_mode) in (0o700, 0o755),
                    "APFS root must retain the ordinary creator UID/GID without group/other writes")
            parent = self.root.lstat()
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                    and stat.S_IMODE(parent.st_mode) == 0o700,
                    "APFS fixture requires its ordinary-owner private ancestor")

    def revalidate(self, require_writable=True):
        self.assert_image()
        image_relation(self.info(), self.image, self.mount)
        opened, current = os.fstat(self.mount_fd), self.mount.lstat()
        require(stat.S_ISDIR(current.st_mode) and file_identity(opened) == self.mount_identity
                and file_identity(current) == self.mount_identity, "owned mount identity changed")
        if require_writable:
            self.check_mount_permissions(opened)
        value = self.plist("volume-info", ["/usr/sbin/diskutil", "info", "-plist", str(self.mount)])
        self.check_filesystem(value)
        require(value.get("MountPoint") == str(self.mount) and value.get("VolumeUUID") == self.volume_uuid
                and value.get("VolumeName") == self.label, "owned volume UUID/mount binding changed")
        self.geometry()

    def admit_mount(self, require_writable=True):
        """Recover ownership after an attach tool error only from full evidence.

        The fresh private image inode and exact single mountpoint must already
        match. No device number, unexpected mount or missing UUID is inferred.
        """
        self.assert_image()
        image_relation(self.info(), self.image, self.mount)
        if self.mount_fd is None:
            self.mount_fd = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened, current = os.fstat(self.mount_fd), self.mount.lstat()
        require(stat.S_ISDIR(current.st_mode) and file_identity(opened) == file_identity(current),
                "mount path differs from retained directory")
        captured = file_identity(opened)
        require(self.mount_identity is None or self.mount_identity == captured, "previously bound mount changed")
        self.geometry()
        value = self.plist("volume-info", ["/usr/sbin/diskutil", "info", "-plist", str(self.mount)])
        self.check_filesystem(value)
        observed_uuid = value.get("VolumeUUID")
        require(isinstance(observed_uuid, str) and uuid.UUID(observed_uuid).int != 0, "missing volume UUID")
        require(value.get("MountPoint") == str(self.mount) and value.get("VolumeName") == self.label,
                "volume does not have exact owned mountpoint/label")
        require(self.volume_uuid is None or self.volume_uuid == observed_uuid, "previously bound volume UUID changed")
        self.mount_identity, self.volume_uuid = captured, observed_uuid
        self.revalidate(require_writable=False)
        if require_writable:
            self.check_mount_permissions(opened)

    def create(self):
        require(sys.platform == "darwin" and os.geteuid() != 0, "ordinary native macOS user required")
        require(not self.image.exists() and not self.mount.exists(), "owned image paths already exist")
        host = os.statvfs(self.root)
        require(host.f_bavail * host.f_frsize >= 512 * 1024 * 1024 + LIMIT,
                "insufficient host reserve for bounded image creation")
        require(not any(item.get("image-path") == str(self.image) for item in inventory_images(self.info())),
                "owned image path already attached")
        # Both formatters receive only this newly named fixed-size image, never
        # an existing device or container. No minimum-size failure enlarges it.
        self.create_attempted = True
        try:
            self.tool("image-create", creation_argv(self.filesystem, self.image, self.label))
            self.create_finished = True
        finally:
            if self.image.exists():
                self.image_fd = os.open(self.image, os.O_RDONLY | os.O_NOFOLLOW)
                self.image_identity = file_identity(os.fstat(self.image_fd))
        self.assert_image()
        self.mount.mkdir(mode=0o700)
        self.attach_attempted = True
        self.tool("image-attach", ["/usr/sbin/diskutil", "image", "attach", "--nobrowse",
                  "--mountOptions", "owners,noexec,nosuid,nodev", "--mountPoint", str(self.mount), str(self.image)])
        self.attach_finished = True
        self.admit_mount()
        self.events.append({"event": "admitted", "image_identity": self.image_identity,
                            "mount_identity": self.mount_identity, "volume_uuid": self.volume_uuid,
                            "mount_uid": os.fstat(self.mount_fd).st_uid, "mount_gid": os.fstat(self.mount_fd).st_gid,
                            "mount_mode": oct(stat.S_IMODE(os.fstat(self.mount_fd).st_mode)),
                            "filesystem": self.filesystem, "geometry": self.geometry()})

    def directory(self, name):
        require(name in ("audit-data", "profile-config"), "unrecognized product fixture directory")
        self.revalidate()
        os.mkdir(name, mode=0o700, dir_fd=self.mount_fd)
        return self.mount / name

    def fill(self):
        self.revalidate()
        require(self.filler_identity is None, "filler already exists")
        fd = os.open("owned-filler", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.mount_fd)
        try:
            value = os.fstat(fd)
            require(value.st_dev == self.mount_identity[0] and stat.S_ISREG(value.st_mode), "filler escaped admitted volume")
            self.filler_identity = file_identity(value)
            before = self.geometry()
            result = write_until_enospc(fd)
            require(file_identity(os.fstat(fd)) == self.filler_identity, "filler identity changed")
            result.update(before=before, after=self.geometry(), identity=self.filler_identity)
            self.events.append({"event": "real-enospc", **result})
            return result
        finally:
            os.close(fd)

    def release(self):
        self.revalidate()
        require(self.filler_identity is not None, "no owned filler to release")
        current = os.stat("owned-filler", dir_fd=self.mount_fd, follow_symlinks=False)
        require(stat.S_ISREG(current.st_mode) and file_identity(current) == self.filler_identity,
                "refusing to unlink changed filler")
        os.unlink("owned-filler", dir_fd=self.mount_fd)
        os.fsync(self.mount_fd)
        self.filler_identity = None
        require(self.geometry()["available"] > 1024 * 1024, "space did not recover after owned filler removal")
        self.events.append({"event": "space-released", "geometry": self.geometry()})

    def close(self):
        # System disk services are not our children and are never signaled.
        # A failed attachment before full admission remains explicit unavailable
        # cleanup; there is no best-guess device-number or force-unmount fallback.
        failure, descriptor_errors = None, []
        try:
            if self.create_attempted and not self.detached:
                inventory = self.info()
                images = inventory_images(inventory)
                matching = [item for item in images if item.get("image-path") == str(self.image)]
                if not matching:
                    require(self.create_finished and (not self.attach_attempted or self.attach_finished),
                            "disk service operation unresolved after failed client; a single absent inventory is insufficient")
                    require(not any(entity.get("mount-point") == str(self.mount) for item in images
                                    for entity in item["system-entities"]), "owned mountpoint is attributed to another image")
                    require(not self.mount.exists() or self.mount.lstat().st_dev == self.host_dev,
                            "image absent but owned mountpoint still uses another filesystem")
                    self.detached = True
                    self.events.append({"event": "attachment-absent", "detach_attempted": False})
                else:
                    image_relation(inventory, self.image, self.mount)
                    # Write eligibility is deliberately separate from authority
                    # to normally detach an otherwise exactly bound owned image.
                    self.admit_mount(require_writable=False)
                    self.events.append({"event": "cleanup-attachment-fully-bound", "volume_uuid": self.volume_uuid})
                    descriptor = self.mount_fd
                    self.mount_fd = None
                    os.close(descriptor)
                    self.assert_image()
                    image_relation(self.info(), self.image, self.mount)
                    value = self.plist("detach-volume-info", ["/usr/sbin/diskutil", "info", "-plist", str(self.mount)])
                    self.check_filesystem(value)
                    require(value.get("MountPoint") == str(self.mount) and value.get("VolumeUUID") == self.volume_uuid
                            and value.get("VolumeName") == self.label and file_identity(self.mount.lstat()) == self.mount_identity,
                            "volume binding changed immediately before detach")
                    self.tool("image-detach", ["/usr/bin/hdiutil", "detach", str(self.mount)])
                    remaining = inventory_images(self.info())
                    require(not any(item.get("image-path") == str(self.image) for item in remaining), "owned image still attached")
                    require(not self.mount.exists() or self.mount.stat().st_dev == self.host_dev, "mount still uses detached volume")
                    self.detached = True
                    self.events.append({"event": "detached", "forced": False})
        except Exception as error:
            failure = error
            self.events.append({"event": "cleanup-refused-or-failed", "reason": type(error).__name__ + ": " + str(error)})
        finally:
            for attribute in ("mount_fd", "image_fd"):
                descriptor = getattr(self, attribute)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        descriptor_errors.append(attribute + ": " + str(error))
                    finally:
                        setattr(self, attribute, None)
            self.events.append({"event": "owned-descriptors-closed", "errors": descriptor_errors})
        if failure is not None:
            raise failure
        require(not descriptor_errors, "owned descriptor cleanup failed")

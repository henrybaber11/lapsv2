"""
sd.py
-----
Pure-Python Security Descriptor / ACE / SID helpers.
Replaces the Impacket ldaptypes pieces used to build the
target_sd that is sent to MS-GKDI GetKey.
"""

from __future__ import annotations
import struct
from typing import List


# ---------------------------------------------------------------------------
# SID
# ---------------------------------------------------------------------------

class SID:
    """
    Simple Security Identifier.
    Can be created from a canonical string like "S-1-5-18"
    and can be turned into the binary form Windows expects.
    """
    def __init__(self):
        self.revision: int = 1
        self.identifier_authority: bytes = b"\x00\x00\x00\x00\x00\x05"  # NT Authority
        self.sub_authorities: List[int] = []

    @classmethod
    def from_canonical(cls, sid_str: str) -> "SID":
        """
        Parse "S-1-5-21-..." into a SID object.
        """
        parts = sid_str.split("-")
        if parts[0] != "S":
            raise ValueError(f"Invalid SID string: {sid_str}")

        obj = cls()
        obj.revision = int(parts[1])

        # Identifier Authority (6 bytes, big-endian)
        auth = int(parts[2])
        obj.identifier_authority = auth.to_bytes(6, byteorder="big")

        obj.sub_authorities = [int(p) for p in parts[3:]]
        return obj

    def to_bytes(self) -> bytes:
        """
        Binary form:
            Revision          : 1 byte
            SubAuthorityCount : 1 byte
            IdentifierAuth    : 6 bytes
            SubAuthorities    : 4 bytes each (little-endian)
        """
        count = len(self.sub_authorities)
        header = struct.pack("BB", self.revision, count) + self.identifier_authority
        body = b"".join(struct.pack("<I", sa) for sa in self.sub_authorities)
        return header + body

    def __str__(self) -> str:
        auth = int.from_bytes(self.identifier_authority, "big")
        subs = "-".join(str(s) for s in self.sub_authorities)
        return f"S-{self.revision}-{auth}-{subs}"


# ---------------------------------------------------------------------------
# ACCESS_MASK
# ---------------------------------------------------------------------------

class ACCESS_MASK:
    def __init__(self, mask: int = 0):
        self.Mask = mask

    def to_bytes(self) -> bytes:
        return struct.pack("<I", self.Mask)


# ---------------------------------------------------------------------------
# ACCESS_ALLOWED_ACE
# ---------------------------------------------------------------------------

class ACCESS_ALLOWED_ACE:
    """
    AceType  = 0x00 (ACCESS_ALLOWED_ACE_TYPE)
    """
    ACE_TYPE = 0x00

    def __init__(self):
        self.Mask = ACCESS_MASK()
        self.Sid = SID()

    def to_bytes(self) -> bytes:
        # AceSize will be filled by the parent ACE
        return self.Mask.to_bytes() + self.Sid.to_bytes()


# ---------------------------------------------------------------------------
# ACE  (header + body)
# ---------------------------------------------------------------------------

class ACE:
    def __init__(self):
        self.AceType: int = 0
        self.AceFlags: int = 0
        self.Ace = None          # will hold ACCESS_ALLOWED_ACE etc.

    def to_bytes(self) -> bytes:
        body = self.Ace.to_bytes()
        # AceSize = 4-byte header + body
        ace_size = 4 + len(body)
        header = struct.pack("<BBH", self.AceType, self.AceFlags, ace_size)
        return header + body


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------

class ACL:
    def __init__(self):
        self.AclRevision: int = 2
        self.Sbz1: int = 0
        self.Sbz2: int = 0
        self.aces: List[ACE] = []

    def to_bytes(self) -> bytes:
        ace_data = b"".join(ace.to_bytes() for ace in self.aces)
        # AclSize = 8-byte header + all ACEs
        acl_size = 8 + len(ace_data)
        header = struct.pack("<BBHHH",
                             self.AclRevision,
                             self.Sbz1,
                             acl_size,
                             len(self.aces),
                             self.Sbz2)
        return header + ace_data


# ---------------------------------------------------------------------------
# SR_SECURITY_DESCRIPTOR
# ---------------------------------------------------------------------------

class SR_SECURITY_DESCRIPTOR:
    """
    Minimal Security Descriptor that contains Owner, Group and DACL.
    This is exactly what the original code builds and sends to GKDI.
    """
    def __init__(self):
        self.Revision: bytes = b"\x01"
        self.Sbz1: bytes = b"\x00"
        self.Control: int = 0
        self.OwnerSid: SID = SID()
        self.GroupSid: SID = SID()
        self.Sacl: bytes = b""          # we leave SACL empty
        self.Dacl: ACL = ACL()

    def to_bytes(self) -> bytes:
        """
        Classic self-relative Security Descriptor layout.
        """
        # We build it in the same order Impacket does.
        owner_bin = self.OwnerSid.to_bytes()
        group_bin = self.GroupSid.to_bytes()
        dacl_bin = self.Dacl.to_bytes()

        # Offsets are relative to the start of the SD
        # Header is 20 bytes:
        #   Revision (1) + Sbz1 (1) + Control (2) +
        #   OffsetOwner (4) + OffsetGroup (4) + OffsetSacl (4) + OffsetDacl (4)
        header_size = 20

        offset_owner = header_size
        offset_group = offset_owner + len(owner_bin)
        offset_sacl  = 0                     # no SACL
        offset_dacl  = offset_group + len(group_bin)

        header = (
            self.Revision +
            self.Sbz1 +
            struct.pack("<H", self.Control) +
            struct.pack("<I", offset_owner) +
            struct.pack("<I", offset_group) +
            struct.pack("<I", offset_sacl) +
            struct.pack("<I", offset_dacl)
        )

        return header + owner_bin + group_bin + dacl_bin

    # keep the old name so existing call sites still work
    def getData(self) -> bytes:
        return self.to_bytes()


# ---------------------------------------------------------------------------
# Helper functions that the main script calls
# ---------------------------------------------------------------------------

def create_ace(sid_str: str, mask: int) -> ACE:
    """
    Build an ACCESS_ALLOWED_ACE for the given SID and access mask.
    """
    nace = ACE()
    nace.AceType = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace.AceFlags = 0x00

    acedata = ACCESS_ALLOWED_ACE()
    acedata.Mask = ACCESS_MASK(mask)
    acedata.Sid = SID.from_canonical(sid_str)
    nace.Ace = acedata
    return nace


def create_sd(sid_str: str) -> SR_SECURITY_DESCRIPTOR:
    """
    Build the exact Security Descriptor the original code sent to GKDI.
    Owner/Group = Local System (S-1-5-18)
    DACL contains:
        - the target SID with mask 3
        - Everyone (S-1-1-0) with mask 2
    """
    sd = SR_SECURITY_DESCRIPTOR()
    sd.Revision = b"\x01"
    sd.Sbz1 = b"\x00"
    sd.Control = 32772          # SE_DACL_PRESENT | SE_SELF_RELATIVE

    sd.OwnerSid = SID.from_canonical("S-1-5-18")
    sd.GroupSid = SID.from_canonical("S-1-5-18")
    sd.Sacl = b""

    acl = ACL()
    acl.AclRevision = 2
    acl.Sbz1 = 0
    acl.Sbz2 = 0
    acl.aces = []
    acl.aces.append(create_ace(sid_str, 3))
    acl.aces.append(create_ace("S-1-1-0", 2))
    sd.Dacl = acl

    return sd

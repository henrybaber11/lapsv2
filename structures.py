"""
structures.py
-------------
Pure-Python replacements for the Impacket Structure classes used by the
LAPSv2 tool. No Impacket dependency.

All classes have:
  - from_bytes(data)  -> parse a blob
  - to_bytes()        -> (only where needed)
  - dump()            -> pretty print
  - dict-style access via self["FieldName"] for compatibility with old code
"""

from __future__ import annotations
import struct
from typing import Optional


# ---------------------------------------------------------------------------
# Tiny helper so the classes feel a bit like the old Impacket ones
# ---------------------------------------------------------------------------

class _DictMixin:
    """Lets you do obj['Field'] instead of obj.Field"""
    def __getitem__(self, key: str):
        return getattr(self, key)

    def __setitem__(self, key: str, value):
        setattr(self, key, value)

    def get(self, key: str, default=None):
        return getattr(self, key, default)


# ---------------------------------------------------------------------------
# FFCDHParameter  (Finite Field Cryptography Diffie-Hellman parameters)
# ---------------------------------------------------------------------------

class FFCDHParameter(_DictMixin):
    """
    Layout (little-endian):
        Length      : 4 bytes  (total size of this structure)
        Magic       : 4 bytes
        KeyLength   : 4 bytes  (size of the following two big integers)
        FieldOrder  : KeyLength bytes
        Generator   : KeyLength bytes
    """
    def __init__(self):
        self.Length: int = 0
        self.Magic: bytes = b""
        self.KeyLength: int = 0
        self.FieldOrder: bytes = b""
        self.Generator: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "FFCDHParameter":
        obj = cls()
        obj.Length, = struct.unpack_from("<I", data, 0)
        obj.Magic = data[4:8]
        obj.KeyLength, = struct.unpack_from("<I", data, 8)
        off = 12
        obj.FieldOrder = data[off:off + obj.KeyLength]
        off += obj.KeyLength
        obj.Generator = data[off:off + obj.KeyLength]
        return obj

    def dump(self):
        print("[FFCDH PARAMETER]")
        print(f"Length:\t\t{self.Length}")
        print(f"Magic:\t\t{self.Magic}")
        print(f"KeyLength:\t\t{self.KeyLength}")
        print(f"FieldOrder:\t\t{self.FieldOrder.hex()}")
        print(f"Generator:\t\t{self.Generator.hex()}")
        print()


# ---------------------------------------------------------------------------
# FFCDHKey
# ---------------------------------------------------------------------------

class FFCDHKey(_DictMixin):
    """
    Layout:
        Magic       : 4 bytes
        KeyLength   : 4 bytes
        FieldOrder  : KeyLength bytes
        Generator   : KeyLength bytes
        PubKey      : KeyLength bytes
    """
    def __init__(self):
        self.Magic: bytes = b""
        self.KeyLength: int = 0
        self.FieldOrder: bytes = b""
        self.Generator: bytes = b""
        self.PubKey: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "FFCDHKey":
        obj = cls()
        obj.Magic = data[0:4]
        obj.KeyLength, = struct.unpack_from("<I", data, 4)
        off = 8
        obj.FieldOrder = data[off:off + obj.KeyLength]
        off += obj.KeyLength
        obj.Generator = data[off:off + obj.KeyLength]
        off += obj.KeyLength
        obj.PubKey = data[off:off + obj.KeyLength]
        return obj

    def dump(self):
        print("[FFCDH KEY]")
        print(f"KeyLength:\t\t{self.KeyLength}")
        print(f"FieldOrder:\t\t{self.FieldOrder.hex()}")
        print(f"Generator:\t\t{self.Generator.hex()}")
        print(f"PubKey:\t\t{self.PubKey.hex()}")
        print()


# ---------------------------------------------------------------------------
# ECDHKey  (not used in the common DH path, but kept for completeness)
# ---------------------------------------------------------------------------

class ECDHKey(_DictMixin):
    def __init__(self):
        self.Magic: bytes = b""
        self.KeyLength: int = 0
        self.XCoordinate: bytes = b""
        self.YCoordinate: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "ECDHKey":
        obj = cls()
        obj.Magic = data[0:4]
        obj.KeyLength, = struct.unpack_from("<I", data, 4)
        off = 8
        obj.XCoordinate = data[off:off + obj.KeyLength]
        off += obj.KeyLength
        obj.YCoordinate = data[off:off + obj.KeyLength]
        return obj

    def dump(self):
        print("[ECDH KEY]")
        print(f"Magic:\t\t{self.Magic.hex()}")
        print(f"XCoordinate:\t\t{self.XCoordinate.hex()}")
        print(f"YCoordinate:\t\t{self.YCoordinate.hex()}")
        print()


# ---------------------------------------------------------------------------
# KDFParameter
# ---------------------------------------------------------------------------

class KDFParameter(_DictMixin):
    """
    Layout:
        Unknown1   : 4 bytes
        Unknown2   : 4 bytes
        HashLen    : 4 bytes   (length of the hash name string in bytes)
        Unknown3   : 4 bytes
        HashName   : HashLen bytes  (UTF-16LE, e.g. "SHA512\0")
    """
    def __init__(self):
        self.Unknown1: int = 0
        self.Unknown2: int = 0
        self.HashLen: int = 0
        self.Unknown3: int = 0
        self.HashName: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "KDFParameter":
        obj = cls()
        obj.Unknown1, obj.Unknown2, obj.HashLen, obj.Unknown3 = struct.unpack_from("<IIII", data, 0)
        obj.HashName = data[16:16 + obj.HashLen]
        return obj


# ---------------------------------------------------------------------------
# EncryptedPasswordBlob  (the outer LAPS blob you get from LDAP)
# ---------------------------------------------------------------------------

class EncryptedPasswordBlob(_DictMixin):
    """
    Layout:
        Timestamp_lower : 4 bytes
        Timestamp_upper : 4 bytes
        Length          : 4 bytes   (size of the CMS blob that follows)
        Flags           : 4 bytes
        Blob            : Length bytes  (the real CMS / PKCS#7 content)
    """
    def __init__(self):
        self.Timestamp_lower: int = 0
        self.Timestamp_upper: int = 0
        self.Length: int = 0
        self.Flags: int = 0
        self.Blob: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedPasswordBlob":
        obj = cls()
        obj.Timestamp_lower, obj.Timestamp_upper, obj.Length, obj.Flags = \
            struct.unpack_from("<IIII", data, 0)
        obj.Blob = data[16:16 + obj.Length]
        return obj

    def dump(self):
        print("[ENCRYPTED PASSWORD BLOB]")
        print(f"Timestamp_upper:\t\t{self.Timestamp_upper}")
        print(f"Timestamp_lower:\t\t{self.Timestamp_lower}")
        ts = (self.Timestamp_upper << 32) | self.Timestamp_lower
        print(f"Update Timestamp:\t\t{ts}")
        print(f"Length:\t\t{self.Length}")
        print(f"Flags:\t\t{self.Flags}")
        print(f"Blob length:\t\t{len(self.Blob)}")
        print()


# ---------------------------------------------------------------------------
# GroupKeyEnvelope  (what MS-GKDI GetKey returns)
# ---------------------------------------------------------------------------

class GroupKeyEnvelope(_DictMixin):
    """
    This is the big one.  After the fixed header there are a series of
    length-prefixed fields.
    """
    def __init__(self):
        self.Version: int = 0
        self.Magic: int = 0
        self.Flags: int = 0
        self.L0Index: int = 0
        self.L1Index: int = 0
        self.L2Index: int = 0
        self.RootKeyId: bytes = b""
        self.KdfAlgoLength: int = 0
        self.KdfParaLength: int = 0
        self.SecAlgoLength: int = 0
        self.SecParaLength: int = 0
        self.PrivKeyLength: int = 0
        self.PubKeyLength: int = 0
        self.L1KeyLength: int = 0
        self.L2KeyLength: int = 0
        self.DomainLength: int = 0
        self.ForestLength: int = 0

        self.KdfAlgo: bytes = b""
        self.KdfPara: Optional[KDFParameter] = None
        self.SecAlgo: bytes = b""
        self.SecPara: Optional[FFCDHParameter] = None
        self.Domain: bytes = b""
        self.Forest: bytes = b""
        self.L1Key: bytes = b""
        self.L2Key: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "GroupKeyEnvelope":
        obj = cls()
        # Fixed header (17 * 4 = 68 bytes + 16-byte GUID)
        (obj.Version, obj.Magic, obj.Flags,
         obj.L0Index, obj.L1Index, obj.L2Index) = struct.unpack_from("<IIIIII", data, 0)
        obj.RootKeyId = data[24:40]
        (obj.KdfAlgoLength, obj.KdfParaLength,
         obj.SecAlgoLength, obj.SecParaLength,
         obj.PrivKeyLength, obj.PubKeyLength,
         obj.L1KeyLength, obj.L2KeyLength,
         obj.DomainLength, obj.ForestLength) = struct.unpack_from("<IIIIIIIIII", data, 40)

        off = 80  # 24 + 16 + 40

        obj.KdfAlgo = data[off:off + obj.KdfAlgoLength]
        off += obj.KdfAlgoLength

        kdf_para_raw = data[off:off + obj.KdfParaLength]
        obj.KdfPara = KDFParameter.from_bytes(kdf_para_raw)
        off += obj.KdfParaLength

        obj.SecAlgo = data[off:off + obj.SecAlgoLength]
        off += obj.SecAlgoLength

        sec_para_raw = data[off:off + obj.SecParaLength]
        obj.SecPara = FFCDHParameter.from_bytes(sec_para_raw)
        off += obj.SecParaLength

        obj.Domain = data[off:off + obj.DomainLength]
        off += obj.DomainLength

        obj.Forest = data[off:off + obj.ForestLength]
        off += obj.ForestLength

        obj.L1Key = data[off:off + obj.L1KeyLength]
        off += obj.L1KeyLength

        obj.L2Key = data[off:off + obj.L2KeyLength]

        return obj

    def dump(self):
        print("[GROUP KEY ENVELOPE]")
        print(f"Version:\t\t{self.Version}")
        print(f"Magic:\t\t{hex(self.Magic)}")
        print(f"Flags:\t\t{self.Flags}")
        print(f"L0Index:\t\t{self.L0Index}")
        print(f"L1Index:\t\t{self.L1Index}")
        print(f"L2Index:\t\t{self.L2Index}")
        print(f"RootKeyId:\t\t{self.RootKeyId.hex()}")
        print(f"KdfAlgo:\t\t{self.KdfAlgo.decode('utf-16le', errors='replace')}")
        if self.KdfPara:
            print(f"KdfPara:\t\t{self.KdfPara.HashName.decode('utf-16le', errors='replace')}")
        print(f"SecAlgo:\t\t{self.SecAlgo.decode('utf-16le', errors='replace')}")
        if self.SecPara:
            print(f"SecPara[FieldOrder]:\t{self.SecPara.FieldOrder.hex()}")
            print(f"SecPara[Generator]:\t{self.SecPara.Generator.hex()}")
        print(f"PrivKeyLength:\t\t{self.PrivKeyLength}")
        print(f"PubKeyLength:\t\t{self.PubKeyLength}")
        print(f"Domain:\t\t{self.Domain.decode('utf-16le', errors='replace')}")
        print(f"Forest:\t\t{self.Forest.decode('utf-16le', errors='replace')}")
        print(f"L1Key:\t\t{self.L1Key.hex()}")
        print(f"L2Key:\t\t{self.L2Key.hex()}")
        print()


# ---------------------------------------------------------------------------
# KeyIdentifier  (lives inside the CMS envelope)
# ---------------------------------------------------------------------------

class KeyIdentifier(_DictMixin):
    def __init__(self):
        self.Version: int = 0
        self.Magic: int = 0
        self.Flags: int = 0
        self.L0Index: int = 0
        self.L1Index: int = 0
        self.L2Index: int = 0
        self.RootKeyId: bytes = b""
        self.UnknownLength: int = 0
        self.DomainLength: int = 0
        self.ForestLength: int = 0
        self.Unknown: bytes = b""
        self.Domain: bytes = b""
        self.Forest: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "KeyIdentifier":
        obj = cls()
        (obj.Version, obj.Magic, obj.Flags,
         obj.L0Index, obj.L1Index, obj.L2Index) = struct.unpack_from("<IIIIII", data, 0)
        obj.RootKeyId = data[24:40]
        obj.UnknownLength, obj.DomainLength, obj.ForestLength = \
            struct.unpack_from("<III", data, 40)

        off = 52
        obj.Unknown = data[off:off + obj.UnknownLength]
        off += obj.UnknownLength
        obj.Domain = data[off:off + obj.DomainLength]
        off += obj.DomainLength
        obj.Forest = data[off:off + obj.ForestLength]
        return obj

    def is_public_key(self) -> bool:
        return bool(self.Flags & 1)

    def dump(self):
        print("[KEY IDENTIFIER]")
        print(f"Version:\t\t{self.Version}")
        print(f"Magic:\t\t{hex(self.Magic)}")
        print(f"Flags:\t\t{self.Flags}")
        print(f"L0Index:\t\t{self.L0Index}")
        print(f"L1Index:\t\t{self.L1Index}")
        print(f"L2Index:\t\t{self.L2Index}")
        print(f"RootKeyId:\t\t{self.RootKeyId.hex()}")
        print(f"Unknown:\t\t{self.Unknown.hex()}")
        print(f"Domain:\t\t{self.Domain.decode('utf-16le', errors='replace')}")
        print(f"Forest:\t\t{self.Forest.decode('utf-16le', errors='replace')}")
        print()

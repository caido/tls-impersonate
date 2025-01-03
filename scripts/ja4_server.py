import socket
import sys
from typing import Dict
import hashlib


def get_extension_name(ext_type: int) -> str:
    # Common TLS extensions mapping
    extensions = {
        0x0000: "server_name",
        0x0001: "max_fragment_length",
        0x0002: "client_certificate_url",
        0x0003: "trusted_ca_keys",
        0x0004: "truncated_hmac",
        0x0005: "status_request",
        0x0006: "user_mapping",
        0x0007: "client_authz",
        0x0008: "server_authz",
        0x0009: "cert_type",
        0x000A: "supported_groups",
        0x000B: "ec_point_formats",
        0x000D: "signature_algorithms",
        0x000E: "use_srtp",
        0x000F: "heartbeat",
        0x0010: "application_layer_protocol_negotiation",
        0x0011: "status_request_v2",
        0x0012: "signed_certificate_timestamp",
        0x0013: "client_certificate_type",
        0x0014: "server_certificate_type",
        0x0015: "padding",
        0x0016: "encrypt_then_mac",
        0x0017: "extended_master_secret",
        0x0018: "token_binding",
        0x0019: "cached_info",
        0x0023: "session_ticket",
        0x0029: "pre_shared_key",
        0x002A: "early_data",
        0x002B: "supported_versions",
        0x002C: "cookie",
        0x002D: "psk_key_exchange_modes",
        0x002F: "certificate_authorities",
        0x0030: "oid_filters",
        0x0031: "post_handshake_auth",
        0x0032: "signature_algorithms_cert",
        0x0033: "key_share",
        0xFF01: "renegotiation_info",
    }
    return extensions.get(ext_type, f"unknown_{ext_type}")


def parse_extension_data(ext_type: int, data: bytes, pos: int, length: int) -> Dict:
    result = {"type": get_extension_name(ext_type), "raw_type": ext_type}

    try:
        if ext_type == 0:  # server_name
            if length > 0:
                sni_length = int.from_bytes(data[pos + 3 : pos + 5], "big")
                result["server_name"] = data[pos + 5 : pos + 5 + sni_length].decode()

        elif ext_type == 10:  # supported_groups
            groups_length = int.from_bytes(data[pos : pos + 2], "big")
            groups = []
            for i in range(0, groups_length, 2):
                group = int.from_bytes(data[pos + 2 + i : pos + 4 + i], "big")
                groups.append(group)
            result["groups"] = groups

        elif ext_type == 13:  # signature_algorithms
            sig_length = int.from_bytes(data[pos : pos + 2], "big")
            sigs = []
            for i in range(0, sig_length, 2):
                sig = int.from_bytes(data[pos + 2 + i : pos + 4 + i], "big")
                sigs.append(sig)
            result["algorithms"] = sigs

        elif ext_type == 16:  # ALPN
            alpn_length = int.from_bytes(data[pos : pos + 2], "big")
            pos_alpn = pos + 2
            protocols = []
            while pos_alpn < pos + 2 + alpn_length:
                proto_len = data[pos_alpn]
                proto = data[pos_alpn + 1 : pos_alpn + 1 + proto_len].decode()
                protocols.append(proto)
                pos_alpn += 1 + proto_len
            result["protocols"] = protocols

        elif ext_type == 43:  # supported_versions
            versions_length = data[pos]
            versions = []
            for i in range(0, versions_length, 2):
                version = int.from_bytes(data[pos + 1 + i : pos + 3 + i], "big")
                versions.append(f"0x{version:04x}")
            result["versions"] = versions

    except Exception as e:
        result["parse_error"] = str(e)

    return result


def parse_client_hello(
    data: bytes,
) -> Dict:
    pos = 9  # Skip record layer and handshake header

    # Get TLS version
    tls_version = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2

    # Skip random
    pos += 32

    # Skip session ID
    session_id_length = data[pos]
    pos += 1 + session_id_length

    # Get cipher suites
    cipher_suites_length = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    cipher_suites = []
    for i in range(0, cipher_suites_length, 2):
        cipher_suite = int.from_bytes(data[pos + i : pos + i + 2], "big")
        cipher_suites.append(cipher_suite)
    pos += cipher_suites_length

    # Get compression methods
    compression_methods_length = data[pos]
    pos += 1
    compression_methods = list(data[pos : pos + compression_methods_length])
    pos += compression_methods_length

    # Get extensions
    extensions_length = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    extensions = []
    alpn_protocols = []
    has_sni = False

    while pos < len(data):
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        ext_length = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2

        # Parse extension data
        ext_data = parse_extension_data(ext_type, data, pos, ext_length)
        extensions.append(ext_data)

        # Check for SNI
        if ext_type == 0:
            has_sni = True

        # Collect ALPN protocols for JA4
        if ext_type == 16 and "protocols" in ext_data:
            alpn_protocols = ext_data["protocols"]

        pos += ext_length

    return {
        "tls_version": f"0x{tls_version:04x}",
        "cipher_suites": cipher_suites,
        "compression_methods": compression_methods,
        "extensions": extensions,
        "alpn_protocols": alpn_protocols,
        "has_sni": has_sni,
    }


def compute_ja4(client_hello: Dict) -> str:
    # Filter out GREASE values
    cipher_suites = [
        cs for cs in client_hello["cipher_suites"] if (cs & 0x0F0F) != 0x0A0A
    ]

    # Format cipher suites as sorted hex strings
    cipher_hex = [f"{x:04x}" for x in cipher_suites]
    cipher_hex.sort()
    cipher_str = ",".join(cipher_hex)
    c_hash = (
        "000000000000"
        if not cipher_hex
        else hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
    )

    # Get extensions excluding SNI (0x0000) and ALPN (0x0010)
    ext_types = [
        ext["raw_type"]
        for ext in client_hello["extensions"]
        if ext["raw_type"] not in [0x0000, 0x0010]
        and (ext["raw_type"] & 0x0F0F) != 0x0A0A
    ]
    ext_hex = [f"{x:04x}" for x in ext_types]
    ext_hex.sort()

    # Get signature algorithms if present
    sig_algs = []
    for ext in client_hello["extensions"]:
        if ext["raw_type"] == 0x000D and "algorithms" in ext:
            sig_algs = [f"{x:04x}" for x in ext["algorithms"]]
            break

    # Build extension string with signature algorithms
    ext_str = ",".join(ext_hex)
    if sig_algs:
        ext_str += "_" + ",".join(sig_algs)
    e_hash = (
        "000000000000"
        if not ext_hex
        else hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    )

    # Get ALPN identifier
    alpn_protocols = client_hello["alpn_protocols"]
    if not alpn_protocols:
        alpn_id = "00"
    else:
        first_proto = alpn_protocols[0]
        if not first_proto:
            alpn_id = "00"
        else:
            # Get first and last alphanumeric chars
            alpn_chars = [c for c in first_proto if c.isalnum()]
            if not alpn_chars:
                # Use hex if no alphanumeric chars
                alpn_id = f"{ord(first_proto[0]):02x}{ord(first_proto[-1]):02x}"[-2:]
            elif len(alpn_chars) == 1:
                alpn_id = alpn_chars[0] * 2
            else:
                alpn_id = alpn_chars[0] + alpn_chars[-1]

    # Get protocol type (t=TCP)
    proto_type = "t"

    # Get TLS version (13 for TLS 1.3, etc)
    tls_version = client_hello["tls_version"]
    version_num = "13" if tls_version == "0x0303" else "12"

    # Get SNI flag (d=default with SNI, i=without SNI)
    sni_flag = "d" if client_hello["has_sni"] else "i"

    # Get extension count (2 chars)
    # Filter out GREASE extensions (values that are 0x0a0a, 0x1a1a, etc)
    non_grease_exts = [
        ext
        for ext in client_hello["extensions"]
        if not (ext["raw_type"] & 0x0F0F == 0x0A0A)
    ]
    ext_count = f"{len(non_grease_exts):02d}"

    # Get cipher suite count (2 chars)
    cs_count = f"{len(cipher_suites):02d}"

    return f"{proto_type}{version_num}{sni_flag}{cs_count}{ext_count}{alpn_id}_{c_hash}_{e_hash}"


def main():
    # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # context.load_cert_chain("cert.pem", "key.pem")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen(1)

    print("Server listening on port 443...")

    while True:
        try:
            client, addr = server.accept()
            print(f"\nConnection from {addr}")

            data = client.recv(4096)
            if not data.startswith(b"\x16\x03"):
                print("Not a TLS connection")
                client.close()
                continue

            client_hello = parse_client_hello(data)

            print("\nTLS Client Hello Details:")
            print(f"TLS Version: {client_hello['tls_version']}")
            print(f"SNI: {client_hello['has_sni']}")
            print("\nCipher Suites:")
            for cs in client_hello["cipher_suites"]:
                print(f"  0x{cs:04x}")

            print("\nExtensions:")
            for ext in client_hello["extensions"]:
                print(f"\n  {ext['type']} (0x{ext['raw_type']:04x}):")
                for key, value in ext.items():
                    if key not in ["type", "raw_type"]:
                        print(f"    {key}: {value}")

            ja4 = compute_ja4(client_hello)
            print("\nJA4 Fingerprint:", ja4)

            client.close()

        except Exception as e:
            print(f"Error: {e}")
            continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        sys.exit(0)

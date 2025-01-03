#!/usr/bin/env python3

import sys

# TLS Cipher Suite mapping from IANA registry
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
CIPHER_SUITES = {
    # NULL cipher suites (mostly for testing)
    "0x0000": "TLS_NULL_WITH_NULL_NULL",
    "0x0001": "TLS_RSA_WITH_NULL_MD5",
    "0x0002": "TLS_RSA_WITH_NULL_SHA",
    "0x003B": "TLS_RSA_WITH_NULL_SHA256",
    # Legacy cipher suites
    "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x000A": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    # Standard RSA cipher suites
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0033": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x0039": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "0x003c": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "0x003d": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "0x0067": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "0x006b": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "0x009e": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "0x009f": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    # TLS 1.3 cipher suites
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0x1304": "TLS_AES_128_CCM_SHA256",
    "0x1305": "TLS_AES_128_CCM_8_SHA256",
    # ECDHE cipher suites
    "0xc009": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "0xc00a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0xc023": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "0xc024": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "0xc027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "0xc028": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    # ChaCha20-Poly1305 cipher suites
    "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xccaa": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # PSK cipher suites
    "0x00ae": "TLS_PSK_WITH_AES_128_GCM_SHA256",
    "0x00af": "TLS_PSK_WITH_AES_256_GCM_SHA384",
    "0x00b0": "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    "0x00b1": "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "0x00b2": "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    "0x00b3": "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    # Additional ECDHE-PSK cipher suites
    "0xc0ac": "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    "0xc0ad": "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "0xc0ae": "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    # CCM cipher suites
    "0xc0a0": "TLS_RSA_WITH_AES_128_CCM",
    "0xc0a1": "TLS_RSA_WITH_AES_256_CCM",
    "0xc0a2": "TLS_DHE_RSA_WITH_AES_128_CCM",
    "0xc0a3": "TLS_DHE_RSA_WITH_AES_256_CCM",
    "0xc0a4": "TLS_PSK_WITH_AES_128_CCM",
    "0xc0a5": "TLS_PSK_WITH_AES_256_CCM",
    "0xc0a6": "TLS_DHE_PSK_WITH_AES_128_CCM",
    "0xc0a7": "TLS_DHE_PSK_WITH_AES_256_CCM",
    "0xc0a8": "TLS_PSK_WITH_AES_128_CCM_8",
    "0xc0a9": "TLS_PSK_WITH_AES_256_CCM_8",
    "0xc0aa": "TLS_PSK_DHE_WITH_AES_128_CCM_8",
    "0xc0ab": "TLS_PSK_DHE_WITH_AES_256_CCM_8",
}

# TLS Extension mapping
EXTENSIONS = {
    "0x0000": "server_name",
    "0x0001": "max_fragment_length",
    "0x0002": "client_certificate_url",
    "0x0003": "trusted_ca_keys",
    "0x0004": "truncated_hmac",
    "0x0005": "status_request",
    "0x0006": "user_mapping",
    "0x0007": "client_authz",
    "0x0008": "server_authz",
    "0x0009": "cert_type",
    "0x000a": "supported_groups",
    "0x000b": "ec_point_formats",
    "0x000c": "srp",
    "0x000d": "signature_algorithms",
    "0x000e": "use_srtp",
    "0x000f": "heartbeat",
    "0x0010": "application_layer_protocol_negotiation",
    "0x0011": "status_request_v2",
    "0x0012": "signed_certificate_timestamp",
    "0x0013": "client_certificate_type",
    "0x0014": "server_certificate_type",
    "0x0015": "padding",
    "0x0016": "encrypt_then_mac",
    "0x0017": "extended_master_secret",
    "0x0018": "token_binding",
    "0x0019": "cached_info",
    "0x001a": "tls_lts",
    "0x001b": "compress_certificate",
    "0x001c": "record_size_limit",
    "0x001d": "pwd_protect",
    "0x001e": "pwd_clear",
    "0x001f": "password_salt",
    "0x0020": "ticket_pinning",
    "0x0021": "tls_cert_with_extern_psk",
    "0x0022": "delegated_credentials",
    "0x0023": "session_ticket",
    "0x0024": "TLMSP",
    "0x0025": "TLMSP_proxying",
    "0x0026": "TLMSP_delegate",
    "0x0027": "supported_ekt_ciphers",
    "0x0028": "pre_shared_key",
    "0x0029": "early_data",
    "0x002b": "supported_versions",
    "0x002c": "cookie",
    "0x002d": "psk_key_exchange_modes",
    "0x002f": "certificate_authorities",
    "0x0030": "oid_filters",
    "0x0031": "post_handshake_auth",
    "0x0032": "signature_algorithms_cert",
    "0x0033": "key_share",
    "0x0034": "transparency_info",
    "0x0035": "connection_id",
    "0x0036": "connection_id_deprecated",
    "0x0037": "external_id_hash",
    "0x0038": "external_session_id",
    "0x0039": "quic_transport_parameters",
    "0x003a": "ticket_request",
    "0x003b": "dnssec_chain",
    "0x003c": "code_signing",
    "0x003d": "ech_outer_extensions",
    "0x003e": "supported_ech_config_versions",
    "0x003f": "ech_nonce",
    "0x0040": "ech",
    "0x0041": "post_handshake_message_extension",
    "0x0042": "external_extensions",
    "0x0043": "certificate_compression",
    "0x0044": "record_authentication",
    "0x0045": "client_cert_compression",
    "0x0046": "message_authentication",
    "0x0047": "client_hello_padding",
    "0x0048": "ech_is_inner",
    "0x0049": "sequence_number_encryption",
    "0x004a": "rrc",
    "0x004b": "encrypted_client_hello",
    "0x004c": "handshake_ack",
    "0x004d": "compressed_certificate",
    "0x004e": "proof_of_knowledge",
    "0x004f": "npn",
    "0x0050": "connection_id_deprecated_draft",
    "0x0051": "channel_id_new",
    "0x0052": "token_binding_draft",
    "0x0053": "token_binding_draft_tls13",
    "0x0054": "token_binding_draft_tls13_ietf",
    "0x0055": "token_binding_draft_tls13_ietf_final",
    "0x0056": "token_binding_draft_tls13_ietf_final2",
    "0x3374": "next_protocol_negotiation",
    "0xff01": "renegotiation_info",
}

# Signature Algorithms mapping from TLS 1.3 specification
# https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-28#section-4.2.3
SIGNATURE_ALGORITHMS = {
    # RSASSA-PKCS1-v1_5 algorithms
    "0x0401": "rsa_pkcs1_sha256",
    "0x0501": "rsa_pkcs1_sha384",
    "0x0601": "rsa_pkcs1_sha512",
    # ECDSA algorithms
    "0x0403": "ecdsa_secp256r1_sha256",
    "0x0503": "ecdsa_secp384r1_sha384",
    "0x0603": "ecdsa_secp521r1_sha512",
    # RSASSA-PSS algorithms with public key OID rsaEncryption
    "0x0804": "rsa_pss_rsae_sha256",
    "0x0805": "rsa_pss_rsae_sha384",
    "0x0806": "rsa_pss_rsae_sha512",
    # EdDSA algorithms
    "0x0807": "ed25519",
    "0x0808": "ed448",
    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    "0x0809": "rsa_pss_pss_sha256",
    "0x080a": "rsa_pss_pss_sha384",
    "0x080b": "rsa_pss_pss_sha512",
    # Legacy algorithms
    "0x0201": "rsa_pkcs1_sha1",
    "0x0203": "ecdsa_sha1",
    # Reserved Code Points
    "0x0000": "RESERVED",
    "0xFE00": "RESERVED_PRIVATE_USE_START",
    "0xFFFF": "RESERVED_PRIVATE_USE_END",
}


def parse_ja4_fingerprint(ja4_string):
    """Parse a JA4 fingerprint string into its components.
    Format: version_ciphersuites_extensions[_signature_algorithms]
    The last group is optional.
    """
    # Initialize the result structure
    result = {
        "TLS Version": {"Raw": None, "Version": None, "Additional Info": None},
        "Cipher Suites": [],
        "Extensions": [],
        "Signature Algorithms": [],
    }

    # Split the string into its components
    parts = ja4_string.split("_")
    if len(parts) < 3 or len(parts) > 4:
        return {
            "error": f"Invalid JA4 fingerprint format. Expected 3-4 groups, got {len(parts)}"
        }

    # 1. Parse TLS Version (always present)
    version_info = parts[0]
    tls_versions = {
        "t10": "TLS 1.0",
        "t11": "TLS 1.1",
        "t12": "TLS 1.2",
        "t13": "TLS 1.3",
    }
    version = version_info[:3]
    result["TLS Version"]["Raw"] = version_info
    result["TLS Version"]["Version"] = tls_versions.get(version, "Unknown")
    result["TLS Version"]["Additional Info"] = (
        version_info[3:] if len(version_info) > 3 else None
    )

    # 2. Parse Cipher Suites (always present)
    if parts[1]:
        for cipher in parts[1].split(","):
            hex_cipher = f"0x{cipher}"
            result["Cipher Suites"].append(
                {
                    "hex": hex_cipher,
                    "name": CIPHER_SUITES.get(hex_cipher, "Unknown Cipher Suite"),
                }
            )

    # 3. Parse Extensions (always present)
    if parts[2]:
        for ext in parts[2].split(","):
            hex_ext = f"0x{ext}"
            result["Extensions"].append(
                {"hex": hex_ext, "name": EXTENSIONS.get(hex_ext, "Unknown Extension")}
            )

    # 4. Parse Signature Algorithms (optional)
    if len(parts) >= 4 and parts[3]:
        for sig in parts[3].split(","):
            hex_sig = f"0x{sig}"
            result["Signature Algorithms"].append(
                {
                    "hex": hex_sig,
                    "name": SIGNATURE_ALGORITHMS.get(
                        hex_sig, "Unknown Signature Algorithm"
                    ),
                }
            )

    return result


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ja4_fingerprint_reader.py <ja4_fingerprint>")
        print(
            "Example: python3 ja4_fingerprint_reader.py t13d_1301,1302,1303_000a,000b,000d_0403,0804"
        )
        sys.exit(1)

    ja4_string = sys.argv[1]
    result = parse_ja4_fingerprint(ja4_string)

    # Pretty print the results
    print("\nJA4 Fingerprint Analysis:")
    print("-" * 50)

    # Print TLS Version info
    print(f"TLS Version: {result['TLS Version']['Version']}")
    print(f"Version Raw Info: {result['TLS Version']['Raw']}")
    if result["TLS Version"]["Additional Info"]:
        print(f"Additional Version Info: {result['TLS Version']['Additional Info']}")

    # Print Cipher Suites
    print(f"\nCipher Suites ({len(result['Cipher Suites'])}):")
    for cipher in result["Cipher Suites"]:
        print(f"  - {cipher['hex']}: {cipher['name']}")

    # Print Extensions
    print(f"\nExtensions ({len(result['Extensions'])}):")
    for ext in result["Extensions"]:
        print(f"  - {ext['hex']}: {ext['name']}")

    # Print Signature Algorithms if present
    if result["Signature Algorithms"]:
        print(f"\nSignature Algorithms ({len(result['Signature Algorithms'])}):")
        for sig in result["Signature Algorithms"]:
            print(f"  - {sig['hex']}: {sig['name']}")


if __name__ == "__main__":
    main()

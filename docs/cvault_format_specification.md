CVAULT FILE FORMAT v1  (all multi-byte integers are big-endian / network order)

Offset  Size   Field
------  ----   ---------------------------------------------
0       6      magic            = b"CVAULT"
6       2      version          = uint16 (currently 1)
8       16     document_id      = UUID (RFC 4122 bytes)
24      8      ciphertext_len   = uint64
32      4      aad_len          = uint32  (length of authenticated metadata block)
36      12     nonce            = 12 random bytes (AES-GCM)
48      2      mime_len         = uint16
50      2      algo_len         = uint16
52      ...    mime             = UTF-8, mime_len bytes  (typically "application/pdf")
...     ...    algorithm        = UTF-8, algo_len bytes (currently "AES-256-GCM")
...     4      policy_ref_len   = uint32
...     ...    policy_ref       = UTF-8 (opaque policy identifier string)
...     ...    aad              = aad_len bytes  (canonical authenticated metadata block)
...     ...    ciphertext       = ciphertext_len bytes (AES-GCM, tag appended by GCM)
...     32     body_sha256      = SHA-256 of (aad || ciphertext)   for fast pre-auth integrity check
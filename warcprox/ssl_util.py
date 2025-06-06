import ssl
from urllib3.util.ssl_ import create_urllib3_context

def create_chrome_ssl_context():
    """Create a custom SSL context imitating Chrome.
    Chrome typically uses these cipher suites (as of Chrome 120+)
    """
    context = create_urllib3_context()
    context.set_ciphers(
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA"
    )

    # Set TLS versions (Chrome supports 1.2 and 1.3)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    return context


def create_firefox_ssl_context():
    """Create a custom SSL context imitating Firefox.
    Firefox (as of recent versions) uses these cipher suites
    """
    context = create_urllib3_context()
    context.set_ciphers(
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    # Set TLS versions (Firefox supports TLS 1.2 and 1.3)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # Firefox preferred elliptic curves. None is available in Python so we stick to the defaults.
    # if hasattr(context, "set_ecdh_curve"):
    #     context.set_ecdh_curve("X25519:secp256r1:secp384r1")

    return context

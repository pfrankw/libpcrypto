add_library( pcrypto sha1.c sha256.c sha512.c base58.c base64.c random.c pk.c aes.c x509.c ssl.c ext/libbase58/base58.c )
install( TARGETS pcrypto DESTINATION lib )

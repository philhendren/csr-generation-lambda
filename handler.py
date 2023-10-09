import OpenSSL.crypto


def handler(event, context):
    # Extract values from JSON payload
    common_name = event['common_name']
    organization = event['organization']
    country = event['country']

    # Generate a new private key
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Create a CSR (Certificate Signing Request) object
    req = OpenSSL.crypto.X509Req()
    req.set_pubkey(key)
    req.get_subject().CN = common_name
    req.get_subject().O = organization
    req.get_subject().C = country
    req.sign(key, "sha256")

    # Serialize the CSR to PEM format
    csr_pem = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req).decode('utf-8')

    return {
        'csr_pem': csr_pem
    }

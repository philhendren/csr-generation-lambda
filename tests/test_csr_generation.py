import OpenSSL.crypto
import unittest
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import handler

# Mocking the event parameter with sample data
sample_event = {
    'common_name': 'example.com',
    'organization': 'Example Org',
    'country': 'US'
}


class TestLambdaHandler(unittest.TestCase):

    def test_lambda_handler(self):
        # Call the lambda_handler function with the sample_event
        response = handler.handler(sample_event, None)

        # Assert the response contains the 'csr_pem' key
        self.assertIn('csr_pem', response)

        # Deserialize the PEM-formatted CSR
        csr_pem = response['csr_pem']
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem.encode('utf-8'))

        # Assert the CSR's common name, organization, and country match the sample_event data
        self.assertEqual(csr.get_subject().CN, sample_event['common_name'])
        self.assertEqual(csr.get_subject().O, sample_event['organization'])
        self.assertEqual(csr.get_subject().C, sample_event['country'])

        # Assert the CSR's public key is of type RSA and has a bit length of 2048
        public_key = csr.get_pubkey()
        self.assertEqual(public_key.type(), OpenSSL.crypto.TYPE_RSA)
        self.assertEqual(public_key.bits(), 2048)



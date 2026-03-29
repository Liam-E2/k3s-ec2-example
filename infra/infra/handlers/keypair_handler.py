import base64
import hashlib
import json
import os
import subprocess
import tempfile
import boto3


def handler(event, context):
    props = event['ResourceProperties']
    secret_arn = props['SecretArn']
    bucket_name = props['BucketName']
    issuer_url = props['IssuerUrl']
    region = props['Region']

    if event['RequestType'] == 'Delete':
        return {}

    sm_client = boto3.client('secretsmanager', region_name=region)

    if event['RequestType'] == 'Create':
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, 'private.pem')
            subprocess.run(
                ['openssl', 'genrsa', '-out', key_path, '2048'],
                check=True, capture_output=True,
            )
            with open(key_path) as f:
                priv_pem = f.read()
        sm_client.put_secret_value(SecretId=secret_arn, SecretString=priv_pem)
    else:
        # Update: reuse existing key, only re-upload JWKS
        priv_pem = sm_client.get_secret_value(SecretId=secret_arn)['SecretString']

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, 'private.pem')
        with open(key_path, 'w') as f:
            f.write(priv_pem)
        mod_result = subprocess.run(
            ['openssl', 'rsa', '-in', key_path, '-noout', '-modulus'],
            check=True, capture_output=True, text=True,
        )
        pub_der = subprocess.run(
            ['openssl', 'rsa', '-in', key_path, '-pubout', '-outform', 'DER'],
            check=True, capture_output=True,
        ).stdout

    mod_hex = mod_result.stdout.strip().split('=', 1)[1]

    n_int = int(mod_hex, 16)
    n_bytes = n_int.to_bytes((n_int.bit_length() + 7) // 8, 'big')
    e_bytes = (65537).to_bytes(3, 'big')

    def b64url(b):
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

    n_b64 = b64url(n_bytes)
    e_b64 = b64url(e_bytes)

    # SHA256 of DER-encoded SubjectPublicKeyInfo — matches k3s key ID computation
    kid = b64url(hashlib.sha256(pub_der).digest())

    jwks = {
        'keys': [{
            'kty': 'RSA', 'use': 'sig', 'alg': 'RS256',
            'kid': kid,
            'n': n_b64,
            'e': e_b64,
        }]
    }
    discovery = {
        'issuer': issuer_url,
        'jwks_uri': f'{issuer_url}/openid/v1/jwks',
        'authorization_endpoint': 'urn:kubernetes:programmatic_authorization',
        'response_types_supported': ['id_token'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
    }

    s3_client = boto3.client('s3', region_name=region)
    s3_client.put_object(
        Bucket=bucket_name, Key='openid/v1/jwks',
        Body=json.dumps(jwks), ContentType='application/json',
    )
    s3_client.put_object(
        Bucket=bucket_name, Key='.well-known/openid-configuration',
        Body=json.dumps(discovery), ContentType='application/json',
    )

    return {'Data': {'IssuerUrl': issuer_url}}

import * as crypto from 'crypto';
import * as x509 from '@peculiar/x509';
import cbor from 'cbor';
import { Buffer } from 'buffer';
import fs from 'fs'
import { base64 } from '@phala/wapo-env/guest'

async function importPublicKey(spkiBase64: string) {
  const binaryDer = base64.decode(spkiBase64)
  return await crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['verify']
  )
}
// Constants
// const APP_ID = '4RKXM42395.junyaoc.Toy-Cam';
const APP_ID = '4RKXM42395.junyaoc.Miracam';
const DEV_MODE = true;

// Helper functions
function getRPIdHash(authData) {
  return authData.subarray(0, 32);
}

function getSignCount(authData) {
  return authData.readInt32BE(33);
}

async function verifyAppAttestCertificateChain(certificates) {
  if (certificates.length !== 2) {
    throw new Error('Expected 2 certificates in x5c array');
  }
  const [leafCertBuffer, intermediateCertBuffer] = certificates;

  const leafCert = new x509.X509Certificate(leafCertBuffer);
  const intermediateCert = new x509.X509Certificate(intermediateCertBuffer);
  // const response = await fetch('https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem');
  // const appleRootCert = await response.text();

  const appleRootCert = 
  `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

    const h = `30820221308201a7a00302010202100bf3be0ef1cdd2e0fb8c6e721f621798300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333235335a170d3435303331353030303030305a30523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b81040022036200044531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd656141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35a3423040300f0603551d130101ff040530030101ff301d0603551d0e04160414ac91105333bdbe6841ffa70ca9e5faeae5e58aa1300e0603551d0f0101ff040403020106300a06082a8648ce3d040303036800306502304201469c1cafb2255ba532b04a06b490fd1ef047834b8fac4264ef6fbbe7e773b9f8545781e2e1a49d3acac0b93eb3b2023100a79538c43804825945ec49f755c13789ec5966d29e627a6ab628d5a3216b696548c9dfdd81a9e6addb82d5b993046c03`

    const rootCert = new x509.X509Certificate(h)


  const chain = [leafCert, intermediateCert, rootCert];
  for (let i = 0; i < chain.length - 1; i++) {
    const cert = chain[i];
    const issuer = chain[i + 1];

    if (cert.issuer.toString() !== issuer.subject.toString()) {
      throw new Error(`Certificate at index ${i} was not issued by the next certificate in the chain`);
    }

    const verified = await cert.verify({
      publicKey: await issuer.publicKey.export(),
    });
    return 72

    if (!verified) {
      throw new Error(`Failed to verify certificate at index ${i}`);
    }

  }
  return 54

  const oidAppAttest = '1.2.840.113635.100.8.2';
  const appAttestExtension = leafCert.extensions.find(ext => ext.type === oidAppAttest);
  if (!appAttestExtension) {
    throw new Error('Leaf certificate does not contain the App Attest extension');
  }

  let extAsnString = appAttestExtension.toString('asn');
  let credCertPublicKey = leafCert.publicKey.rawData.slice(-65);
  let credCertPublicKeyHex = Buffer.from(credCertPublicKey).toString('hex');
  let expectedKeyId = crypto.createHash('sha256').update(Buffer.from(credCertPublicKeyHex, 'hex')).digest().toString('base64');

  const expectedIntermediateSubject = 'CN=Apple App Attestation CA 1, O=Apple Inc., ST=California';
  if (intermediateCert.subject.toString() !== expectedIntermediateSubject) {
    throw new Error('Intermediate certificate is not the expected Apple App Attestation CA');
  }

  return { chainValid: true, extAsnString, expectedKeyId };
}

export async function verifyAttestation(keyId, attestation, retrieveNonce) {
  const attestationObject = Buffer.from(attestation, 'base64');
  const attestationObjectJSON = cbor.decode(attestationObject);
  //   console.log(attestationObjectJSON)

  if (attestationObjectJSON.fmt !== 'apple-appattest') {
    throw new Error('Unsupported attestation format');
  }

  try {
    // const { chainValid, extAsnString, expectedKeyId } = await verifyAppAttestCertificateChain(attestationObjectJSON.attStmt.x5c);
    const num = await verifyAppAttestCertificateChain(attestationObjectJSON.attStmt.x5c);
    return num
  } catch (error) {
    return { error: 'Failed to verify attestation certificate chain', details: error.message }
  }

  let authData = attestationObjectJSON.authData;
  return 88
  // Retrieve the stored nonce
  const nonce = await retrieveNonce(keyId);
  // const nonceHash = crypto.createHash('sha256').update(Buffer.from(nonce, 'utf-8')).digest();
  const clientDataHash = Buffer.concat([authData, Buffer.from(nonce, 'base64')]);
  const clientDataHashSha256 = crypto.createHash('sha256').update(clientDataHash).digest('hex');

  let clientDataValid = extAsnString.endsWith(clientDataHashSha256);
  let keyIdValid = keyId === expectedKeyId;

  let appIdHash = crypto.createHash('sha256').update(Buffer.from(APP_ID, 'utf-8')).digest().toString('hex');
  let rpIdHash = getRPIdHash(authData);
  let rpIdHashHex = rpIdHash.toString('hex');
  let isRPIdHashValid = rpIdHashHex === appIdHash;
  return 100
  const signCount = getSignCount(authData);
  let isSignCountValid = signCount === 0;

  const endIndex = DEV_MODE ? 53 : 46;
  const aaGuid = authData.subarray(37, endIndex).toString();
  const expectedGuid = DEV_MODE ? 'appattestdevelop' : 'appattest';
  let isAAGuidValid = aaGuid === expectedGuid;

  const credIdLen = authData.subarray(53, 55);
  if (credIdLen[0] !== 0 || credIdLen[1] !== 32) {
    throw new Error('Invalid credId length');
  }

  const credId = authData.subarray(55, 87);
  let isCredIdValid = credId.toString('base64') === keyId;

  console.log(116, {
    // success: true,
    chainValid,
    clientDataValid,
    keyIdValid,
    isRPIdHashValid,
    isSignCountValid,
    isAAGuidValid,
    isCredIdValid,
  })

  return chainValid && clientDataValid && keyIdValid && isRPIdHashValid && isSignCountValid && isAAGuidValid && isCredIdValid
  // return {
  //   // success: true,
  //   chainValid,
  //   clientDataValid,
  //   keyIdValid,
  //   isRPIdHashValid,
  //   isSignCountValid,
  //   isAAGuidValid,
  //   isCredIdValid,
  // };
}

// const attestdata = require('./attestdata.json')
//  verifyAttestation(attestdata.key_id, attestdata.attestation_receipt, () => attestdata.challenge_data).then(console.log)

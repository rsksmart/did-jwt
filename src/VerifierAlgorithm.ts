import { ec as EC } from 'elliptic'
import { sha256, toEthereumAddress, hashPersonalMessage } from './Digest'
import { verify } from '@stablelib/ed25519'
import { PublicKey } from 'did-resolver'
import { encode } from '@stablelib/utf8'
import { base64ToBytes, base64urlToBytes, bytesToHex, EcdsaSignature } from './util'

const secp256k1 = new EC('secp256k1')

// https://github.com/ethereumjs/ethereumjs-util/blob/dd2882d790c1d3b50b75bee6f88031433cbd5bef/src/signature.ts#L146
// calculate sig recovery param as per eip 155
function calculateSigRecovery(v: number, chainId?: number): number {
  return v < 27 ? v : (chainId ? v - (2 * chainId + 35) : v - 27)
}

// converts a JOSE signature to it's components
export function toSignatureObject(signature: string, recoverable = false, chainId?: number): EcdsaSignature {
  const rawsig: Uint8Array = base64urlToBytes(signature)
  if (rawsig.length !== (recoverable ? 65 : 64)) {
    throw new Error('wrong signature length')
  }
  const r: string = bytesToHex(rawsig.slice(0, 32))
  const s: string = bytesToHex(rawsig.slice(32, 64))
  const sigObj: EcdsaSignature = { r, s }
  if (recoverable) {
    sigObj.recoveryParam = calculateSigRecovery(rawsig[64], chainId)
  }
  return sigObj
}

const sha256OrPersonal = (data: string, ethPersonal: boolean) => !ethPersonal ? sha256(data) : hashPersonalMessage(data)

export function verifyES256K(data: string, signature: string, authenticators: PublicKey[], ethPersonal = false): PublicKey {
  const hash: Uint8Array = sha256OrPersonal(data, ethPersonal)
  const sigObj: EcdsaSignature = toSignatureObject(signature)
  const fullPublicKeys = authenticators.filter(({ publicKeyHex }) => {
    return typeof publicKeyHex !== 'undefined'
  })
  const ethAddressKeys = authenticators.filter(({ ethereumAddress }) => {
    return typeof ethereumAddress !== 'undefined'
  })

  let signer: PublicKey = fullPublicKeys.find(({ publicKeyHex }) => {
    try {
      return secp256k1.keyFromPublic(publicKeyHex, 'hex').verify(hash, sigObj)
    } catch (err) {
      return false
    }
  })

  if (!signer && ethAddressKeys.length > 0) {
    signer = verifyRecoverableES256K(data, signature, ethAddressKeys, ethPersonal)
  }

  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

const checkSignatureAgainstSigner = (data: string, authenticators: PublicKey[], ethPersonal = false) => (sigObj: EcdsaSignature): PublicKey => {
  const hash: Uint8Array = sha256OrPersonal(data, ethPersonal)
  const recoveredKey: any = secp256k1.recoverPubKey(hash, sigObj, sigObj.recoveryParam)
  const recoveredPublicKeyHex: string = recoveredKey.encode('hex')
  const recoveredCompressedPublicKeyHex: string = recoveredKey.encode('hex', true)
  const recoveredAddress: string = toEthereumAddress(recoveredPublicKeyHex)

  const signer: PublicKey = authenticators.find(
    ({ publicKeyHex, ethereumAddress }) =>
      publicKeyHex === recoveredPublicKeyHex ||
      publicKeyHex === recoveredCompressedPublicKeyHex ||
      ethereumAddress === recoveredAddress
  )

  return signer
}

export function verifyRecoverableES256K(data: string, signature: string, authenticators: PublicKey[], ethPersonal = false, chainId?: number): PublicKey {
  let signatures: EcdsaSignature[]
  if (signature.length > 86) {
    signatures = [toSignatureObject(signature, true, chainId)]
  } else {
    const so = toSignatureObject(signature, false, chainId)
    signatures = [
      { ...so, recoveryParam: 0 },
      { ...so, recoveryParam: 1 }
    ]
  }

  const signer: PublicKey[] = signatures.map(checkSignatureAgainstSigner(data, authenticators, ethPersonal)).filter(key => key != null)

  if (signer.length === 0) throw new Error('Signature invalid for JWT')
  return signer[0]
}

export function verifyEd25519(data: string, signature: string, authenticators: PublicKey[]): PublicKey {
  const clear: Uint8Array = encode(data)
  const sig: Uint8Array = base64urlToBytes(signature)
  const signer: PublicKey = authenticators.find(({ publicKeyBase64 }) =>
    verify(base64ToBytes(publicKeyBase64), clear, sig)
  )
  if (!signer) throw new Error('Signature invalid for JWT')
  return signer
}

type Verifier = ((data: string, signature: string, authenticators: PublicKey[], eip155?: boolean, chainId?: number) => PublicKey)

interface Algorithms {
  [name: string]: Verifier
}
const algorithms: Algorithms = {
  ES256K: verifyES256K,
  'ES256K-R': verifyRecoverableES256K,
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: verifyEd25519,
  EdDSA: verifyEd25519
}

function VerifierAlgorithm(alg: string): Verifier {
  const impl: Verifier = algorithms[alg]
  if (!impl) throw new Error(`Unsupported algorithm ${alg}`)
  return impl
}

VerifierAlgorithm.toSignatureObject = toSignatureObject

export default VerifierAlgorithm

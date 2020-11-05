
import { fromRpcSig, toBuffer, hashPersonalMessage, ecsign, bufferToHex } from 'ethereumjs-util'
import { concatSig } from 'eth-sig-util'

// https://github.com/MetaMask/eth-sig-util/blob/master/index.ts#L299
function personalSign (privateKey, msgParams, chainId?): string {
  const message = toBuffer(msgParams.data);
  const msgHash = hashPersonalMessage(message);
  const sig = ecsign(msgHash, privateKey); // adds 27 by default
  // https://github.com/ethereumjs/ethereumjs-util/blob/master/src/signature.ts#L27
  sig.v = chainId ? sig.v + (chainId * 2 + 35) - 27 : sig.v // decreases 27 added by ecsign
  const serialized = bufferToHex(concatSig(sig.v, sig.r, sig.s));
  return serialized;
}

export const ethPersonalSigner = (privateKey: string, chainId?: number) => (data) => {
  const { r, s, v } = fromRpcSig(
    personalSign(
      Buffer.from(privateKey, 'hex'), { data }, chainId
    )
  )

  return Promise.resolve({
    r: r.toString('hex'),
    s: s.toString('hex'),
    recoveryParam: v
  })
}

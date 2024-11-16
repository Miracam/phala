import '@phala/wapo-env'
import { Hono } from 'hono/tiny'
import { handle } from '@phala/wapo-env/guest'
import { privateKeyToAccount } from 'viem/accounts'
import {
    keccak256,
    http,
    type Address,
    createPublicClient,
    PrivateKeyAccount,
    verifyMessage,
    createWalletClient,
    parseGwei
} from 'viem'
import { baseSepolia } from 'viem/chains'
import superjson from 'superjson'
import { verifyAttestation } from './attestation.ts'
import crypto from 'crypto'
import fs from 'fs'

export const app = new Hono()

const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(),
})
const walletClient = createWalletClient({
    chain: baseSepolia,
    transport: http(),
})

function getECDSAAccount(salt: string): PrivateKeyAccount {
    const derivedKey = Wapo.deriveSecret(salt)
    const keccakPrivateKey = keccak256(derivedKey)
    return privateKeyToAccount(keccakPrivateKey)
}

async function signData(account: PrivateKeyAccount, data: string): Promise<any> {
    let result = {
        derivedPublicKey: account.address,
        data: data,
        signature: ''
    }
    const publicKey = account.address
    console.log(`Signing data [${data}] with Account [${publicKey}]`)
    const signature = await account.signMessage({
        message: data,
    })
    console.log(`Signature: ${signature}`)
    result.signature = signature
    return result
}

async function verifyData(account: PrivateKeyAccount, data: string, signature: any): Promise<any> {
    let result = {
        derivedPublicKey: account.address,
        data: data,
        signature: signature,
        valid: false
    }
    const publicKey = account.address
    console.log("Verifying Signature with PublicKey ", publicKey)
    const valid = await verifyMessage({
        address: publicKey,
        message: data,
        signature,
    })
    console.log("Is signature valid? ", valid)
    result.valid = valid
    return result
}

async function sendTransaction(account: PrivateKeyAccount, to: Address, gweiAmount: string): Promise<any> {
    let result = {
        derivedPublicKey: account.address,
        to: to,
        gweiAmount: gweiAmount,
        hash: '',
        receipt: {}
    }
    console.log(`Sending Transaction with Account ${account.address} to ${to} for ${gweiAmount} gwei`)
    // @ts-ignore
    const hash = await walletClient.sendTransaction({
        account,
        to,
        value: parseGwei(`${gweiAmount}`),
    })
    console.log(`Transaction Hash: ${hash}`)
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    console.log(`Transaction Status: ${receipt.status}`)
    result.hash = hash
    result.receipt = receipt
    return result
}

app.get('/', async (c) => {
    let vault: Record<string, string> = {}
    let queries = c.req.queries() || {}
    let result = {};
    try {
        vault = JSON.parse(process.env.secret || '')
    } catch (e) {
        console.error(e)
        return c.json({ error: "Failed to parse secrets" })
    }
    const secretSalt = (vault.secretSalt) ? vault.secretSalt as string : 'SALTY_BAE'
    const getType = (queries.type) ? queries.type[0] as string : ''
    const account = getECDSAAccount(secretSalt)
    const data = (queries.data) ? queries.data[0] as string : ''
    console.log(`Type: ${getType}, Data: ${data}`)
    try {
        if (getType == 'sendTx') {
            result = (queries.to && queries.gweiAmount) ?
              await sendTransaction(account, queries.to[0] as Address, queries.gweiAmount[0]) :
              { message: 'Missing query [to] or [gweiAmount] in URL'}
        } else if (getType == 'sign') {
            result = (data) ? await signData(account, data) : { message: 'Missing query [data] in URL'}
        } else if (getType == 'verify') {
            if (data && queries.signature) {
                result = await verifyData(account, data, queries.signature[0] as string)
            } else {
                result = { message: 'Missing query [data] or [signature] in URL'}
            }
        } else if (getType == 'attest') {
            result = await attest(account, data)
        } else {
            result = { derivedPublicKey: account.address }
        }
    } catch (error) {
        console.error('Error:', error)
        result = { message: error }
    }
    const { json, meta } = superjson.serialize(result)
    return c.json(json)
})

const proof = {"secp256r1_pubkey":"BKSPNyhyF7mfptZmtr7vP6le8WVa9yrRStEK+KboeewRUBhNH4MxM8Id+RzM5kUO5xoq3CCTabCM+C29tgC3KXY=","attestation_receipt":"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","ethereum_address":"0xf6E37cEE1F92CAF16c8c1F37a54680c87dcAF205","lit_ciphertext":"krJrQBkbEa3ng6vyPZaZahc/xEPOXhWjBNiFvL4kZIEG4kr5Olgo01kbUlym5uCPUiIUIJu7z1LaGWXwqaCWobqc1n11TEXS+sEUIJUQE0xBts32iAJL+zAiPWe5UWA+3y7P95BTNArHIyqKP2DRuLQ4AuAUV0paEYcpWeyHr8mlQqYbpdyyM8EPdnklFXBPrB4C","key_id":"epE8EyZIJVvPRZ8the/TRY4AirjUcW0rS67sqfw+LEQ=","challenge_data":"rLYZFKaF6vri2HV9c7tSy5bho5ChjgF4Ix/u1LNIdeo=","lit_hash":"b092ca8037768953d62fb0737100f28ca9c8584c00e0fb4c8e1a8a63be5fb42e","challenge_data_plain":"ethereum_address=0xf6E37cEE1F92CAF16c8c1F37a54680c87dcAF205&lit_ciphertext=krJrQBkbEa3ng6vyPZaZahc/xEPOXhWjBNiFvL4kZIEG4kr5Olgo01kbUlym5uCPUiIUIJu7z1LaGWXwqaCWobqc1n11TEXS+sEUIJUQE0xBts32iAJL+zAiPWe5UWA+3y7P95BTNArHIyqKP2DRuLQ4AuAUV0paEYcpWeyHr8mlQqYbpdyyM8EPdnklFXBPrB4C&lit_hash=b092ca8037768953d62fb0737100f28ca9c8584c00e0fb4c8e1a8a63be5fb42e&secp256r1_pubkey=BKSPNyhyF7mfptZmtr7vP6le8WVa9yrRStEK+KboeewRUBhNH4MxM8Id+RzM5kUO5xoq3CCTabCM+C29tgC3KXY="}

async function attest(account: PrivateKeyAccount, url: string) {
    console.log("attest")
    // const url = c.req.query('url')

    // const proof = await fetch(url!).then(res => res.json())
  const { ethereum_address, key_id, challenge_data, lit_ciphertext, lit_hash, attestation_receipt, secp256r1_pubkey } = proof

  if (!attestation_receipt) {
    throw new Error('Missing key_id or attestation_receipt in the request body')
  }


  const challenge_data_hash = crypto.createHash('sha256').update(`ethereum_address=${ethereum_address}&lit_ciphertext=${lit_ciphertext}&lit_hash=${lit_hash}&secp256r1_pubkey=${secp256r1_pubkey}`).digest('base64')
  // console.log("challenge_data_hash", challenge_data_hash)
  if (challenge_data_hash !== challenge_data) {
    return {error: 'Challenge data hash mismatch', details: challenge_data_hash, expected: challenge_data}
  }
  console.log("verifyAttestation", key_id, attestation_receipt, challenge_data)
  try {
    const valid = await verifyAttestation(key_id, attestation_receipt, async () => challenge_data)
    return valid
  } catch (error) {
    return {error: 'Failed to verify attestation', details: error}
  }
//   return { valid, owner: ethereum_address, attester: secp256r1_pubkey }
}

app.post('/', async (c) => {
    const data = await c.req.json()
    console.log('user payload in JSON:', data)
    return c.json(data)
});

export default handle(app)

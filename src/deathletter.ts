import {
    createCipheriv,
    createDecipheriv,
    createHash,
    generateKeyPairSync,
    randomBytes,
    scryptSync,
    sign as cryptoSign,
    verify as cryptoVerify,
} from "node:crypto"

import {
    readFileSync,
    writeFileSync,
} from "node:fs"

const MAGIC = Buffer.from("DLP1")
const VERSION = 1

const NONCE_SIZE = 12
const TAG_SIZE = 16
const KEY_SIZE = 32

const DEFAULT_ROTATION_FORCE = 16
const DEFAULT_SEQUENCE_WINDOW = 48
const DEFAULT_EXTEND_ENCRYPTION = 0

const SCRYPT_N = 1 << 15
const SCRYPT_R = 8
const SCRYPT_P = 1

export interface DeathletterPacket {
    version: number
    flags: number

    rotationForce: number
    sequenceWindow: number
    extendEncryption: number

    keyId: string
    keyIdChecksum: Buffer

    salt: Buffer
    nonce: Buffer

    ciphertext: Buffer
    tag: Buffer

    signature?: Buffer
}

export interface DeathletterKeyPair {
    publicKey: string
    privateKey: string
}

export interface EncryptOptions {
    keyId?: string
    rotationForce?: number
    sequenceWindow?: number
    extendEncryption?: number
}

function sha256(data: Buffer | string): Buffer {
    return createHash("sha256")
        .update(data)
        .digest()
}

function rotateBuffer(buf: Buffer, shift: number): Buffer {
    const s = shift % buf.length
    return Buffer.concat([buf.subarray(s), buf.subarray(0, s)])
}

function u8(value: number): Buffer {
    const b = Buffer.allocUnsafe(1)
    b.writeUInt8(value, 0)
    return b
}

function u16(value: number): Buffer {
    const b = Buffer.allocUnsafe(2)
    b.writeUInt16BE(value, 0)
    return b
}

function u32(value: number): Buffer {
    const b = Buffer.allocUnsafe(4)
    b.writeUInt32BE(value, 0)
    return b
}

function readU8(buffer: Buffer, offset: number): number {
    return buffer.readUInt8(offset)
}

function readU16(buffer: Buffer, offset: number): number {
    return buffer.readUInt16BE(offset)
}

function readU32(buffer: Buffer, offset: number): number {
    return buffer.readUInt32BE(offset)
}

function ensureRange(
    value: number,
    min: number,
    max: number,
    name: string,
): void {
    if (!Number.isInteger(value) || value < min || value > max) {
        throw new Error(`${name} must be between ${min} and ${max}`)
    }
}

function xor(bytes: Buffer, key: Buffer) {
    const newBuffer = Buffer.alloc(bytes.length)

    for (let i = 0; i < bytes.length; i++)
        newBuffer[i] = bytes[i] ^ key[i % key.length]

    return newBuffer
}

function xor_k(bytes: Buffer, key: Buffer, salt: Buffer) {
    return xor(bytes, xor(key, salt))
}

export function deriveEncryptionKey(
    password: string,
    salt: Buffer,
    keyId: string,
    extendEncryption: number,
    rotationForce: number
): Buffer {
    const passwordMaterial = Buffer.from(password, "utf8")

    const context = Buffer.concat([
        Buffer.from("deathletter/1\0", "utf8"),
        Buffer.from(keyId, "utf8"),
    ])

    let passwordWithContext = Buffer.concat([
        passwordMaterial,
        sha256(context),
    ])

    const extraRounds = Array.from(passwordMaterial).reduce((a, b) => a + (b * passwordMaterial[0]), 0) * extendEncryption
    let activeSalt = Buffer.from(salt)

    for (let i = 0; i < extraRounds; i++) {
        const hash = sha256(Buffer.concat([
            passwordWithContext, activeSalt, u32(i)
        ])) as any

        passwordWithContext = rotateBuffer(hash, rotationForce * (i + 1)) as any
        if (i % 16 === 0)
            activeSalt = sha256(Buffer.concat([activeSalt, passwordWithContext, u32(i)])) as any
    } 

    return scryptSync(
        passwordWithContext,
        salt,
        KEY_SIZE,
        {
            N: SCRYPT_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            maxmem: 128 * 1024 * 1024,
        },
    )
}

function canonicalSignedData(packet: DeathletterPacket): Buffer {
    const keyId = Buffer.from(packet.keyId, "utf8")

    return Buffer.concat([
        MAGIC,
        u8(packet.version),
        u8(packet.flags),

        u8(packet.rotationForce),
        u8(packet.sequenceWindow),
        u8(packet.extendEncryption),

        u8(keyId.length),
        keyId,

        u8(packet.keyIdChecksum.length),
        packet.keyIdChecksum,

        u8(packet.salt.length),
        packet.salt,

        u8(packet.nonce.length),
        packet.nonce,

        u32(packet.ciphertext.length),
        packet.ciphertext,

        packet.tag,
    ])
}

export function encodePacket(packet: DeathletterPacket): Buffer {
    const rawKeyId = Buffer.from(packet.keyId, "utf8")

    ensureRange(packet.version, 0, 255, "version")
    ensureRange(packet.flags, 0, 255, "flags")
    ensureRange(packet.rotationForce, 0, 255, "rotationForce")
    ensureRange(packet.sequenceWindow, 0, 255, "sequenceWindow")
    ensureRange(packet.extendEncryption, 0, 255, "extendEncryption")

    if (packet.salt.length > 255) {
        throw new Error("salt is too long")
    }

    if (packet.nonce.length > 255) {
        throw new Error("nonce is too long")
    }

    if (packet.tag.length !== TAG_SIZE) {
        throw new Error("invalid GCM tag size")
    }

    const hasSignature = packet.signature !== undefined

    if (hasSignature && packet.signature!.length !== 64) {
        throw new Error("Ed25519 signature must be 64 bytes")
    }

    let keyId = xor_k(rawKeyId, packet.nonce, packet.salt)

    if (packet.signature)
        keyId = xor(keyId, packet.signature)

    if (keyId.length > 255) {
        throw new Error("keyId is too long")
    }

    return Buffer.concat([
        MAGIC,

        u8(packet.version),
        u8(packet.flags),

        u8(packet.rotationForce),
        u8(packet.sequenceWindow),
        u8(packet.extendEncryption),

        u8(keyId.length),
        keyId,

        u8(packet.keyIdChecksum.length),
        packet.keyIdChecksum,

        u8(packet.salt.length),
        packet.salt,

        u8(packet.nonce.length),
        packet.nonce,

        u32(packet.ciphertext.length),
        packet.ciphertext,

        packet.tag,

        u8(hasSignature ? 1 : 0),

        ...(hasSignature ? [packet.signature!] : []),
    ])
}


export function decodePacket(buffer: Buffer): DeathletterPacket {
    let offset = 0

    if (buffer.length < 4) {
        throw new Error("packet is too short")
    }

    if (!buffer.subarray(0, 4).equals(MAGIC)) {
        throw new Error("invalid DLCrypt magic")
    }

    offset += 4

    const version = readU8(buffer, offset++)
    const flags = readU8(buffer, offset++)

    if (version !== VERSION) {
        throw new Error(
            `unsupported DLCrypt version: ${version}`,
        )
    }

    const rotationForce = readU8(buffer, offset++)
    const sequenceWindow = readU8(buffer, offset++)
    const extendEncryption = readU8(buffer, offset++)

    const keyIdLength = readU8(buffer, offset++)

    if (offset + keyIdLength > buffer.length) {
        throw new Error("truncated keyId")
    }

    let rawKeyId = buffer
        .subarray(offset, offset + keyIdLength)

    offset += keyIdLength

    const keyChecksumLen = readU8(buffer, offset++)

    if (offset + keyChecksumLen > buffer.length) {
        throw new Error("truncated keyChecksum")
    }

    const keyIdChecksum = buffer
        .subarray(offset, offset + keyChecksumLen)

    offset += keyChecksumLen

    const saltLength = readU8(buffer, offset++)

    if (offset + saltLength > buffer.length) {
        throw new Error("truncated salt")
    }

    const salt = Buffer.from(
        buffer.subarray(offset, offset + saltLength),
    )

    offset += saltLength

    const nonceLength = readU8(buffer, offset++)

    if (offset + nonceLength > buffer.length) {
        throw new Error("truncated nonce")
    }

    const nonce = Buffer.from(
        buffer.subarray(offset, offset + nonceLength),
    )

    offset += nonceLength

    const ciphertextLength = readU32(buffer, offset)
    offset += 4

    if (
        offset + ciphertextLength + TAG_SIZE + 1 > buffer.length
    ) {
        throw new Error("truncated ciphertext")
    }

    const ciphertext = Buffer.from(
        buffer.subarray(
            offset,
            offset + ciphertextLength,
        ),
    )

    offset += ciphertextLength

    const tag = Buffer.from(
        buffer.subarray(offset, offset + TAG_SIZE),
    )

    offset += TAG_SIZE

    const signaturePresent = readU8(buffer, offset++)

    let signature: Buffer | undefined

    if (signaturePresent === 1) {
        if (offset + 64 > buffer.length) {
            throw new Error("truncated signature")
        }

        signature = Buffer.from(
            buffer.subarray(offset, offset + 64),
        )

        rawKeyId = xor(rawKeyId, signature)

        offset += 64
    } else if (signaturePresent !== 0) {
        throw new Error("invalid signature flag")
    }

    const keyId = xor_k(rawKeyId, nonce, salt).toString("utf8")
    const originalPlainKeyId = xor_k(Buffer.from(keyId, 'hex'), salt, nonce).toString('utf8')

    const decodedKeyChecksum = sha256(originalPlainKeyId)

    if (!decodedKeyChecksum.every((e, i) => keyIdChecksum[i] === e)) {
        throw new Error("invalid checksum")
    }

    if (offset !== buffer.length) {
        throw new Error("unexpected trailing data")
    }

    return {
        version,
        flags,

        rotationForce,
        sequenceWindow,
        extendEncryption,

        keyId,
        keyIdChecksum,

        salt,
        nonce,

        ciphertext,
        tag,

        signature,
    }
}

export function encrypt(
    plaintext: Buffer | string,
    password: string,
    options: EncryptOptions = {},
): DeathletterPacket {
    const rawKeyId = options.keyId ?? "default"
    
    const keyHash = sha256(rawKeyId)

    const rotationForce =
        options.rotationForce ?? DEFAULT_ROTATION_FORCE

    const sequenceWindow =
        options.sequenceWindow ?? DEFAULT_SEQUENCE_WINDOW

    const extendEncryption =
        options.extendEncryption ?? DEFAULT_EXTEND_ENCRYPTION

    const input =
        Buffer.isBuffer(plaintext)
            ? plaintext
            : Buffer.from(plaintext, "utf8")

    const salt = randomBytes(16)
    const nonce = randomBytes(NONCE_SIZE)

    const keyId = xor_k(Buffer.from(rawKeyId, 'utf8'), salt, nonce).toString('hex')

    const key = deriveEncryptionKey(
        password,
        salt,
        keyId,
        extendEncryption,
        rotationForce
    )

    const packetBase: DeathletterPacket = {
        version: VERSION,
        flags: 0,

        rotationForce,
        sequenceWindow,
        extendEncryption,

        keyId,
        keyIdChecksum: keyHash,

        salt,
        nonce,

        ciphertext: Buffer.alloc(0),
        tag: Buffer.alloc(0),
    }

    const aad = canonicalMetadata(packetBase)

    const cipher = createCipheriv(
        "aes-256-gcm",
        key,
        nonce,
    )

    cipher.setAAD(aad)

    const ciphertext = Buffer.concat([
        cipher.update(input),
        cipher.final(),
    ])

    const tag = cipher.getAuthTag()

    return {
        ...packetBase,
        ciphertext,
        tag,
    }
}

function canonicalMetadata(packet: DeathletterPacket): Buffer {
    const keyId = Buffer.from(packet.keyId, "utf8")

    return Buffer.concat([
        MAGIC,

        u8(packet.version),
        u8(packet.flags),

        u8(packet.rotationForce),
        u8(packet.sequenceWindow),
        u8(packet.extendEncryption),

        u8(keyId.length),
        keyId,

        u8(packet.keyIdChecksum.length),
        packet.keyIdChecksum,

        u8(packet.salt.length),
        packet.salt,

        u8(packet.nonce.length),
        packet.nonce,
    ])
}

export function decrypt(
    packet: DeathletterPacket,
    password: string,
): Buffer {
    const key = deriveEncryptionKey(
        password,
        packet.salt,
        packet.keyId,
        packet.extendEncryption,
        packet.rotationForce
    )

    const aad = canonicalMetadata(packet)

    const decipher = createDecipheriv(
        "aes-256-gcm",
        key,
        packet.nonce,
    )

    decipher.setAAD(aad)
    decipher.setAuthTag(packet.tag)

    return Buffer.concat([
        decipher.update(packet.ciphertext),
        decipher.final(),
    ])
}

export function signPacket(
    packet: DeathletterPacket,
    privateKey: string | Buffer,
): DeathletterPacket {
    const data = canonicalSignedData(packet)

    const signature = cryptoSign(
        null,
        data,
        privateKey,
    )

    return {
        ...packet,
        signature,
    }
}

export function verifyPacket(
    packet: DeathletterPacket,
    publicKey: string | Buffer,
): boolean {
    if (!packet.signature) {
        return false
    }

    const data = canonicalSignedData(packet)

    return cryptoVerify(
        null,
        data,
        publicKey,
        packet.signature,
    )
}

export function generateKeys(): DeathletterKeyPair {
    const {
        publicKey,
        privateKey,
    } = generateKeyPairSync("ed25519", {
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },

        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
    })

    return {
        publicKey,
        privateKey,
    }
}

export function encryptFile(
    inputPath: string,
    outputPath: string,
    password: string,
    privateKey?: string,
    options: EncryptOptions = {},
): DeathletterPacket {
    let packet = encrypt(
        readFileSync(inputPath),
        password,
        options,
    )

    if (privateKey) {
        packet = signPacket(
            packet,
            privateKey,
        )
    }

    writeFileSync(
        outputPath,
        encodePacket(packet),
    )

    return packet
}


export function decryptFile(
    inputPath: string,
    outputPath: string,
    password: string,
): Buffer {
    const packet = decodePacket(
        readFileSync(inputPath),
    )

    const plaintext = decrypt(
        packet,
        password,
    )

    writeFileSync(
        outputPath,
        plaintext,
    )

    return plaintext
}

export function encryptHex(
    plaintext: string,
    password: string,
    options?: EncryptOptions,
): string {
    const packet = encrypt(
        plaintext,
        password,
        options,
    )

    return encodePacket(packet).toString("hex")
}


export function decryptHex(
    hex: string,
    password: string,
): string {
    const packet = decodePacket(
        Buffer.from(hex, "hex"),
    )

    return decrypt(
        packet,
        password,
    ).toString("utf8")
}

export function inspectPacket(
    packet: DeathletterPacket,
): string {
    const signatureState =
        packet.signature
            ? "PRESENT"
            : "NONE"

    const decryptedKeyid = xor_k(Buffer.from(packet.keyId, 'hex'), packet.salt, packet.nonce).toString('utf8')

    return [
        "deathletter/1",
        "",
        "[packet]",
        ` version              ${packet.version}`,
        ` flags                0x${packet.flags.toString(16).padStart(2, "0")}`,
        "",
        ` rotation_force       ${packet.rotationForce}`,
        ` sequence_window      ${packet.sequenceWindow}`,
        ` extend_encryption    ${packet.extendEncryption}`,
        "",
        ` key_id               ${decryptedKeyid}`,
        ` salt                 ${packet.salt.toString("hex")}`,
        ` nonce                ${packet.nonce.toString("hex")}`,
        "",
        "[cipher]",
        " algorithm             AES-256-GCM",
        ` ciphertext            ${packet.ciphertext.length} bytes`,
        ` tag                   ${packet.tag.toString("hex")}`,
        "",
        "[identity]",
        ` signature             ${signatureState}`,
        "",
        "[status]",
        " packet                VALID",
    ].join("\n")
}


function usage(): void {
    console.log(`
deathletter/1

Usage:

  deathletter keygen <directory>

  deathletter encrypt <input> <output> <password>
      [--key-id <id>]
      [--private-key <file>]

  deathletter decrypt <input> <output> <password>

  deathletter sign <input> <output> <private-key>

  deathletter verify <input> <public-key>

  deathletter inspect <input>

Examples:

  deathletter keygen ./keys

  deathletter encrypt secret.txt secret.dlp mypassword \\
      --key-id example \\
      --private-key ./keys/private.pem

  deathletter decrypt secret.dlp secret.txt mypassword

  deathletter verify secret.dlp ./keys/public.pem

  deathletter inspect secret.dlp
`)
}


function getArg(
    args: string[],
    name: string,
): string | undefined {
    const index = args.indexOf(name)

    if (index === -1) {
        return undefined
    }

    return args[index + 1]
}


function requireArg(
    value: string | undefined,
    name: string,
): string {
    if (!value) {
        throw new Error(`missing argument: ${name}`)
    }

    return value
}


function main(): void {
    const args = process.argv.slice(2)
    const command = args[0]

    if (!command) {
        usage()
        return
    }

    if (command === "keygen") {
        const directory = requireArg(
            args[1],
            "directory",
        )

        const {
            publicKey,
            privateKey,
        } = generateKeys()

        const { mkdirSync } = require("node:fs")

        mkdirSync(directory, {
            recursive: true,
        })

        const privatePath =
            `${directory}/private.pem`

        const publicPath =
            `${directory}/public.pem`

        writeFileSync(
            privatePath,
            privateKey,
            { mode: 0o600 },
        )

        writeFileSync(
            publicPath,
            publicKey,
        )

        console.log(
            `[+] private key: ${privatePath}`,
        )

        console.log(
            `[+] public key:  ${publicPath}`,
        )

        return
    }

    if (command === "encrypt") {
        const input = requireArg(
            args[1],
            "input",
        )

        const output = requireArg(
            args[2],
            "output",
        )

        const password = requireArg(
            args[3],
            "password",
        )

        const keyId =
            getArg(args, "--key-id") ??
            "default"

        const extendStr = getArg(args, "--extend-encryption")
        const extendEncryption = extendStr ? parseInt(extendStr, 10) : DEFAULT_EXTEND_ENCRYPTION

        const rotationStr = getArg(args, "--rotation-force")
        const rotationForce = rotationStr ? parseInt(rotationStr, 10) : DEFAULT_ROTATION_FORCE

        const privateKeyPath =
            getArg(args, "--private-key")

        let privateKey: string | undefined

        if (privateKeyPath) {
            privateKey = readFileSync(
                privateKeyPath,
                "utf8",
            )
        }

        const packet = encryptFile(
            input,
            output,
            password,
            privateKey,
            {
                keyId,
                extendEncryption,
                rotationForce
            },
        )

        console.log(
            `[+] encrypted ${input} -> ${output}`,
        )

        console.log(
            `[+] key_id: ${packet.keyId}`,
        )

        console.log(
            `[+] signature: ${
                packet.signature
                    ? "YES"
                    : "NO"
            }`,
        )

        return
    }

    if (command === "decrypt") {
        const input = requireArg(
            args[1],
            "input",
        )

        const output = requireArg(
            args[2],
            "output",
        )

        const password = requireArg(
            args[3],
            "password",
        )

        const packet = decodePacket(
            readFileSync(input),
        )

        const plaintext = decrypt(
            packet,
            password,
        )

        writeFileSync(
            output,
            plaintext,
        )

        console.log(
            `[+] decrypted ${input} -> ${output}`,
        )

        return
    }

    if (command === "sign") {
        const input = requireArg(
            args[1],
            "input",
        )

        const output = requireArg(
            args[2],
            "output",
        )

        const privateKeyPath = requireArg(
            args[3],
            "private-key",
        )

        const packet = decodePacket(
            readFileSync(input),
        )

        const privateKey = readFileSync(
            privateKeyPath,
            "utf8",
        )

        const signed = signPacket(
            packet,
            privateKey,
        )

        writeFileSync(
            output,
            encodePacket(signed),
        )

        console.log(
            `[+] signed ${input} -> ${output}`,
        )

        return
    }

    if (command === "verify") {
        const input = requireArg(
            args[1],
            "input",
        )

        const publicKeyPath = requireArg(
            args[2],
            "public-key",
        )

        const packet = decodePacket(
            readFileSync(input),
        )

        const publicKey = readFileSync(
            publicKeyPath,
            "utf8",
        )

        const valid = verifyPacket(
            packet,
            publicKey,
        )

        if (valid) {
            console.log(
                "[+] signature: VALID",
            )

            console.log(
                "[+] identity:  AUTHENTIC",
            )

            process.exitCode = 0
        } else {
            console.log(
                "[-] signature: INVALID",
            )

            console.log(
                "[-] identity:  UNKNOWN",
            )

            process.exitCode = 1
        }

        return
    }

    if (command === "inspect") {
        const input = requireArg(
            args[1],
            "input",
        )

        const packet = decodePacket(
            readFileSync(input),
        )

        console.log(
            inspectPacket(packet),
        )

        return
    }

    usage()
}

const isMain =
    process.argv[1] &&
    (
        process.argv[1].endsWith("deathletter.ts") ||
        process.argv[1].endsWith("deathletter.js") ||
        process.argv[1].endsWith("deathletter")
    )

if (isMain) {
    try {
        main()
    } catch (error) {
        console.error(
            `[-] ${
                error instanceof Error
                    ? error.message
                    : String(error)
            }`,
        )

        process.exitCode = 1
    }
}
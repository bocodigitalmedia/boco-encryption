class Dependencies
  DEFAULT_CIPHER_IV_ALGORITHM: null
  DEFAULT_CIPHER_IV_BYTE_SIZE: null

  Crypto: null
  Error: null
  Buffer: null
  Stream: null

  constructor: (props) ->
    @[key] = val for own key, val of props

    @DEFAULT_CIPHER_IV_ALGORITHM ?= 'aes-256-ctr'
    @DEFAULT_CIPHER_IV_BYTE_SIZE ?= 16

    @Error ?= try Error
    @Buffer ?= try Buffer

    if typeof require is 'function'
      @Crypto ?= require 'crypto'
      @Stream ?= require 'stream'

configure = (props) ->
  {
    DEFAULT_CIPHER_IV_ALGORITHM
    DEFAULT_CIPHER_IV_BYTE_SIZE
    Error
    Crypto
    Buffer
    Stream
    Base64Stream
  } = dependencies = new Dependencies(props)

  class Exception extends Error
    payload: null

    @getMessage: (payload) -> null

    constructor: (payload) ->
      @name = @constructor.name
      @message = @constructor.getMessage payload
      @payload = payload

      if typeof Error.captureStackTrace is 'function'
        Error.captureStackTrace @, @constructor

  class NotImplemented extends Exception
    @getMessage: (payload) -> "Not implemented."

  class Encryption
    constructor: (props) ->
      @[key] = val for own key, val of props

    encrypt: (buffer, done) ->
      done new NotImplemented()

    decrypt: (buffer, done) ->
      done new NotImplemented()

    encryptStream: (readableStream) ->
      done new NotImplemented()

    decryptStream: (encryptedStream) ->
      done new NotImplemented()

  class CipherIvEncryption extends Encryption
    algorithm: null
    initializationVectorByteSize: null
    secretKey: null

    constructor: (props) ->
      super props

      @algorithm ?= DEFAULT_CIPHER_IV_ALGORITHM
      @initializationVectorByteSize ?= DEFAULT_CIPHER_IV_BYTE_SIZE

    encrypt: (buffer, done) ->
      try
        initializationVector = @generateInitializationVector()
        cipher = @createCipher {initializationVector}
        encrypted = Buffer.concat [cipher.update(buffer), cipher.final()]
        combined = Buffer.concat [initializationVector, encrypted]
      catch error
      finally
        return done error if error?
        return done null, combined

    decrypt: (buffer, done) ->
      try
        initializationVector = buffer.slice 0, @initializationVectorByteSize
        encrypted = buffer.slice @initializationVectorByteSize
        decipher = @createDecipher {initializationVector}
        decrypted = Buffer.concat [decipher.update(encrypted), decipher.final()]
      catch error
      finally
        return done error if error?
        return done null, decrypted

    encryptStream: (readableStream) ->
      encryptedStream = new Stream.PassThrough

      setImmediate =>
        initializationVector = @generateInitializationVector()
        encryptedStream.write initializationVector
        cipher = @createCipher {initializationVector}
        readableStream.pipe(cipher).pipe(encryptedStream)

      encryptedStream

    decryptStream: (encryptedStream) ->
      decryptedStream = new Stream.PassThrough

      onceStreamReadable = =>
        # get initialization vector
        ivSize = @initializationVectorByteSize
        data = Buffer encryptedStream.read(ivSize)
        encryptedStream.unshift data.slice(ivSize) if data.length > ivSize
        initializationVector = data.slice 0, ivSize

        decipher = @createDecipher {initializationVector}
        encryptedStream.pipe(decipher).pipe(decryptedStream)

      encryptedStream.once 'readable', onceStreamReadable
      decryptedStream

    generateInitializationVector: (encoding) ->
      Crypto.randomBytes @initializationVectorByteSize

    createCipher: ({initializationVector}) ->
      Crypto.createCipheriv @algorithm, @secretKey, initializationVector

    createDecipher: ({initializationVector}) ->
      Crypto.createDecipheriv @algorithm, @secretKey, initializationVector

  cipherIv = ({algorithm, initializationVectorByteSize, secretKey} = {}) ->
    secretKey ?= process?.env?.BOCO_ENCRYPTION_SECRET_KEY
    initializationVectorByteSize ?= process?.env?.BOCO_ENCRYPTION_IV_BYTE_SIZE

    new CipherIvEncryption {algorithm, secretKey, initializationVectorByteSize}

  {
    configure
    dependencies
    Dependencies
    Exception
    Encryption
    CipherIvEncryption
    cipherIv
  }

module.exports = configure()

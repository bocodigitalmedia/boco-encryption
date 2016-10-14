Path = require 'path'
BocoEncryption = require '.'
Minimist = require 'minimist'
Base64Stream = require 'base64-stream'

encrypt = ({encryption, str, argv}) ->
  return help() unless str?

  encoding = if argv.base64 then "base64" else null
  buffer = Buffer str

  encryption.encrypt buffer, (error, encrypted) ->
    throw error if error?

    process.stdout.write encrypted.toString(encoding)
    process.stdout.write "\n"
    process.exit 0

decrypt = ({encryption, str, argv}) ->
  return help() unless str?

  encoding = if argv.base64 then "base64" else null
  buffer = Buffer str, encoding

  encryption.decrypt buffer, (error, decrypted) ->
    throw error if error?

    process.stdout.write decrypted
    process.stdout.write "\n"
    process.exit 0

encryptStream = ({encryption, argv}) ->
  stream = encryption.encryptStream process.stdin
  stream = stream.pipe Base64Stream.encode() if argv.base64
  stream.pipe process.stdout

decryptStream = ({encryption, argv}) ->
  encryptedStream = process.stdin
  encryptedStream = encryptedStream.pipe Base64Stream.decode() if argv.base64
  stream = encryption.decryptStream encryptedStream
  stream.pipe process.stdout

help = ->
  process.stdout.write """
    Usage: boco-encryption <command> [<args...>] [--base64]

    Commands:
      encrypt <string> --base64
      decrypt <string> --base64
      encrypt-stream --base64 < <stream>
      decrypt-stream --base64 < <stream>

    Options:
      --base64 - use base64 encoding for reading and writing encrypted data
      --config=<path> - use config file specified at <path>. Defaults to boco-encryption.json

    Configuration: json
      You may configure the encryption using json by specifying the following attributes:
      * method - the encryption factory method to call (ie: `cipherIv`)
      * params - the parameters for the factory method

    Configuration: javascript
      You may configure the encryption using javascript by exporting an async function
      that returns the BocoEncryption.Encryption instance to use.

      ie: module.exports = function(done) { ... done(null, myEncryption); };
    """

getEncryption = ({configPath}, done) ->

  if configPath?
    try config = require Path.resolve configPath
    catch error
      return done Error("Cannot load config: #{error.message}") if error?

  else

    try
      defaultJsonConfig = require Path.resolve __dirname, 'boco-encryption.config.json'
    catch error
    finally
      return done Error("Cannot load config: #{error.message}") unless error.code is 'MODULE_NOT_FOUND'

    try
      defaultJsConfig = require Path.resolve __dirname, 'boco-encryption.config.js'
    catch error
    finally
      return done Error("Cannot load config: #{error.message}") unless error.code is 'MODULE_NOT_FOUND'

    error = null

    config = defaultJsConfig ? defaultJsonConfig

    config ?= {}
    config.method ?= 'cipherIv'
    config.params ?= {}
    config.params.secretKey ?= process.env.BOCO_ENCRYPTION_SECRET_KEY

  if typeof config is 'object'
    try
      {method, params} = config
      encryption = BocoEncryption[method] params
    catch error
    finally
      return done error if error?
      return done null, encryption

  if typeof config is 'function'
    return config done

  done Error "Could not create encryption"

main = ->
  argv = Minimist process.argv.slice(2)
  configPath = argv['config']
  [command, str] = argv._

  getEncryption {configPath}, (error, encryption) ->
    throw error if error?
    return help() unless encryption?

    switch command

      when 'encrypt' then encrypt {encryption, str, argv}
      when 'decrypt' then decrypt {encryption, str, argv}
      when 'encrypt-stream' then encryptStream {encryption, argv}
      when 'decrypt-stream' then decryptStream {encryption, argv}
      else help()

module.exports = {
  main
  help
  encrypt
  decrypt
  encryptStream
  decryptStream
}

return main() unless module?.parent?

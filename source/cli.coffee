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

    """

main = ->

  argv = Minimist process.argv.slice(2)
  [command, str] = argv._
  config = argv.config ? './boco-encryption.config.js'

  encryption = try require Path.resolve(config)
  encryption ?= BocoEncryption.cipherIv()

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

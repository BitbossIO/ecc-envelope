Algorithms =
  0: 'plaintext'
  1: 'aes'
  2: 'triplesec'

promise = Promise ? require('es6-promise').Promise

crypto = require 'crypto'

et = require 'ecc-tools'
pb = require 'protobufjs'

# TODO: Move to separate file
protocol = '''
  package protocol;

  message Envelope {
    required Cipher cipher = 1;
    required bytes checksum = 2;
    optional bytes signature = 3;

    message Cipher {
      enum Algorithm {
        PLAINTEXT = 0;
        plaintext = 0;
        AES = 1;
        aes = 1;
        TRIPLESEC = 2;
        triplesec = 2;
      }

      required bytes ciphertext = 1;
      required Algorithm algorithm = 2;

      optional bytes iv = 3;
      optional bytes mac = 4;
      optional bytes ephemeralKey = 5;

      optional bytes to = 6;
      optional bytes from = 7;
    }
  }
'''

builder = pb.loadProto(protocol)
Protocol = builder.build('protocol')

class Envelope
  constructor: (args={}) ->
    if !(@ instanceof Envelope) then return new Envelope(args)

    @_to = {}
    @_from = {}

    if @_decode = args.decode
      switch args.as
        when 'hex' then @_buffer = Protocol.Envelope.decodeHex(@_decode)
        when 'json' then @_buffer = Protocol.Envelope.decodeJSON(@_decode)
        else @_buffer = Protocol.Envelope.decode((@_decode.toBuffer?() ? @_decode))
      @_checksum = @_buffer.checksum
      @_signature = @_buffer.signature
      @_cipher = @_buffer.cipher

      @_to.public = @_cipher.to
      @_from.public = @_cipher.from
      @_algorithm = Algorithms[@_cipher.algorithm]
      @_seal = promise.resolve(@)
    else
      @_to.public = args.to
      @_from.private = args.from ? et.privateKey()
      @_from.public = et.publicKey(@_from.private)

      @_data = args.send
      @_algorithm = args.using ? 'aes'

      if @_to.public && @_algorithm != 'plaintext'
        @_encryptor = et.encrypt(@_data, @_to.public, @_algorithm)
      else if @_data
        @_algorithm = 'plaintext'
        @_encryptor = promise.resolve
          ciphertext: new Buffer(et.stringify(@_data))

  seal: ->
    @_seal ?= @_encryptor.then (cipher) =>
      cipher.to = et.publicKeyConvert(@_to.public, true) if @_to.public?
      cipher.from = et.publicKeyConvert(@_from.public, true) if @_from.public
      cipher.algorithm = @_algorithm
      @_cipher = new Protocol.Envelope.Cipher(cipher)
      @_checksum = et.checksum(@_cipher.encodeJSON())
    .then (checksum) => et.sign(checksum, @_from.private)
    .then (signature) => @_signature = signature
    .then =>
      @_buffer = new Protocol.Envelope
        cipher: @_cipher
        checksum: @_checksum
        signature: @_signature
      @

  verify: ->
    @seal().then (e) =>
      checksum = Buffer.from(e._checksum.toBuffer?() ? e._checksum)
      et.verify(checksum, e._from.public, e._signature) &&
      checksum.equals(et.checksum(e._cipher.encodeJSON()))

  open: (key) ->
    @seal().then (e) =>
      @verify().then (valid) =>
        return false unless valid
        if @_algorithm == 'plaintext'
          ciphertext = Buffer.from(e._cipher.ciphertext.toBuffer?() ? e._cipher.ciphertext)
          @_decryptor = promise.resolve(JSON.parse(ciphertext))
        else
          @_decryptor = et.decrypt(e._cipher, key, e._algorithm)


        @_decryptor.then (plaintext) =>
          to = e._to.public?.toBuffer?() ? e._to.public
          from = e._from.public?.toBuffer?() ? e._from.public
          result = { data: plaintext }
          result.to = Buffer.from(to) if to?
          result.from = Buffer.from(from) if from?
          result

  encode: (encoding) ->
    @seal().then (e) =>
      switch encoding
        when 'hex' then e._buffer.encodeHex()
        when 'json' then e._buffer.encodeJSON()
        when 'base64' then e._buffer.encode64()
        else
          buffer = e._buffer.encode()
          Buffer.from(buffer.toBuffer() ? buffer)

Envelope.et = et
Envelope.Protocol = Protocol

Envelope.encode = (buffer) -> et.bs58check.encode(buffer.toBuffer?() ? buffer)
Envelope.decode = (buffer) -> et.bs58check.decode(buffer.toBuffer?() ? buffer)

module.exports = Envelope


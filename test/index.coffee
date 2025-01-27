promise = Promise ? require('es6-promise').Promise

chaiAsPromised = require 'chai-as-promised'
chai = require 'chai'
chai.use chaiAsPromised

expect = chai.expect

Envelope = require '../src/index'
et = require 'ecc-tools'

describe 'Envelope', ->
  before ->
    @alicePrivateKey = et.privateKey()
    @alicePublicKey = et.publicKey(@alicePrivateKey)

    @bobPrivateKey = et.privateKey()
    @bobPublicKey = et.publicKey(@bobPrivateKey)

  describe 'class', ->
    describe 'constructor', ->
      it 'should create a envelope', ->
        envelope = new Envelope()
        expect(envelope).to.be.an.instanceOf(Envelope)

      describe 'send:', ->
        it 'should set _data to buffer of string', ->
          envelope = Envelope send: 'hello world'
          expect(envelope._data).to.eql('hello world')

        it 'should set _checksum to sha256 of _cipher', ->
          envelope = Envelope send: 'hello world'
          result = envelope.seal().then (e) -> e._checksum.equals(et.checksum(e._cipher.encodeJSON()))
          expect(result).to.eventually.be.true

      describe 'decode:', ->
        before ->
          @envelope = Envelope(send: {hello: 'world'}, from: @alicePrivateKey, to: @bobPublicKey)
          @envelope.encode().then (message) =>
            @message = message

        it 'should create an envelope', ->
          envelope = Envelope(decode: @message)
          expect(envelope).to.be.an.instanceOf(Envelope)

        it 'should be valid', ->
          envelope = Envelope(decode: @message)
          expect(envelope.verify()).to.eventually.be.true

        it 'should decrypt', ->
          envelope = Envelope(decode: @message)
          result = envelope.open(@bobPrivateKey)
          expect(result).to.eventually.have.deep.property('data.hello', 'world')

        it 'should decode ByteBuffer encoding', ->
          result = @envelope.encode().then (e) -> Envelope(decode: e).verify()
          expect(result).to.eventually.be.true

        it 'should decode base64 encoding', ->
          result = @envelope.encode('base64').then (e) -> Envelope(decode: e).verify()
          expect(result).to.eventually.be.true

        it 'should decode hex encoding with as: set', ->
          result = @envelope.encode('hex').then (e) -> Envelope(decode: e, as: 'hex').verify()
          expect(result).to.eventually.be.true

        it 'should decode json encoding with as: set', ->
          result = @envelope.encode('json').then (e) -> Envelope(decode: e, as: 'json').verify()
          expect(result).to.eventually.be.true


      describe 'to:', ->
        it 'should encrypt the data', ->
          envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey
          result = envelope.seal().then (e) => e.open(@alicePrivateKey)
          expect(result).to.eventually.have.deep.property('data.hello', 'world')

        it 'should default the algorithm to AES', ->
          envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey
          envelope.seal().then (e) ->
            expect(e._algorithm).to.eql('aes')

      describe 'from:', ->
        it 'should take a PrivateKey', ->
          envelope = Envelope send: {hello: 'world'}, from: @bobPrivateKey
          expect(envelope._from.private).to.eql(@bobPrivateKey)

        it 'should error on an invalid PrivateKey', ->
          envelope = -> Envelope send: {hello: 'world'}, from: 'not a key'
          expect(envelope).to.throw(Error)

        it 'should sign the checksum', ->
          envelope = Envelope send: {hello: 'world'}, from: @bobPrivateKey
          result = envelope.seal().then (e) =>
            et.verify(e._checksum, @bobPublicKey, e._signature)
          expect(result).to.eventually.be.true


      describe 'using:', ->
        it 'should let me set the algorithm to plaintext', ->
          envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, using: 'plaintext'
          result = envelope.seal()
          data = envelope.open().then (e) -> e.data
          promise.all [
            expect(result).to.eventually.have.property('_algorithm', 'plaintext')
            expect(data).to.eventually.eql(hello: 'world')
          ]

        # it 'should let me set the algorithm to triplesec', ->
        #   envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, using: 'triplesec'
        #   result = envelope.seal().then (e) => e._algorithm
        #   expect(result).to.eventually.eql('triplesec')


  describe 'instance', ->
    describe 'verify', ->
      it 'should fulfill if signature and checksum is valid', ->
        envelope = Envelope send: {hello: 'world'}, from: @alicePrivateKey
        expect(envelope.verify()).to.be.fulfilled

      it 'should reject if signature is invalid', ->
        envelope = Envelope send: {hello: 'world'}, from: @alicePrivateKey
        result = envelope.seal().then (e) ->
          e._signature = Buffer.from('fubar')
          e.verify()
        expect(result).to.reject

      it 'should reject if checksum is invalid', ->
        envelope = Envelope send: {hello: 'world'}, from: @alicePrivateKey
        result = envelope.seal().then (e) ->
          e._checksum = Buffer.from('fubar')
          e.verify()
        expect(result).to.reject

      it 'should reject if cipher is invalid', ->
        envelope = Envelope send: {hello: 'world'}, from: @alicePrivateKey
        result = envelope.seal().then (e) ->
          e._cipher = Buffer.from('fubar')
          e.verify()
        expect(result).to.reject


    describe 'open', ->
      it 'should decrypt the data', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey
        result = envelope.open(@alicePrivateKey)
        expect(result).to.eventually.have.deep.property('data.hello', 'world')

      it 'should decrypt plaintext', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, using: 'plaintext'
        result = envelope.open(@alicePrivateKey)
        expect(result).to.eventually.have.deep.property('data.hello', 'world')

      # it 'should decrypt triplesec', ->
      #   envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, using: 'triplesec'
      #   result = envelope.open(@alicePrivateKey)
      #   expect(result).to.eventually.have.deep.property('data.hello', 'world')

    describe 'encode', ->
      it 'should return a promise', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        expect(envelope.encode()).to.be.fulfilled

      it 'should include a checksum', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e)
        expect(result).to.eventually.have.property('checksum')

      it 'should include a signature', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e)
        expect(result).to.eventually.have.property('signature')

      it 'should include a cipher', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e)
        expect(result).to.eventually.have.property('cipher')

      it 'should include a to', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e).cipher
        expect(result).to.eventually.have.property('to')

      it 'should include a from', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e).cipher
        expect(result).to.eventually.have.property('from')

      it 'should include an algorithm', ->
        envelope = Envelope send: {hello: 'world'}, to: @alicePublicKey, from: @bobPrivateKey
        result = envelope.encode().then (e) -> Envelope.Protocol.Envelope.decode(e).cipher
        expect(result).to.eventually.have.property('algorithm')


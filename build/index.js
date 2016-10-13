// Generated by CoffeeScript 1.11.1
var Dependencies, configure,
  hasProp = {}.hasOwnProperty,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

Dependencies = (function() {
  Dependencies.prototype.DEFAULT_CIPHER_IV_ALGORITHM = null;

  Dependencies.prototype.DEFAULT_CIPHER_IV_BYTE_SIZE = null;

  Dependencies.prototype.Crypto = null;

  Dependencies.prototype.Error = null;

  Dependencies.prototype.Buffer = null;

  Dependencies.prototype.Stream = null;

  function Dependencies(props) {
    var key, val;
    for (key in props) {
      if (!hasProp.call(props, key)) continue;
      val = props[key];
      this[key] = val;
    }
    if (this.DEFAULT_CIPHER_IV_ALGORITHM == null) {
      this.DEFAULT_CIPHER_IV_ALGORITHM = 'aes-256-ctr';
    }
    if (this.DEFAULT_CIPHER_IV_BYTE_SIZE == null) {
      this.DEFAULT_CIPHER_IV_BYTE_SIZE = 16;
    }
    if (this.Error == null) {
      this.Error = (function() {
        try {
          return Error;
        } catch (error1) {}
      })();
    }
    if (this.Buffer == null) {
      this.Buffer = (function() {
        try {
          return Buffer;
        } catch (error1) {}
      })();
    }
    if (typeof require === 'function') {
      if (this.Crypto == null) {
        this.Crypto = require('crypto');
      }
      if (this.Stream == null) {
        this.Stream = require('stream');
      }
    }
  }

  return Dependencies;

})();

configure = function(props) {
  var Base64Stream, Buffer, CipherIvEncryption, Crypto, DEFAULT_CIPHER_IV_ALGORITHM, DEFAULT_CIPHER_IV_BYTE_SIZE, Encryption, Error, Exception, NotImplemented, Stream, cipherIv, dependencies, ref;
  ref = dependencies = new Dependencies(props), DEFAULT_CIPHER_IV_ALGORITHM = ref.DEFAULT_CIPHER_IV_ALGORITHM, DEFAULT_CIPHER_IV_BYTE_SIZE = ref.DEFAULT_CIPHER_IV_BYTE_SIZE, Error = ref.Error, Crypto = ref.Crypto, Buffer = ref.Buffer, Stream = ref.Stream, Base64Stream = ref.Base64Stream;
  Exception = (function(superClass) {
    extend(Exception, superClass);

    Exception.prototype.payload = null;

    Exception.getMessage = function(payload) {
      return null;
    };

    function Exception(payload) {
      this.name = this.constructor.name;
      this.message = this.constructor.getMessage(payload);
      this.payload = payload;
      if (typeof Error.captureStackTrace === 'function') {
        Error.captureStackTrace(this, this.constructor);
      }
    }

    return Exception;

  })(Error);
  NotImplemented = (function(superClass) {
    extend(NotImplemented, superClass);

    function NotImplemented() {
      return NotImplemented.__super__.constructor.apply(this, arguments);
    }

    NotImplemented.getMessage = function(payload) {
      return "Not implemented.";
    };

    return NotImplemented;

  })(Exception);
  Encryption = (function() {
    function Encryption(props) {
      var key, val;
      for (key in props) {
        if (!hasProp.call(props, key)) continue;
        val = props[key];
        this[key] = val;
      }
    }

    Encryption.prototype.encrypt = function(buffer, done) {
      return done(new NotImplemented());
    };

    Encryption.prototype.decrypt = function(buffer, done) {
      return done(new NotImplemented());
    };

    Encryption.prototype.encryptStream = function(readableStream) {
      return done(new NotImplemented());
    };

    Encryption.prototype.decryptStream = function(encryptedStream) {
      return done(new NotImplemented());
    };

    return Encryption;

  })();
  CipherIvEncryption = (function(superClass) {
    extend(CipherIvEncryption, superClass);

    CipherIvEncryption.prototype.algorithm = null;

    CipherIvEncryption.prototype.initializationVectorByteSize = null;

    CipherIvEncryption.prototype.secretKey = null;

    function CipherIvEncryption(props) {
      CipherIvEncryption.__super__.constructor.call(this, props);
      if (this.algorithm == null) {
        this.algorithm = DEFAULT_CIPHER_IV_ALGORITHM;
      }
      if (this.initializationVectorByteSize == null) {
        this.initializationVectorByteSize = DEFAULT_CIPHER_IV_BYTE_SIZE;
      }
    }

    CipherIvEncryption.prototype.encrypt = function(buffer, done) {
      var cipher, combined, encrypted, error, initializationVector;
      try {
        initializationVector = this.generateInitializationVector();
        cipher = this.createCipher({
          initializationVector: initializationVector
        });
        encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
        return combined = Buffer.concat([initializationVector, encrypted]);
      } catch (error1) {
        error = error1;
      } finally {
        if (error != null) {
          return done(error);
        }
        return done(null, combined);
      }
    };

    CipherIvEncryption.prototype.decrypt = function(buffer, done) {
      var decipher, decrypted, encrypted, error, initializationVector;
      try {
        initializationVector = buffer.slice(0, this.initializationVectorByteSize);
        encrypted = buffer.slice(this.initializationVectorByteSize);
        decipher = this.createDecipher({
          initializationVector: initializationVector
        });
        return decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      } catch (error1) {
        error = error1;
      } finally {
        if (error != null) {
          return done(error);
        }
        return done(null, decrypted);
      }
    };

    CipherIvEncryption.prototype.encryptStream = function(readableStream) {
      var encryptedStream;
      encryptedStream = new Stream.PassThrough;
      setImmediate((function(_this) {
        return function() {
          var cipher, initializationVector;
          initializationVector = _this.generateInitializationVector();
          encryptedStream.write(initializationVector);
          cipher = _this.createCipher({
            initializationVector: initializationVector
          });
          return readableStream.pipe(cipher).pipe(encryptedStream);
        };
      })(this));
      return encryptedStream;
    };

    CipherIvEncryption.prototype.decryptStream = function(encryptedStream) {
      var decryptedStream, onceStreamReadable;
      decryptedStream = new Stream.PassThrough;
      onceStreamReadable = (function(_this) {
        return function() {
          var data, decipher, initializationVector, ivSize;
          ivSize = _this.initializationVectorByteSize;
          data = Buffer(encryptedStream.read(ivSize));
          if (data.length > ivSize) {
            encryptedStream.unshift(data.slice(ivSize));
          }
          initializationVector = data.slice(0, ivSize);
          decipher = _this.createDecipher({
            initializationVector: initializationVector
          });
          return encryptedStream.pipe(decipher).pipe(decryptedStream);
        };
      })(this);
      encryptedStream.once('readable', onceStreamReadable);
      return decryptedStream;
    };

    CipherIvEncryption.prototype.generateInitializationVector = function(encoding) {
      return Crypto.randomBytes(this.initializationVectorByteSize);
    };

    CipherIvEncryption.prototype.createCipher = function(arg) {
      var initializationVector;
      initializationVector = arg.initializationVector;
      return Crypto.createCipheriv(this.algorithm, this.secretKey, initializationVector);
    };

    CipherIvEncryption.prototype.createDecipher = function(arg) {
      var initializationVector;
      initializationVector = arg.initializationVector;
      return Crypto.createDecipheriv(this.algorithm, this.secretKey, initializationVector);
    };

    return CipherIvEncryption;

  })(Encryption);
  cipherIv = function(arg) {
    var algorithm, initializationVectorByteSize, ref1, ref2, ref3, secretKey;
    ref1 = arg != null ? arg : {}, algorithm = ref1.algorithm, initializationVectorByteSize = ref1.initializationVectorByteSize, secretKey = ref1.secretKey;
    if (secretKey == null) {
      secretKey = typeof process !== "undefined" && process !== null ? (ref2 = process.env) != null ? ref2.BOCO_ENCRYPTION_SECRET_KEY : void 0 : void 0;
    }
    if (initializationVectorByteSize == null) {
      initializationVectorByteSize = typeof process !== "undefined" && process !== null ? (ref3 = process.env) != null ? ref3.BOCO_ENCRYPTION_IV_BYTE_SIZE : void 0 : void 0;
    }
    return new CipherIvEncryption({
      algorithm: algorithm,
      secretKey: secretKey,
      initializationVectorByteSize: initializationVectorByteSize
    });
  };
  return {
    configure: configure,
    dependencies: dependencies,
    Dependencies: Dependencies,
    Exception: Exception,
    Encryption: Encryption,
    CipherIvEncryption: CipherIvEncryption,
    cipherIv: cipherIv
  };
};

module.exports = configure();

//# sourceMappingURL=index.js.map

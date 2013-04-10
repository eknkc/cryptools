var crypto = require('crypto')

exports.options = {
  signKey: null,
  encryptKey: null
};

exports.sha1 = function(str, encoding) {
  return crypto
    .createHash('sha1')
    .update(str, "utf8")
    .digest(encoding || 'hex');
};

exports.sha256 = function(str, encoding) {
  return crypto
    .createHash('sha256')
    .update(str, "utf8")
    .digest(encoding || 'hex');
};

exports.signature = function(input, options) {
  options = merge({ algorithm: "sha256", encoding: "hex" }, exports.options, options);

  if (!options.signKey)
    throw new Error("Please set cryptools.options.signKey signature key.");

  if (['sha1', 'sha256'].indexOf(options.algorithm) < 0)
    throw new Error("You can only use sha1 or sha256 for signing.");

  return crypto
    .createHmac(options.algorithm, options.signKey)
    .update(input, "utf8")
    .digest(options.encoding);
};

exports.encrypt = function(input, options) {
  options = merge({ encoding: "base64", signed: false }, exports.options, options);

  if (!options.encryptKey)
    throw new Error("Please set cryptools.options.encryptKey encryption key.");

  input = JSON.stringify(input);

  if (options.signed)
    input += exports.signature(input, { signKey: options.signKey, algorithm: options.signAlgorithm });

  var key = exports.sha256(options.encryptKey);
  var cipher = crypto.createCipher("aes-256-cbc", key);
  var result = cipher.update(input, "utf8", options.encoding);
  result += cipher.final(options.encoding);

  return result;
};

exports.decrypt = function(input, options) {
  options = merge({ encoding: "base64", signed: false }, exports.options, options);

  if (!options.encryptKey)
    throw new Error("Please set cryptools.options.encryptKey encryption key.");

  var key = exports.sha256(options.encryptKey);
  var decipher = crypto.createDecipher("aes-256-cbc", key);

  try {
      input = (new Buffer(input, 'base64')).toString('base64');
      var txt = decipher.update(input, options.encoding, 'utf8');
      txt += decipher.final('utf8');

      if (options.signed) {
        var len = (options.signAlgorithm == 'sha1') ? 40 : 64
        var signature = txt.substr(-len);
        txt = txt.substr(0, txt.length - len);

        if (exports.signature(txt, { signKey: options.signKey, algorithm: options.signAlgorithm }) != signature)
          return null;
      }

      return JSON.parse(txt);
  } catch(e) { return null; }
};

exports.randomBytes = function(length, encoding) {
  return crypto.randomBytes(length || 32).toString(encoding || 'hex');
}

function merge(obj) {
  [].slice.call(arguments, 1).forEach(function(source) {
    if (source) {
      for (var prop in source) {
        if (source[prop])
          obj[prop] = source[prop];
      }
    }
  });

  return obj;
};

var assert = require('assert')
  , cryptools = require('../')

describe('cryptools', function () {
  it('should hash sha1 correctly', function () {
    assert.equal(cryptools.sha1('qwerty'), 'b1b3773a05c0ed0176787a4f1574ff0075f7521e')
    assert.equal(cryptools.sha1('42'), '92cfceb39d57d914ed8b14d0e37643de0797ae56')
    assert.equal(cryptools.sha1('42', 'base64'), 'ks/Os51X2RTtixTQ43ZD3geXrlY=')
  });

  it('should hash sha256 correctly', function () {
    assert.equal(cryptools.sha256('qwerty'), '65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5')
    assert.equal(cryptools.sha256('42'), '73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049')
    assert.equal(cryptools.sha256('42', 'base64'), 'c0dctApWjo2ooEXO0RATfhWfiQrE2og7axfcZRs6gEk=')
  });

  it('should complain about missing sign key', function() {
    assert.throws(function() { cryptools.signature('test') });
    assert.doesNotThrow(function() { cryptools.signature('test', { signKey: "a" }) });
  });

  it('should sign with default options', function() {
    assert.equal(cryptools.signature('test', { signKey: "123" }), "a7f5c8c626f994482813230854f66700e626208f52d913b9bd6b4e039aab0f41")
    assert.equal(cryptools.signature('test', { signKey: "123", algorithm: "sha1" }), "cfa54b5a91f6667966fc8a33362128a4715572f7")
  });

  it('should sign with encoding option', function() {
    assert.equal(cryptools.signature('test', { signKey: "123", encoding: "base64" }), "p/XIxib5lEgoEyMIVPZnAOYmII9S2RO5vWtOA5qrD0E=")
    assert.equal(cryptools.signature('test', { signKey: "123", algorithm: "sha1", encoding: "base64" }), "z6VLWpH2Znlm/IozNiEopHFVcvc=")
  });

  it('should encrypt with default options', function() {
    assert.equal(cryptools.encrypt('test', { encryptKey: "123" }), "JHIx04HobNrfDzk3VFA9YQ==")
  });

  it('should decrypt with default options', function() {
    assert.equal(cryptools.decrypt('JHIx04HobNrfDzk3VFA9YQ==', { encryptKey: "123" }), "test")
  });

  it('should encrypt with encoding option', function() {
    assert.equal(cryptools.encrypt('test', { encryptKey: "123", encoding: "hex" }), "247231d381e86cdadf0f393754503d61")
  });

  it('should decrypt with encoding option', function() {
    assert.equal(cryptools.decrypt('247231d381e86cdadf0f393754503d61', { encryptKey: "123", encoding: "hex" }), "test")
  });

  it('should encrypt with sign option', function() {
    assert.equal(cryptools.encrypt('test', { encryptKey: "123", signKey: "abc", signed: true }), "m2Sp9QEvqhn8GIEhjpdgkSuFPB+j8wEjoIf/MHSi1kZhjLvywOeOgY0l4hbZap2e0pY7Q4OctTs7jB9ad8tv+QZVQZJ4ttvTEyMPatUJuZ8=")
    assert.equal(cryptools.encrypt('test', { encryptKey: "123", signKey: "abc", signAlgorithm: "sha1", signed: true }), "flqjBjihbCWilFunoRlQYC5LPWCi8Vg/imDnFukNjA/SDCdkF3dHTcCpIDIUvMOI")
  });

  it('should decrypt with sign option', function() {
    assert.equal(cryptools.decrypt('m2Sp9QEvqhn8GIEhjpdgkSuFPB+j8wEjoIf/MHSi1kZhjLvywOeOgY0l4hbZap2e0pY7Q4OctTs7jB9ad8tv+QZVQZJ4ttvTEyMPatUJuZ8=', { encryptKey: "123", signKey: "abc", signed: true }), "test")
    assert.equal(cryptools.decrypt('flqjBjihbCWilFunoRlQYC5LPWCi8Vg/imDnFukNjA/SDCdkF3dHTcCpIDIUvMOI', { encryptKey: "123", signKey: "abc", signAlgorithm: 'sha1', signed: true }), "test")
  });
});

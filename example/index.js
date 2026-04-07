// Polyfill TextEncoder/TextDecoder for React Native (must run before anything else)
// React Native's Hermes engine may have stub implementations, so we force override
(function () {
  'use strict';

  // TextEncoder polyfill
  function TextEncoderPolyfill() {}
  TextEncoderPolyfill.prototype.encode = function (input) {
    var bytes = new Uint8Array(input.length);
    for (var i = 0; i < input.length; i++) {
      bytes[i] = input.charCodeAt(i) & 0xff;
    }
    return bytes;
  };

  // TextDecoder polyfill
  function TextDecoderPolyfill() {}
  TextDecoderPolyfill.prototype.decode = function (input) {
    if (!input) return '';
    var bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
    var result = '';
    for (var i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  };

  // Force override global
  /* eslint-disable no-undef */
  global.TextEncoder = TextEncoderPolyfill;
  global.TextDecoder = TextDecoderPolyfill;
  if (typeof globalThis !== 'undefined') {
    globalThis.TextEncoder = TextEncoderPolyfill;
    globalThis.TextDecoder = TextDecoderPolyfill;
  }
  /* eslint-enable no-undef */
})();

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);

// Polyfill TextEncoder/TextDecoder for React Native (must run before anything else)
globalThis.TextEncoder = class TextEncoder {
  encode(input) {
    const bytes = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      bytes[i] = input.charCodeAt(i) & 0xff;
    }
    return bytes;
  }
};

globalThis.TextDecoder = class TextDecoder {
  decode(input) {
    const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : input;
    if (!bytes) return '';
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  }
};

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);

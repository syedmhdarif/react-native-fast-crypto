import { toHex, fromHex, toBase64, fromBase64, toUint8Array } from '../../src/utils';

describe('toHex', () => {
  it('converts empty buffer', () => {
    expect(toHex(new ArrayBuffer(0))).toBe('');
  });

  it('converts known bytes to hex', () => {
    const buf = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer;
    expect(toHex(buf)).toBe('deadbeef');
  });

  it('handles zero bytes', () => {
    const buf = new Uint8Array([0x00, 0x00, 0x01]).buffer;
    expect(toHex(buf)).toBe('000001');
  });

  it('handles all-ff bytes', () => {
    const buf = new Uint8Array([0xff, 0xff]).buffer;
    expect(toHex(buf)).toBe('ffff');
  });
});

describe('fromHex', () => {
  it('converts empty string', () => {
    expect(fromHex('').byteLength).toBe(0);
  });

  it('converts hex to buffer', () => {
    const buf = fromHex('deadbeef');
    const arr = new Uint8Array(buf);
    expect(arr).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('throws on odd-length hex', () => {
    expect(() => fromHex('abc')).toThrow('length must be even');
  });

  it('round-trips with toHex', () => {
    const original = 'cafebabe01020304';
    expect(toHex(fromHex(original))).toBe(original);
  });
});

describe('toBase64 / fromBase64', () => {
  it('round-trips', () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]).buffer; // "Hello"
    const b64 = toBase64(data);
    expect(b64).toBe('SGVsbG8=');
    const decoded = fromBase64(b64);
    expect(new Uint8Array(decoded)).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
  });

  it('handles empty buffer', () => {
    expect(toBase64(new ArrayBuffer(0))).toBe('');
    expect(fromBase64('').byteLength).toBe(0);
  });
});

describe('toUint8Array', () => {
  it('wraps ArrayBuffer', () => {
    const buf = new Uint8Array([1, 2, 3]).buffer;
    const view = toUint8Array(buf);
    expect(view).toBeInstanceOf(Uint8Array);
    expect(view.length).toBe(3);
    expect(view[0]).toBe(1);
  });
});

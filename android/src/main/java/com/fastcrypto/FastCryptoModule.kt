package com.fastcrypto

import com.facebook.react.bridge.ReactApplicationContext

class FastCryptoModule(reactContext: ReactApplicationContext) :
  NativeFastCryptoSpec(reactContext) {

  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }

  companion object {
    const val NAME = NativeFastCryptoSpec.NAME
  }
}

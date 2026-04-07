require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "FastCrypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "14.0" }
  s.source       = { :git => "https://github.com/syedmhdarif/react-native-fast-crypto.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}", "cpp/**/*.{h,cpp}"
  s.private_header_files = "ios/**/*.h", "cpp/**/*.h"

  # Swift / Obj-C++ interop
  s.swift_version = "5.9"

  # C++17 configuration
  s.pod_target_xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++17",
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) FAST_CRYPTO_USE_OPENSSL=1",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/cpp\"",
    "DEFINES_MODULE" => "YES",
  }

  # OpenSSL dependency (1.1.x - stable, widely available)
  s.dependency "OpenSSL-Universal", "~> 1.1"

  install_modules_dependencies(s)
end

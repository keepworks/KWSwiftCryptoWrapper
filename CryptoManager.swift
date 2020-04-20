//
//  CryptoManager.swift
//  KWSwiftCryptoWrapper
//
//  Created by Pavan Kotesh on 28/03/20.
//  Copyright © 2020 KWSwiftCryptoWrapper Inc. All rights reserved.
//

import CryptoSwift
import SwiftyRSA

class CryptoManager {
  static let shared = CryptoManager()

  // MARK: - Public Methods
  func generateKeyPair() -> (publicKey: String, privateKey: String) {
    do {
      let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 2048)
      let privateKey = keyPair.privateKey
      let publicKey = keyPair.publicKey

      let base64EncodedPublicKey = try publicKey.base64String()
      let base64EncodedPrivateKey = try privateKey.base64String()
      return (base64EncodedPublicKey, base64EncodedPrivateKey)
    } catch {
      let exception = NSException(
        name: NSExceptionName(rawValue: "GenerateRSAKeyPairFailedException"),
        reason: error.localizedDescription,
        userInfo: nil
      )

      // throw exception

      print("Failed to initialize encryption. Please restart the application to try again.")
      return ("", "")
    }
  }

  func decrypt(_ content: String, withRSA decryptKey: String) -> String? {
    do {
      let encrypted = try EncryptedMessage(base64Encoded: content)
      let privateKey = try PrivateKey(base64Encoded: decryptKey)
      let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
      return decrypted.data.base64EncodedString()
    } catch {
      let exception = NSException(
        name: NSExceptionName(rawValue: "DecryptWithRSAPrivateKeyFailedException"),
        reason: error.localizedDescription,
        userInfo: nil
      )

      // throw exception

      print(error.localizedDescription)
    }

    return content
  }

  func encrypt(_ content: String, withAES key: String, iv: String) -> String? {
    do {
      let keyData = Data(base64Encoded: key)
      let ivData = Data(base64Encoded: iv)

      let aes = try AES(key: keyData!.bytes, blockMode: CBC(iv: ivData!.bytes), padding: .pkcs7)
      let crypted = try aes.encrypt(content.bytes)
      return crypted.toBase64()
    } catch {
      let exception = NSException(
        name: NSExceptionName(rawValue: "EncryptWithAESKeyFailedException"),
        reason: error.localizedDescription,
        userInfo: nil
      )

      // throw exception

      print(error.localizedDescription)
    }

    return content
  }

  func decrypt(_ content: String, withAES key: String, iv: String) -> String? {
    let encryptedPrefix = SecurityManager.shared.encryptionPrefix
    let encrypted = content.deletePrefix(encryptedPrefix)

    do {
      let keyData = Data(base64Encoded: key)
      let ivData = Data(base64Encoded: iv)
      let encryptedData = Data(base64Encoded: encrypted)

      let aes = try AES(key: keyData!.bytes, blockMode: CBC(iv: ivData!.bytes), padding: .pkcs7)
      let decrypted = try aes.decrypt(encryptedData!.bytes)
      let decryptedContent = String(bytes: decrypted, encoding: .ascii)
      return decryptedContent
    } catch {
      let exception = NSException(
        name: NSExceptionName(rawValue: "DecryptWithAESKeyFailedException"),
        reason: error.localizedDescription,
        userInfo: nil
      )

      // throw exception

      print(error.localizedDescription)
    }

    return encrypted
  }
}

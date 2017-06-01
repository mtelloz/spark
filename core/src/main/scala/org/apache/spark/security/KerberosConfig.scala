/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.spark.security

import java.nio.file.{Files, Paths}
import java.nio.file.attribute.PosixFilePermissions
import javax.xml.bind.DatatypeConverter

import org.apache.spark.internal.Logging

object KerberosConfig extends Logging{

  def prepareEnviroment(vaultUrl: String,
                        vaultToken: String,
                        options: Map[String, String]): Map[String, String] = {
    val kerberosVaultPath = options.get("KERBEROS_VAULT_PATH")
    if(kerberosVaultPath.isDefined) {
      val (keytab64, principal) =
        VaultHelper.getKeytabPrincipalFromVault(vaultUrl, vaultToken, kerberosVaultPath.get)
      val keytabPath = getKeytabPrincipal(keytab64, principal)
      Map("principal" -> principal, "keytabPath" -> keytabPath)
    } else {
      logInfo(s"tying to get ssl secrets from vault for Kerberos but not found vault path," +
        s" skipping")
      Map[String, String]()
    }
  }

  private def getKeytabPrincipal(keytab64: String, principal: String): String = {
    val bytes = DatatypeConverter.parseBase64Binary(keytab64)
    val kerberosSecretFile = Files.createFile(Paths.get(s"/tmp/$principal.keytab"),
      PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    kerberosSecretFile.toFile.deleteOnExit() // just to be sure
    val writePath = Files.write(kerberosSecretFile, bytes)
    writePath.toAbsolutePath.toString
  }

}

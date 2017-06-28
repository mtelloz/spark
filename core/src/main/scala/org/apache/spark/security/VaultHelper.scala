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

import java.io.{BufferedReader, InputStreamReader}

import scala.util.parsing.json.JSON

import org.apache.http.client.HttpClient
import org.apache.http.client.methods.{HttpGet, HttpPost, HttpRequestBase, HttpUriRequest}
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClientBuilder

import org.apache.spark.internal.Logging

object VaultHelper extends Logging {

  lazy val jsonTempTokenTemplate: String = "{ \"token\" : \"_replace_\" }"
  lazy val jsonRoleSecretTemplate: String = "{ \"role_id\" : \"_replace_role_\"," +
    " \"secret_id\" : \"_replace_secret_\"}"
  lazy val client: HttpClient = HttpClientBuilder.create().build()

  def getTokenFromAppRole(vaultHost: String,
                          appRoleToken: String,
                          role: String): String = {
    val requestUrl = s"$vaultHost/v1/auth/approle/login"
    logDebug(s"Requesting login from app and role: $requestUrl")
    val post = new HttpPost(requestUrl)
    post.addHeader("X-Vault-Token", appRoleToken)
    post.setEntity(new StringEntity(jsonRoleSecretTemplate.replace(
      "_replace_role_", getRoleIdFromVault(vaultHost, appRoleToken, role))
      .replace("_replace_secret_", getSecretIdFromVault(vaultHost, appRoleToken, role))))

    getContentFromResponse(post, "auth")("client_token").asInstanceOf[String]
  }

  private def getRoleIdFromVault(vaultHost: String,
                                 appRoleToken: String,
                                 role: String): String = {
    val requestUrl = s"$vaultHost/v1/auth/approle/role/$role/role-id"
    logDebug(s"Requesting Role ID from Vault: $requestUrl")
    getContentFromResponse(getFromVault(requestUrl, appRoleToken),
      "data")("role_id").asInstanceOf[String]
  }

  private def getSecretIdFromVault(vaultHost: String,
                                   appRoleToken: String,
                                   role: String): String = {
    val requestUrl = s"$vaultHost/v1/auth/approle/role/$role/secret-id"
    logDebug(s"Requesting Secret ID from Vault: $requestUrl")
    val post = new HttpPost(requestUrl)
    post.addHeader("X-Vault-Token", appRoleToken)
    getContentFromResponse(post, "data")("secret_id").asInstanceOf[String]
  }

  def getTemporalToken(vaultHost: String, token: String): String = {
    val requestUrl = s"$vaultHost/v1/sys/wrapping/wrap"
    logDebug(s"Requesting temporal token: $requestUrl")
    val post = new HttpPost(requestUrl)
    post.addHeader("X-Vault-Token", token)
    post.addHeader("X-Vault-Wrap-TTL", "2000s")
    post.setEntity(new StringEntity(jsonTempTokenTemplate.replace("_replace_", token)))

    getContentFromResponse(post, "wrap_info")("token").asInstanceOf[String]
  }

  def getKeytabPrincipalFromVault(vaultUrl: String,
                                  vaultToken: String,
                                  vaultPath: String): (String, String) = {
    val get = getFromVault(s"$vaultUrl$vaultPath", vaultToken)
    val data = getContentFromResponse(get, "data")
    val keytab64 = data.find(_._1.contains("keytab")).get._2.asInstanceOf[String]
    val principal = data.find(_._1.contains("principal")).get._2.asInstanceOf[String]
    (keytab64, principal)
  }

  def getRootCA(vaultUrl: String, token: String): String = {
    val certVaultPath = "/v1/ca-trust/certificates/"
    val listCertKeysVaultPath = s"$certVaultPath?list=true"
    logDebug(s"Requesting Root CA: $listCertKeysVaultPath")
    val get = getFromVault(s"$vaultUrl/$listCertKeysVaultPath", token)
    val keys = getContentFromResponse(get, "data")("keys").asInstanceOf[List[String]]
    keys.flatMap(key => {
      getContentFromResponse(getFromVault(s"$vaultUrl/$certVaultPath$key", token), "data")
        .find(_._1.endsWith("_crt"))
    }).map(_._2).mkString
  }

  def getCertPassFromVault(vaultUrl: String, token: String): String = {
    val certPassVaultPath = "/v1/ca-trust/passwords/default/keystore"
    logDebug(s"Requesting Cert Pass: $certPassVaultPath")
    val get = getFromVault(s"$vaultUrl$certPassVaultPath", token)
    getContentFromResponse(get, "data")("pass").asInstanceOf[String]
  }

  def getCertPassForAppFromVault(vaultUrl: String,
                                 appPassVaulPath: String,
                                 token: String): String = {
    val get = getFromVault(s"$vaultUrl$appPassVaulPath", token)
    logDebug(s"Requesting Cert Pass For App: $appPassVaulPath")
    getContentFromResponse(get, "data")("pass").asInstanceOf[String]
  }


  def getCertKeyForAppFromVault(vaultUrl: String,
                                vaultPath: String,
                                token: String): (String, String) = {
    val get = getFromVault(s"$vaultUrl/$vaultPath", token)
    logDebug(s"Requesting Cert Key For App: $vaultPath")
    val data = getContentFromResponse(get, "data")
    val certs = data.find(_._1.endsWith("_crt")).get._2.asInstanceOf[String]
    val key = data.find(_._1.endsWith("_key")).get._2.asInstanceOf[String]
    (key, certs)
  }

  def getPassForAppFromVault(vaultUrl: String,
                             vaultPath: String,
                             token: String): String = {
    val get = getFromVault(s"$vaultUrl/$vaultPath", token)
    logDebug(s"Requesting Pass for App: $vaultPath")
    val data = getContentFromResponse(get, "data")
    data("pass").asInstanceOf[String]
  }

  private[security] def getRealToken(vaultUrl: String, token: String): String = {
    val requestUrl = s"$vaultUrl/v1/sys/wrapping/unwrap"
    logDebug(s"Requesting real Token: $requestUrl")
    val post = new HttpPost(requestUrl)
    post.addHeader("X-Vault-Token", token)

    getContentFromResponse(post, "data")("token").asInstanceOf[String]
  }

  private def getContentFromResponse(uriRequest: HttpUriRequest,
                                     parentField: String): Map[String, Any] = {
    val response = client.execute(uriRequest)

    val rd = new BufferedReader(
      new InputStreamReader(response.getEntity().getContent()))

    val json = JSON.parseFull(Stream.continually(rd.readLine()).takeWhile(_ != null).mkString).
      get.asInstanceOf[Map[String, Any]]
    logTrace(s"getFrom Vault ${json.mkString("\n")}")
    if(response.getStatusLine.getStatusCode != 200) {
      val errors = json("errors").asInstanceOf[List[String]].mkString("\n")
      throw new RuntimeException(errors)
    }
    else {
      json(parentField).asInstanceOf[Map[String, Any]]
    }
  }


  private def getFromVault(vaultUrl: String,
                           vaultToken: String): HttpRequestBase = {
    val getResponse = new HttpGet(s"$vaultUrl")
    getResponse.addHeader("X-Vault-Token", vaultToken)
    getResponse
  }
}

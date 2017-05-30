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

import org.apache.spark.internal.Logging

object ConfigSecurity extends Logging{

  var vaultToken: Option[String] = None
  var vaultHost: Option[String] = Option(System.getenv("VAULT_HOST"))

  def prepareEnviroment(vaultTempToken: Option[String] = None,
                        vaulHost: Option[String] = None): Map[String, String] = {

    vaultToken = if (vaultTempToken.isDefined) {
      if (!vaultHost.isDefined) vaultHost = vaulHost
      Option(VaultHelper.getRealToken(vaultHost.get, vaultTempToken.get))
    } else Option(System.getenv("VAULT_TOKEN"))
    if(vaultToken.isDefined) {
      require(vaultHost.isDefined, "A proper vault host is required")
      logDebug(s"env VAR: ${sys.env.mkString("\n")}")
      val secretOptionsMap = ConfigSecurity.extractSecretFromEnv(sys.env)
      logDebug(s"secretOptionsMap: ${secretOptionsMap.mkString("\n")}")
      prepareEnviroment(vaultHost.get, vaultToken.get, secretOptionsMap)
    }
    else Map()
  }

  private def extractSecretFromEnv(env: Map[String, String]): Map[String,
    Map[String, String]] = {
    val extract: ((String, String)) => String = (keyValue: (String, String)) => {
      val (key, value) = keyValue
      key match {
        case key if key.toLowerCase.contains("spark_security_hdfs") => "hdfs"
        case key if key.toLowerCase.contains("spark_security_kerberos") => "kerberos"
        case key if key.toLowerCase.contains("spark_security_spark_tls") => "spark"
        case key if key.toLowerCase.contains("spark_security_kafka") => "kafka"
        case _ => ""
      }
    }
    env.groupBy(extract).filter(_._2.exists(_._2.contains("enable")))
      .flatMap{case (key, value) =>
      if (key.nonEmpty) Option((key, value))
      else None
    }
  }

  private def prepareEnviroment(vaultHost: String,
                                vaultToken: String,
                                secretOptions: Map[String,
                                  Map[String, String]]): Map[String, String] = {
    val seqOp: (Map[String, String], (String, Map[String, String])) => Map[String, String] =
      (agg: Map[String, String], value: (String, Map[String, String])) => {
        val (key, options) = value
        val secretOptions = key match {
          case "hdfs" => HDFSConfig.prepareEnviroment(options)
          case "kerberos" => KerberosConfig.prepareEnviroment(vaultHost,
            vaultToken,
            options)
          case "kafka" => SSLConfig.prepareEnviroment(vaultHost,
            vaultToken,
            SSLConfig.sslTypeKafka,
            options)
          case "spark" => SSLConfig.prepareEnviroment(vaultHost,
            vaultToken,
            SSLConfig.sslTypeSpark,
            options)
          case _ => Map[String, String]()
       }
        secretOptions ++ agg
      }
    val combOp: (Map[String, String], Map[String, String]) => Map[String, String] =
      (agg1: Map[String, String], agg2: Map[String, String]) => agg1 ++ agg2

    secretOptions.aggregate(Map[String, String]())(seqOp, combOp)
  }

}

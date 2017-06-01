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

import java.io.File
import java.nio.file.{Files, Paths}
import java.nio.file.attribute.PosixFilePermissions

import org.apache.spark.internal.Logging

object HDFSConfig extends Logging{

  private def downloadFile(url: String, fileToDownload: String, outputhPath: String) {
    logInfo(s"extracting $url/$fileToDownload")
    new File(outputhPath).mkdirs
    val src = scala.io.Source.fromURL(s"$url/$fileToDownload")
    val downloadFile = Files.createFile(Paths.get(s"$outputhPath/$fileToDownload"),
      PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    downloadFile.toFile.deleteOnExit() // just to be sure
    Files.write(downloadFile, src.mkString("").getBytes)
  }

  def prepareEnviroment(options: Map[String, String]): Map[String, String] = {
    require(options.get("HDFS_CONF_URI").isDefined,
      "a proper HDFS URI must be configured to get Hadoop Configuration")
    require(sys.env.get("HADOOP_CONF_DIR").isDefined,
      "a proper Hadoop Conf Dir must be configured to store Hadoop Configuration")
    val hadoopConfUri = options.get("HDFS_CONF_URI").get
    val hadoopConfDir = sys.env.get("HADOOP_CONF_DIR").get
    downloadFile(hadoopConfUri, "core-site.xml", hadoopConfDir)
    downloadFile(hadoopConfUri, "hdfs-site.xml", hadoopConfDir)
    downloadFile(hadoopConfUri, "krb5.conf", "/etc/")
    Map.empty[String, String]
  }
}

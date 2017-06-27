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

package org.apache.spark.deploy.rest.mesos

import java.io.File
import java.text.SimpleDateFormat
import java.util.{Date, Locale}
import java.util.concurrent.atomic.AtomicLong
import javax.servlet.http.HttpServletResponse

import org.apache.spark.{SparkConf, SPARK_VERSION => sparkVersion}
import org.apache.spark.deploy.Command
import org.apache.spark.deploy.mesos.{MesosClusterDispatcher, MesosDriverDescription}
import org.apache.spark.deploy.rest._
import org.apache.spark.scheduler.cluster.mesos.MesosClusterScheduler
import org.apache.spark.security.VaultHelper
import org.apache.spark.util.Utils

/**
 * A server that responds to requests submitted by the [[RestSubmissionClient]].
 * All requests are forwarded to
 * [[org.apache.spark.scheduler.cluster.mesos.MesosClusterScheduler]].
 * This is intended to be used in Mesos cluster mode only.
 * For more details about the REST submission please refer to [[RestSubmissionServer]] javadocs.
 */
private[spark] class MesosRestServer(
    host: String,
    requestedPort: Int,
    masterConf: SparkConf,
    scheduler: MesosClusterScheduler)
  extends RestSubmissionServer(host, requestedPort, masterConf) {

  protected lazy val token = {
    require(masterConf.getOption("spark.secret.vault.host").isDefined,
      "You are attempt a login in Vault but no vault obtained," +
      " please confiure spark.vault.host in your Stratio Spark Dispatcher instance")
    VaultHelper.getTokenFromAppRole(masterConf.getOption("spark.secret.vault.host").get,
      sys.env("VAULT_ROLE_ID"),
      sys.env("VAULT_SECRET_ID"))
  }

  protected override val submitRequestServlet =
    new MesosSubmitRequestServlet(scheduler, masterConf)
  protected override val killRequestServlet =
    new MesosKillRequestServlet(scheduler, masterConf)
  protected override val statusRequestServlet =
    new MesosStatusRequestServlet(scheduler, masterConf)
}

private[mesos] class MesosSubmitRequestServlet(
    scheduler: MesosClusterScheduler,
    conf: SparkConf)
  extends SubmitRequestServlet {

  private lazy val vaultHost = conf.getOption("spark.vault.host")
  private val DEFAULT_SUPERVISE = false
  private val DEFAULT_MEMORY = Utils.DEFAULT_DRIVER_MEM_MB // mb
  private val DEFAULT_CORES = 1.0

  private val nextDriverNumber = new AtomicLong(0)
  // For application IDs
  private def createDateFormat = new SimpleDateFormat("yyyyMMddHHmmss", Locale.US)
  private def newDriverId(submitDate: Date): String =
    f"driver-${createDateFormat.format(submitDate)}-${nextDriverNumber.incrementAndGet()}%04d"

  /**
   * Build a driver description from the fields specified in the submit request.
   *
   * This involves constructing a command that launches a mesos framework for the job.
   * This does not currently consider fields used by python applications since python
   * is not supported in mesos cluster mode yet.
   */
  private def buildDriverDescription(request: CreateSubmissionRequest): MesosDriverDescription = {
    // Required fields, including the main class because python is not yet supported
    val appResource = Option(request.appResource).getOrElse {
      throw new SubmitRestMissingFieldException("Application jar is missing.")
    }
    val mainClass = Option(request.mainClass).getOrElse {
      throw new SubmitRestMissingFieldException("Main class is missing.")
    }

    // Optional fields
    val sparkProperties = request.sparkProperties
    val driverExtraJavaOptions = sparkProperties.get("spark.driver.extraJavaOptions")
    val driverExtraClassPath = sparkProperties.get("spark.driver.extraClassPath")
    val driverExtraLibraryPath = sparkProperties.get("spark.driver.extraLibraryPath")
    val superviseDriver = sparkProperties.get("spark.driver.supervise")
    val driverMemory = sparkProperties.get("spark.driver.memory")
    val driverCores = sparkProperties.get("spark.driver.cores")
    val appArgs = request.appArgs
    val environmentVariables = request.environmentVariables
    val name = request.sparkProperties.getOrElse("spark.app.name", mainClass)

    // Construct driver description
    val conf = new SparkConf(false).setAll(sparkProperties)
    val extraClassPath = driverExtraClassPath.toSeq.flatMap(_.split(File.pathSeparator))
    val extraLibraryPath = driverExtraLibraryPath.toSeq.flatMap(_.split(File.pathSeparator))
    val extraJavaOpts = driverExtraJavaOptions.map(Utils.splitCommandString).getOrElse(Seq.empty)
    val sparkJavaOpts = Utils.sparkJavaOpts(conf)
    val javaOpts = sparkJavaOpts ++ extraJavaOpts

    val sparkPropertiesToSend = if (sparkProperties.get("spark.secret.vault.role").isDefined) {
      if (sparkProperties.isDefinedAt("spark.secret.vault.host")) {
        val vaultUrl = sparkProperties("spark.secret.vault.host")
        val role = sparkProperties.get("spark.secret.vault.role").getOrElse(sys.env("VAULT_ROLE"))
        logTrace(s"obtaining vault secretID and role ID using role: $role")
        val driverSecretId = VaultHelper.getSecretIdFromVault(vaultUrl, role)
        val driverRoleId = VaultHelper.getRoleIdFromVault(vaultUrl, role)

        Map("spark.mesos.driverEnv.VAULT_ROLE_ID" -> driverRoleId,
          "spark.mesos.driverEnv.VAULT_SECRET_ID" -> driverSecretId) ++ request.sparkProperties
      }
      else {
        logDebug("Vault appRole provided but non vault host" +
          " had been provided, skipping vault calling")
        request.sparkProperties
      }
    } else {
      request.sparkProperties
    }
    val command = new Command(
      mainClass, appArgs, environmentVariables, extraClassPath, extraLibraryPath, javaOpts)
    val actualSuperviseDriver = superviseDriver.map(_.toBoolean).getOrElse(DEFAULT_SUPERVISE)
    val actualDriverMemory = driverMemory.map(Utils.memoryStringToMb).getOrElse(DEFAULT_MEMORY)
    val actualDriverCores = driverCores.map(_.toDouble).getOrElse(DEFAULT_CORES)
    val submitDate = new Date()
    val submissionId = newDriverId(submitDate)

    new MesosDriverDescription(
      name, appResource, actualDriverMemory, actualDriverCores, actualSuperviseDriver,
      command, sparkPropertiesToSend, submissionId, submitDate)
  }

  protected override def handleSubmit(
      requestMessageJson: String,
      requestMessage: SubmitRestProtocolMessage,
      responseServlet: HttpServletResponse): SubmitRestProtocolResponse = {
    requestMessage match {
      case submitRequest: CreateSubmissionRequest =>
        val driverDescription = buildDriverDescription(submitRequest)
        val s = scheduler.submitDriver(driverDescription)
        s.serverSparkVersion = sparkVersion
        val unknownFields = findUnknownFields(requestMessageJson, requestMessage)
        if (unknownFields.nonEmpty) {
          // If there are fields that the server does not know about, warn the client
          s.unknownFields = unknownFields
        }
        s
      case unexpected =>
        responseServlet.setStatus(HttpServletResponse.SC_BAD_REQUEST)
        handleError(s"Received message of unexpected type ${unexpected.messageType}.")
    }
  }
}

private[mesos] class MesosKillRequestServlet(scheduler: MesosClusterScheduler, conf: SparkConf)
  extends KillRequestServlet {
  protected override def handleKill(submissionId: String): KillSubmissionResponse = {
    val k = scheduler.killDriver(submissionId)
    k.serverSparkVersion = sparkVersion
    k
  }
}

private[mesos] class MesosStatusRequestServlet(scheduler: MesosClusterScheduler, conf: SparkConf)
  extends StatusRequestServlet {
  protected override def handleStatus(submissionId: String): SubmissionStatusResponse = {
    val d = scheduler.getDriverStatus(submissionId)
    d.serverSparkVersion = sparkVersion
    d
  }
}

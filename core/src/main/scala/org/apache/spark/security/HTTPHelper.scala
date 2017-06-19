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
import org.apache.http.client.methods.{HttpGet, HttpPost, HttpUriRequest}
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClientBuilder

import org.apache.spark.internal.Logging

object HTTPHelper extends Logging{

  lazy val client: HttpClient = HttpClientBuilder.create().build()

  def executePost(requestUrl: String,
                  parentField: String,
                  headers: Option[Seq[(String, String)]],
                  entity: Option[String] = None): Map[String, Any] = {
    val post = new HttpPost(requestUrl)

    getContentFromResponse(post, parentField, headers, entity)
  }
  def executeGet(requestUrl: String,
                 parentField: String,
                 headers: Option[Seq[(String, String)]]): Map[String, Any] = {
    val get = new HttpGet(requestUrl)
    getContentFromResponse(get, parentField, headers)
  }

  private def getContentFromResponse(uriRequest: HttpUriRequest,
                                     parentField: String,
                                     headers: Option[Seq[(String, String)]],
                                     entities: Option[String] = None): Map[String, Any] = {

    headers.map(head => head.foreach { case (head, value) => uriRequest.addHeader(head, value) })

    entities.map(entity => uriRequest.asInstanceOf[HttpPost].setEntity(new StringEntity(entity)))

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
}

#!/bin/bash

source kms_utils.sh
source commons.sh

# Create krb5.conf file
KERBEROS_REALM=${KERBEROS_REALM:=DEMO.STRATIO.COM}
KERBEROS_KDC_HOST=${KERBEROS_KDC_HOST:=idp.integration.labs.stratio.com:88}
KERBEROS_KADMIN_HOST=${KERBEROS_KADMIN_HOST:=idp.integration.labs.stratio.com:749}
HDFS_DFS_PERMISSIONS_ENABLED=${HDFS_DFS_PERMISSIONS_ENABLED:=false}
HDFS_DFS_BLOCK_ACCESS_TOKEN_ENABLE=${HDFS_DFS_BLOCK_ACCESS_TOKEN_ENABLE:=true}
HDFS_DFS_HTTP_POLICY=${HDFS_DFS_HTTP_POLICY:=HTTPS_ONLY}
HDFS_DFS_HTTPS_PORT=${HDFS_DFS_HTTPS_PORT:=50070}
HDFS_FS_DEFAULTFS=${HDFS_FS_DEFAULTFS:=127.0.0.2:8020}
HDFS_HADOOP_SECURITY_AUTHORIZATION=${HDFS_HADOOP_SECURITY_AUTHORIZATION:=true}
HDFS_HADOOP_SECURITY_AUTHENTICATION=${HDFS_HADOOP_SECURITY_AUTHENTICATION:=kerberos}
HADOOP_CONF_DIR=${HADOOP_CONF_DIR:=/tmp/hadoop}
HISTORY_MESOS_ROLE=${HISTORY_MESOS_ROLE:=stratio}
HISTORY_SERVER_MESOS_PASS=${HISTORY_SERVER_MESOS_PASS:=stratio}
HISTORY_SERVER_MESOS_USER=${HISTORY_SERVER_MESOS_USER:=stratio}
SPARK_HISTORY_OPTS=${SPARK_HISTORY_OPTS:=""}
read -r -d '' auth_to_local_value << EOM
RULE:[1:\$1@\$0](.*@DEMO.STRATIO.COM)s/@DEMO.STRATIO.COM//
RULE:[2:\$1@\$0](.*@DEMO.STRATIO.COM)s/@DEMO.STRATIO.COM//
DEFAULT
EOM

function main() {
   HDFS_HADOOP_SECURITY_AUTH_TO_LOCAL=${HDFS_HADOOP_SECURITY_AUTH_TO_LOCAL:=${auth_to_local_value}}
   VAULT_PORT=${VAULT_PORT:=8200}
   VAULT_TOKEN=${VAULT_TOKEN:=1111111-2222-3333-4444-5555555555555}
   SPARK_HOME=/opt/sds/spark
   FQDN=${HISTORY_SERVER_FQDN:="history-server"}
   INSTANCE=${HISTORY_SERVER_FQDN:=$FQDN}

   mkdir -p $HADOOP_CONF_DIR

   if [[ "$SECURED_MESOS" == "true" ]]
   then
     #Get Mesos secrets from Vault
     getPass "userland" "history-server" "mesos"
     # This should populate HISTORY_SERVER_MESOS_USER and HISTORY_SERVER_MESOS_PASS
     SPARK_HISTORY_OPTS="-Dspark.mesos.principal=${HISTORY_SERVER_MESOS_USER} -Dspark.mesos.secret=${HISTORY_SERVER_MESOS_PASS} -Dspark.mesos.role=${HISTORY_MESOS_ROLE} ${SPARK_HISTORY_OPTS}"
   else
	echo 'MESOS SECURITY IS NOT ENABLE'
   fi

   if [[ "$HDFS_KRB_ENABLE" == "true" ]]
   then
   SPARK_KEYTAB_PATH="/etc/sds/spark/security"
   getKrb userland $INSTANCE $FQDN "$SPARK_KEYTAB_PATH" HISTORY_SERVER_PRINCIPAL_NAME

   generate_krb-conf "${KERBEROS_REALM}" "${KERBEROS_KDC_HOST}" "${KERBEROS_KADMIN_HOST}"
   mv "/tmp/krb5.conf.tmp" "/etc/krb5.conf"
   SPARK_HISTORY_OPTS="-Dspark.history.kerberos.principal=${HISTORY_SERVER_PRINCIPAL_NAME} -Dspark.history.kerberos.keytab=${SPARK_KEYTAB_PATH}/${FQDN}.keytab -Dspark.history.kerberos.enabled=true ${SPARK_HISTORY_OPTS}"
   else
	echo 'HDFS SECURITY IS NOT ENABLE'
   fi

   generate_core-site "${HDFS_FS_DEFAULTFS}" "${HDFS_HADOOP_SECURITY_AUTHORIZATION}" "${HDFS_HADOOP_SECURITY_AUTHENTICATION}" "${HDFS_HADOOP_SECURITY_AUTH_TO_LOCAL}"
   mv "/tmp/core-site.xml.tmp" "${HADOOP_CONF_DIR}/core-site.xml"

   # Needed variables to generate a hdfs-site.xml.

   generate_hdfs_site "${HDFS_DFS_PERMISSIONS_ENABLED}" "${HDFS_DFS_BLOCK_ACCESS_TOKEN_ENABLE}" "${HDFS_DFS_HTTP_POLICY}" "${HDFS_DFS_HTTPS_PORT}"
   mv "/tmp/hdfs-site.xml.tmp" "${HADOOP_CONF_DIR}/hdfs-site.xml"

   SPARK_HISTORY_OPTS="-Dspark.history.fs.logDirectory=hdfs://$HDFS_FS_DEFAULTFS/${HISTORY_SERVER_LOG_DIR} ${SPARK_HISTORY_OPTS}"

   SPARK_HISTORY_OPTS="-Dspark.history.ui.port=${PORT0} ${SPARK_HISTORY_OPTS}" $SPARK_HOME/bin/spark-class org.apache.spark.deploy.history.HistoryServer
}

main

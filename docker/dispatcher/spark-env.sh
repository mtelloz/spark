#!/usr/bin/env bash

# This file is sourced when running various Spark programs.
# Copy it as spark-env.sh and edit that to configure Spark for your site.

cd $MESOS_SANDBOX

MESOS_NATIVE_JAVA_LIBRARY=/usr/lib/libmesos.so

if [ "${SPARK_VIRTUAL_USER_NETWORK}" = "true" ]; then
   HOST="$(hostname --all-ip-addresses|xargs)"
   echo "Virutal network detected changed LIBPROCESS_IP $LIBPROCESS_IP to $HOST"
   export LIBPROCESS_IP=$HOST
fi

if [ "${SPARK_SSL_SECURITY_ENABLED}" == "true" ]; then
    source /opt/spark/dist/kms_utils-0.2.1.sh

    VAULT_HOSTS=$VAULT_HOST
    export SPARK_SSL_CERT_PATH="/tmp"
    SERVICE_ID=$APP_NAME
    INSTANCE=$APP_NAME

   echo "VAULT_HOSTS: ${VAULT_HOSTS} SPARK_SSL_CERT_PATH: ${SPARK_SSL_CERT_PATH} SERVICE_ID: ${SERVICE_ID} INSTANCE; ${INSTANCE}"

   echo "VAULT_ROLE_ID: $VAULT_ROLE_ID"

    #0--- IF VAULT_ROLE_ID IS NOT EMPTY [!-z $YOUR_VAR] IT MEANS THAT WE ARE DEALING WITH SPARK DRIVER
    if [! -z "$VAULT_ROLE_ID"]; then
        login
    else
        #1--- FROM TEMP TOKEN GET APP TOKEN
        VAULT_TOKEN=$(curl -k -L -XPOST -H "X-Vault-Token:$VAULT_TEMP_TOKEN" "$VAULT_HOSTS/v1/sys/wrapping/unwrap" -s| python -m json.tool | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["data"]["token"]')
    fi

   echo "VAULT_TOKEN: $VAULT_TOKEN"

    #2--- GET SECRETS WITH APP TOKEN
    getCert "userland" "$INSTANCE" "$SERVICE_ID" "PEM" $SPARK_SSL_CERT_PATH
    getCAbundle $SPARK_SSL_CERT_PATH "PEM"

    #3--- RESTORE TEMP TOKEN
    export VAULT_TEMP_TOKEN=$(curl -k -L -XPOST -H "X-Vault-Wrap-TTL: 6000" -H "X-Vault-Token:$VAULT_TOKEN" -d "{\"token\": \"$VAULT_TOKEN\" }" "$VAULT_HOSTS/v1/sys/wrapping/wrap" -s| python -m json.tool | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["wrap_info"]["token"]')

    echo "VAULT_TEMP_TOKEN: $VAULT_TEMP_TOKEN"

    openssl pkcs8 -topk8 -inform pem -in "${SPARK_SSL_CERT_PATH}/${SERVICE_ID}.key" -outform der -nocrypt -out "${SPARK_SSL_CERT_PATH}/pkcs8.key"

    mv $SPARK_SSL_CERT_PATH/${SERVICE_ID}.pem $SPARK_SSL_CERT_PATH/cert.crt
    mv $SPARK_SSL_CERT_PATH/ca-bundle.pem $SPARK_SSL_CERT_PATH/caroot.crt

fi

# I first set this to MESOS_SANDBOX, as a Workaround for MESOS-5866
# But this fails now due to MESOS-6391, so I'm setting it to /tmp
MESOS_DIRECTORY=/tmp

# Options read when launching programs locally with
# ./bin/run-example or ./bin/spark-submit
# - HADOOP_CONF_DIR, to point Spark towards Hadoop configuration files
# - SPARK_LOCAL_IP, to set the IP address Spark binds to on this node
# - SPARK_PUBLIC_DNS, to set the public dns name of the driver program
# - SPARK_CLASSPATH, default classpath entries to append

# Options read by executors and drivers running inside the cluster
# - SPARK_LOCAL_IP, to set the IP address Spark binds to on this node
# - SPARK_PUBLIC_DNS, to set the public DNS name of the driver program
# - SPARK_CLASSPATH, default classpath entries to append
# - SPARK_LOCAL_DIRS, storage directories to use on this node for shuffle and RDD data
# - MESOS_NATIVE_JAVA_LIBRARY, to point to your libmesos.so if you use Mesos

# Options read in YARN client mode
# - HADOOP_CONF_DIR, to point Spark towards Hadoop configuration files
# - SPARK_EXECUTOR_INSTANCES, Number of workers to start (Default: 2)
# - SPARK_EXECUTOR_CORES, Number of cores for the workers (Default: 1).
# - SPARK_EXECUTOR_MEMORY, Memory per Worker (e.g. 1000M, 2G) (Default: 1G)
# - SPARK_DRIVER_MEMORY, Memory for Master (e.g. 1000M, 2G) (Default: 1G)
# - SPARK_YARN_APP_NAME, The name of your application (Default: Spark)
# - SPARK_YARN_QUEUE, The hadoop queue to use for allocation requests (Default: ‘default’)
# - SPARK_YARN_DIST_FILES, Comma separated list of files to be distributed with the job.
# - SPARK_YARN_DIST_ARCHIVES, Comma separated list of archives to be distributed with the job.

# Options for the daemons used in the standalone deploy mode
# - SPARK_MASTER_IP, to bind the master to a different IP address or hostname
# - SPARK_MASTER_PORT / SPARK_MASTER_WEBUI_PORT, to use non-default ports for the master
# - SPARK_MASTER_OPTS, to set config properties only for the master (e.g. "-Dx=y")
# - SPARK_WORKER_CORES, to set the number of cores to use on this machine
# - SPARK_WORKER_MEMORY, to set how much total memory workers have to give executors (e.g. 1000m, 2g)
# - SPARK_WORKER_PORT / SPARK_WORKER_WEBUI_PORT, to use non-default ports for the worker
# - SPARK_WORKER_INSTANCES, to set the number of worker processes per node
# - SPARK_WORKER_DIR, to set the working directory of worker processes
# - SPARK_WORKER_OPTS, to set config properties only for the worker (e.g. "-Dx=y")
# - SPARK_DAEMON_MEMORY, to allocate to the master, worker and history server themselves (default: 1g).
# - SPARK_HISTORY_OPTS, to set config properties only for the history server (e.g. "-Dx=y")
# - SPARK_SHUFFLE_OPTS, to set config properties only for the external shuffle service (e.g. "-Dx=y")
# - SPARK_DAEMON_JAVA_OPTS, to set config properties for all daemons (e.g. "-Dx=y")
# - SPARK_PUBLIC_DNS, to set the public dns name of the master or workers

# Generic options for the daemons used in the standalone deploy mode
# - SPARK_CONF_DIR      Alternate conf dir. (Default: ${SPARK_HOME}/conf)
# - SPARK_LOG_DIR       Where log files are stored.  (Default: ${SPARK_HOME}/logs)
# - SPARK_PID_DIR       Where the pid file is stored. (Default: /tmp)
# - SPARK_IDENT_STRING  A string representing this instance of spark. (Default: $USER)
# - SPARK_NICENESS      The scheduling priority for daemons. (Default: 0)

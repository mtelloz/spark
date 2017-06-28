@Library('libpipelines@master') _

hose {
    MAIL = 'support'
    SLACKTEAM = 'stratiosecurity'
    MODULE = 'stratio-spark'
    REPOSITORY = 'spark'
    DEVTIMEOUT = 300
    RELEASETIMEOUT = 200
    BUILDTOOLVERSION = '3.5.0'
    PKGMODULESNAMES = ['stratio-spark']

    DEV = { config ->

        doPackage(config)
       // doUT(config)
        parallel(DOCKER1: {
                    doDocker(conf: config, dockerfile:"DockerfileDispatcher")
                }, DEPLOY: {
                    doDeploy(config)
                }, DOCKER2: {
                     doDocker(conf: config, dockerfile:"DockerfileHistory", image:"spark-stratio-history-server")
        }, failFast: config.FAILFAST)
     }
}

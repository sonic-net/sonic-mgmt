def call(Map options = [:]) {
    String buildArtifactKeepNum = options.buildArtifactKeepNum ?: '15'
    String buildKeepNum = options.buildKeepNum ?: '30'
    // The default cron schedule is one build between 1:xx pm - 4:xx pm on Monday
    String buildCronSchedule = options.buildCronSchedule ?: 'H H(13-16) * * 1'

    properties([
            parameters([
                    choice(name: 'logLevel', choices: ['WARN', 'INFO', 'DEBUG', 'TRACE'], description: 'Set the logging level. WARN is the default.')
            ]),
            buildDiscarder(
                    logRotator(artifactNumToKeepStr: buildArtifactKeepNum, numToKeepStr: buildKeepNum)
            ),
            pipelineTriggers([cron(buildCronSchedule)])
    ])
}

def call(Map optional, String projectName, String projectVersion, String imageDirectory) {
    optional.projectName = projectName
    optional.projectVersion = projectVersion
    optional.imageDirectory = imageDirectory
    call(optional)
}


def call(Map optional) {

    String projectVersion = optional.projectVersion
    String projectName = optional.projectName
    String imageDirectory = optional.imageDirectory
    String url = "https://blackduck.eng.netapp.com"
    String credId = 'hubProductionToken'

    if((boolean) optional.staging){
        url = "https://blackduck-staging.eng.netapp.com"
        credId = 'hubStagingToken'
    }

    BLACKDUCK_SKIP_PHONE_HOME = true
    withCredentials([string(credentialsId: credId, variable: 'TOKEN')]) {
        String memory = optional.scannerMemoryMb ?: '8192'
        String logLevel = optional.logLevel ?: 'INFO'
        String coreCount = optional.coreCount ?: 1
        String timeoutMinutes = optional.timeout ?: 60

        sh''' wget -qN http://esgweb.eng.netapp.com/~lorenp/synopsys-detect-6.0.0-air-gap.zip -O /tmp/synopsys-detect.zip
              unzip -u -d /tmp/tools /tmp/synopsys-detect.zip
              rm -f /tmp/synopsys-detect.zip
        '''

        // Create the temporary directory for the scan logs
        def scanTempDir = sh(returnStdout: true, script: "mktemp --directory \"/tmp/synopsys-detect-${projectName}-${projectVersion}-XXXXXXXXXX\"").trim()

        echo "Initiating Hub Scanning Process on every image in ${imageDirectory}"
        echo "Sending results to ${url}"
        echo "Using a logLevel of ${logLevel}"
        echo "Additional parameters: ${optional}"
        echo "Running with a timeout value of ${timeoutMinutes} minutes"

        // We need to locate all of the images to scan.
        sh "find ${imageDirectory} -type f -iname '*.tar'> listFiles"
        def files = readFile( "listFiles" ).split('\n');
        try {
            files.each {
                def fileName = it.split('/')[-1];
                timeout(time: "${timeoutMinutes}", unit: 'MINUTES') {
                    // Run a single scan for each image we find, using the filename as a scan identifier
                    sh """
                    java -Xms4096m -Xmx8192m -Xss1024m -jar /tmp/tools/synopsys-detect-6.0.0.jar \
                        --blackduck.url=${url} \
                        --detect.blackduck.signature.scanner.memory="${memory}" \
                        --detect.blackduck.signature.scanner.individual.file.matching="ALL" \
                        --blackduck.api.token=${TOKEN} \
                        --detect.docker.tar=${it} \
                        --detect.parallel.processors=${coreCount} \
                        --detect.code.location.name=${projectName}-${projectVersion}-${fileName} \
                        --detect.project.name=${projectName} \
                        --detect.project.version.name=${projectVersion} \
                        --detect.cleanup=false \
                        --blackduck.trust.cert=true \
                        --detect.output.path=${scanTempDir} \
                        --logging.level.com.synopsys.integration="${logLevel}"

                """
                }
            }
        } finally {
            dir("${scanTempDir}") {
                deleteDir()
            }
        }
    }
}

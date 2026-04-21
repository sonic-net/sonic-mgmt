/**
 * Initiate a scan of Synopsys Detect. By default the working directory ('./') is scanned and all detectors are enabled.
 * Java MUST be installed for this to be successful, and it is suggested to scan in a docker container due to the
 * detector possibly building the project automatically.
 *
 * The 'optional' map supports these fields:
 * - clearPriorScans: false. Clear previous scans (but doesn't delete them) for the associated project and version on the server.
 * - coreCount: -1. Scanner parallel processors where -1 uses the number of cores on the system.
 * - disableDetector: false. Disable the synopsys detector; the detector SHOULD be run but it can result in build issues
 *      and can be disabled.
 * - logLevel: info. Logging level of synopsys.
 * - productionScan: false. Set this to true to send scan results to the production blackduck server; staging is used by default.
 * - scanOpts: [:]. A map of additional hub command-line arguments, or overrides, depending on project needs. for example,
 *      users can control the detector search depth with optional.scanOpts["--detect.detector.search.depth"] = "0".
 * - scannerMemoryMB: 1024.
 * - timeout: 60. Maximum scan timeout, in minutes, before failing the build.
 *
 * Important implementation notes:
 * - Java must be installed and in the path.
 * - A temporary directory, scanTempDir, is created at '/tmp/synopsys-detect-<projectName>-<projectVersion>-XXXXXXXX'.
 *      This temporary is DELETED after the scan to avoid excessive storage usage.
 * - Synopsys Detect Air Gap (600MB+ zip, 1.5GB+ extracted) is generated at '$scanTempDir/synopsys-detect-air-gap/<synopVersion>'.
 *      This path is deleted along with the temp dir after the scan.
 * - The files in $scanTempDir/runs/** are archived.
 * - URLs
 *      - https://synopsys.atlassian.net/wiki/spaces/INTDOCS/pages/622673/Synopsys+Detect+Properties
 *      - https://synopsys.atlassian.net/wiki/spaces/INTDOCS/pages/62423113/Synopsys+Detect
 *
 * @param optional map of optional arguments
 * @param projectName the name of the project
 * @param projectVersion the version of the project
 */
def call(Map optional = [:], String projectName, String projectVersion) {
    optional.projectName = projectName
    optional.projectVersion = projectVersion
    optional.scanOpts = (Map) optional.scanOpts ?: [:]
    call(optional)
}

def call(Map optional) {
    String projectVersion = optional.projectVersion
    String projectName = optional.projectName
    String synopsysDetectVersion = optional.synopsysDetectVersion ?: "6.3.0"
    BLACKDUCK_SKIP_PHONE_HOME = true

    String url = "https://blackduck-staging.eng.netapp.com"
    String credId = 'hubStagingToken'

    // Use the production server if productionScan is explicitly set to true
    if (new Boolean(optional.productionScan)) {
        url = "https://blackduck.eng.netapp.com"
        credId = 'hubProductionToken'
    }

    withCredentials([string(credentialsId: credId, variable: 'TOKEN')]) {
        String timeoutMinutes = optional.timeout ?: 60

        // Create the temporary directory for the scan logs and the extracted hub-detect zip
        def scanTempDir = sh(returnStdout: true, script: "mktemp --directory \"/tmp/synopsys-detect-${projectName}-${projectVersion}-XXXXXXXXXX\"").trim()
        def synopsysDir = "${scanTempDir}/synopsys-detect-air-gap/${synopsysDetectVersion}"
        setupSynopsysDetect(synopsysDetectVersion, synopsysDir: synopsysDir)

        echo "Using temporary directory ${scanTempDir}"
        echo "Sending results to ${url}"
        echo "Additional parameters: ${optional}"
        echo "Using timeout of ${timeoutMinutes} minutes"

        Map m = [:]
        m["--blackduck.trust.cert"] = "true"
        m["--blackduck.url"] = url
        m["--blackduck.api.token"] = TOKEN
        m["--detect.project.name"] = projectName
        m["--detect.project.version.name"] = projectVersion
        m["--detect.code.location.name"] = "${projectName}-${projectVersion}"
        m["--detect.project.codelocation.unmap"] = optional.clearPriorScans ?: "false"
        m["--detect.blackduck.signature.scanner.memory"] = optional.scannerMemoryMB ?: "1024"
        m["--detect.parallel.processors"] = optional.coreCount ?: -1
        m["--detect.cleanup"] = "false"
        m["--detect.blackduck.signature.scanner.paths"] = optional.scanDir ?: './'
        m["--detect.output.path"] = scanTempDir
        m["--logging.level.com.synopsys.integration"] = optional.logLevel ?: "INFO"
        m["--detect.detector.search.depth"] = "3"
        m["--detect.sbt.report.depth"] = "3"
        m["--detect.blackduck.signature.scanner.exclusion.name.patterns"] = "node_modules,.git,.gradle"
        m["--detect.blackduck.signature.scanner.exclusion.pattern.search.depth"] = "30"
        m["--detect.docker.inspector.air.gap.path"] = "${synopsysDir}/packaged-inspectors/docker"
        m["--detect.nuget.inspector.air.gap.path"] = "${synopsysDir}/packaged-inspectors/nuget"
        m["--detect.gradle.inspector.air.gap.path"] = "${synopsysDir}/packaged-inspectors/gradle"
        m["--detect.blackduck.signature.scanner.individual.file.matching"] = "ALL"

        if (optional.cloneVersion) {
            m["--detect.clone.project.version.name"] = optional.cloneVersion
        }
        if ((boolean) optional.disableDetector) {
            m["--detect.tools.excluded"] = "DETECTOR"
        }

        m.putAll((Map) optional.scanOpts)

        synopsysArgs = m.collectEntries { k, v -> ["$k=$v"] }.keySet().join(" \\\n  ")
        synopsysExec = "java -Xms1024m -Xmx2048m -jar ${synopsysDir}/synopsys-detect-${synopsysDetectVersion}.jar ${synopsysArgs}"
        echo "The blackduck scan execute command: \n'${synopsysExec}'"

        try {
            timeout(time: "${timeoutMinutes}", unit: 'MINUTES') {
                sh """
                    ${synopsysExec}
                    # Delete any existing docker extractions from this scan to avoid excessive storage use.
                    rm -rf ${scanTempDir}/runs/*/extractions || true
                    mv ${scanTempDir}/runs synopsysRuns
                """

                // NOTE: Archiving works **ONLY** in the build workspace. All artifacts must be copied to the workspace.
                //       Ignore gz to avoid archiving docker images.
                archiveArtifacts artifacts: "synopsysRuns/**", excludes: "**/*.gz"
            }
        } finally {
            dir("${scanTempDir}") {
                deleteDir()
            }
        }
    }
}

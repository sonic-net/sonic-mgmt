
def call(Map options = [:], String synopsysDetectVersion) {
    options.synopsysDir = options.synopsysDir ?: "/tmp/synopsys-detect-air-gap/${synopsysDetectVersion}"
    if (new File(options.synopsysDir).exists()) {
        echo "No need to fetch synopsys-${synopsysDetectVersion}, directory exists ${options.synopsysDir}"
        return
    }

    sh """
        wget -qN http://esgweb.eng.netapp.com/~blucas/packages/synopsys-detect-${synopsysDetectVersion}-air-gap.zip -O synopsys-detect.zip
        mkdir -p ${options.synopsysDir}
        unzip -q -d ${options.synopsysDir} -u synopsys-detect.zip
        rm -f synopsys-detect.zip
    """
}

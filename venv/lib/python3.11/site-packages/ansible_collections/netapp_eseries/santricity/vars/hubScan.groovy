def call(Map optional = [:], String projectName, String projectVersion) {
    optional.projectName = projectName
    optional.projectVersion = projectVersion
    call(optional)
}

def call(Map optional) {
    // Correctly set if the scan is intended for production.
    //   hubScan uses the variable 'staging' (defaulting to true), and hubScanProject uses 'productionScan' (defaulting to false).
    optional.productionScan = !((boolean) optional.staging)

    hubScanProject(optional)
}

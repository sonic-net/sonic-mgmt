def call(Map optional) {
    if (optional.docker) {
        echo "Ensuring that Docker is available on the system."
        sh """
            docker --version
        """
    }
}

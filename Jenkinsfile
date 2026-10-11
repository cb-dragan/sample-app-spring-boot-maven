pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sh 'gradle clean build --no-daemon --no-build-cache --no-configuration-cache --rerun-tasks --info --console=plain'
      }
    }

  }
}
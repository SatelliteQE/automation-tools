pipeline {
  agent {
    node {
      label 'sat6-rhel'
    }

  }
  stages {
    stage('build') {
      agent {
        node {
          label 'sat6-rhel'
        }

      }
      steps {
        sh 'make gitflake8'
      }
    }
  }
}
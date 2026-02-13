pipeline {
    agent any

    environment {
        JENKINS_URL = 'http://localhost:8080/'
        ADMIN_USER  = 'admin'
        ADMIN_TOKEN = credentials('jenkins-admin-token')

        SMTP_CREDS  = credentials('smtp-creds')
        SMTP_SERVER = 'smtp.gmail.com'
        SMTP_PORT   = '587'

        CSV_PATH = 'users.csv'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Using CSV from workspace: ${CSV_PATH}"
            }
        }

        stage('Setup Python Virtual Environment') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    python -m pip install --upgrade pip
                '''
            }
        }

        stage('Install Python Dependencies') {
            steps {
                sh '''
                    . venv/bin/activate
                    pip install requests urllib3
                '''
            }
        }

        stage('Provision Users') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'smtp-creds',
                        usernameVariable: 'SMTP_USER',
                        passwordVariable: 'SMTP_PASSWORD'
                    )
                ]) {
                    sh '''
                        . venv/bin/activate

                        export SMTP_USER=$SMTP_USER
                        export SMTP_PASSWORD=$SMTP_PASSWORD

                        python provision_jenkins_users.py
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'users.csv, provision_jenkins_users.py', fingerprint: true, allowEmptyArchive: true
        }
    }
}

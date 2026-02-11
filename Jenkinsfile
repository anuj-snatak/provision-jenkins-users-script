pipeline {
    agent any

    environment {
        // Jenkins connection – CHANGE THESE!
        JENKINS_URL = 'http://54.188.28.149:8080/'   // your Jenkins URL
        ADMIN_USER = 'admin'                                 // admin username
        ADMIN_TOKEN = credentials('jenkins-admin-token')     // secret text credential

        // SMTP (Gmail app password) – CHANGE THESE!
        SMTP_CREDS = credentials('smtp-creds')
        SMTP_USER = "${SMTP_CREDS_USR}"
        SMTP_PASSWORD = "${SMTP_CREDS_PSW}"
        SMTP_SERVER = 'smtp.gmail.com'
        SMTP_PORT = '587'
        FROM_EMAIL = "${SMTP_USER}"

        // CSV file (in repository root)
        CSV_PATH = 'users.csv'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                echo "Using CSV from workspace: ${CSV_PATH}"
            }
        }

        stage('Install Python Dependencies') {
            steps {
                sh '''
                    # Install Python packages for the Jenkins user only
                    pip install --user --upgrade pip
                    pip install --user requests urllib3
                '''
            }
        }

        stage('Provision Users') {
            steps {
                sh '''
                    # Add user's local Python bin to PATH (so installed packages are found)
                    export PATH=$HOME/.local/bin:$PATH
                    python3 provision_jenkins_users.py
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'users.csv, provision_jenkins_users.py', fingerprint: true
        }
        failure {
            emailext(
                subject: "User Provisioning FAILED - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "Check console: ${env.BUILD_URL}console",
                to: 'your.name@gmail.com'   // CHANGE to your email / team
            )
        }
    }
}

pipeline {
    agent any

    environment {
        // Jenkins connection – CHANGE THESE!
        JENKINS_URL = 'http://localhost:8080/'   // your Jenkins URL
        ADMIN_USER = 'admin'
        ADMIN_TOKEN = credentials('jenkins-admin-token')

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

        stage('Bootstrap pip (no system packages)') {
            steps {
                sh '''
                    # Download get-pip.py using Python's built-in urllib (no wget/curl required)
                    python3 -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')"
                    
                    # Install pip locally for the Jenkins user
                    python3 get-pip.py --user
                    
                    # Clean up
                    rm get-pip.py
                '''
            }
        }

        stage('Install Python Dependencies') {
            steps {
                sh '''
                    # Use the freshly installed local pip
                    export PATH=$HOME/.local/bin:$PATH
                    pip install --user --upgrade pip
                    pip install --user requests urllib3
                '''
            }
        }

        stage('Provision Users') {
            steps {
                sh '''
                    # Add local Python bin to PATH
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
        // failure {   <-- COMMENTED OUT to avoid SMTP configuration errors
        //     emailext(
        //         subject: "User Provisioning FAILED - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
        //         body: "Check console: ${env.BUILD_URL}console",
        //         to: 'your.name@gmail.com'
        //     )
        // }
    }
}

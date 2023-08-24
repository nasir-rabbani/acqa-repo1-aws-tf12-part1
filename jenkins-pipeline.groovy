pipeline {
    //The agent section specifies where the entire Pipeline, or a specific stage, 
    //will execute in the Jenkins environment depending on where the agent section is placed.
    agent { label 'acqa-jenkins1-node1-ub20' }
    
    options {
        ansiColor('xterm')
    }
    
//    parameters {
//        string(name: 'AWS_ACCESS_KEY_ID')
//        string(name: 'AWS_SECRET_ACCESS_KEY')
//    }

    stages {
        stage('Download Accurics CLI'){
            steps{
                sh "wget https://downloads.accurics.com/cli/latest/accurics_linux -O accurics; chmod +x accurics"
            }
        }
        
        stage('Export AWS credentials on the agent'){
            steps{
                sh "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
                sh "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
            }
        }

        stage('Perform IaC scan using Accurics CLI'){
            steps {
                sh './accurics init'
                sh './accurics plan  -mode=pipeline -appurl=https://app.accurics.com -token=cd96d8ad-f646-4852-8a7e-b105fe9ecc8d'
            }
        }
    }
}
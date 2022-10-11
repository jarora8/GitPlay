node {
  stage ('Checkout') 
  {
    // Get the code from the Git repository
    checkout scm
  } 
  
  stage('Git to ISPW Synchronization')
  { 
	gitToIspwIntegration app: 'PLAY', 
	branchMapping:  '''*Bug* => DEV1, per-branch''',
	connectionId: 'cw09-47623', 
	credentialsId: 'pinjxa0-tso', 
	gitCredentialsId: 'jaroragit', 
	gitRepoUrl: 'https://github.com/jarora8/GitPlay.git', 
	runtimeConfig: 'TPZP', 
    stream: 'PLAY',
    ispwConfigPath: 'ispwconfig.yml' 
  }  
	
  stage('Build ISPW assignment')
  {
	ispwOperation connectionId: 'cw09-47623',
	consoleLogResponseBody: true,
	credentialsId: 'CES_Token',
	ispwAction: 'BuildAssignment'
	ispwRequestBody: '''assignmentId=PLAY006906
		            level=DEV1
			    buildAutomatically = true'''
  }
  
}

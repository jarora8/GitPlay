node {
  stage ('Checkout') 
  {
    // Get the code from the Git repository
    checkout scm
  } 

  stage('Task Add')
  {
     ispwOperation connectionId: 'tptp', 
     consoleLogResponseBody: true,
     credentialsId: 'cert', 
     ispwAction: 'AddTask', 
     ispwRequestBody: '''runtimeConfiguration=TPTP
                         assignmentId=ISP1000401
                         taskName=TPROG01
                         stream=PLAY
                         application=PLAY
                         subAppl=PLAY
                         type=COB
                         path=DEV1
                         owner=Foobar
                         checkoutFromLevel=PRD'''
  }	
/*	
  stage('Git to ISPW Synchronization')
  { 
	gitToIspwIntegration app: 'TXX2', 
	branchMapping:  '''*Play* => DEV1, per-branch''',
	connectionId: 'cw09-47623', 
	credentialsId: 'pinjxa0-tso', 
	gitCredentialsId: 'jaroragit', 
	gitRepoUrl: 'https://github.com/jarora8/GitPlay.git', 
	runtimeConfig: 'ISP8', 
    stream: 'CWEZ',
    ispwConfigPath: 'ispwconfig.yml' 
  } */ 
  
}

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
}

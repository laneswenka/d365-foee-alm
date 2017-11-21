# d365-foee-alm
Microsoft Dynamics365 Finance &amp; Operations ALM Tools

## Overview

This repo contains Powershell scripts and documentation to setup automated releases of Microsoft Dynamics365 Finance & Operations Enterprise Edition ERP system using Release capabilities in VSTS.

  

This provides open examples on how we can leverage VSTS Release Management capabilities in our Implementations or DevOps practices.  Continuous Delivery is a critical component to providing a stream of value to your end users be they your customers, business partners, or back office employees.

## How to setup automated deployments

**Prerequisite Setup**  
To use this repo effectively, download the DeploymentScripts folder.  Update the DefaultTopologyData.xml with output from your target environment.  This can be retrieved manually using AxUpdateInstaller.exe or you can look for recent LCS-powered deployments in your Service drive:\DeployablePackages directory.  

Also be advised that this has only been tested on Demo and Standard Acceptance Test topologies.  This is not possible for use with your Production instance, and to mark a package as a Release Candidate you must deploy it once from LCS.

These scripts do not replace LCS, it simply helps your development team provide a continuous stream of value to stakeholders until such time as you have a Release Candidate.  From there, you must use LCS to push to Production.

**Step One**  
Create a new Agent Pool, Queue, and download the Agent to your target system.  In this example, we are downloading the VSTS Agent on our Dynamics TEST environment.
![Step_One](/step_one.jpg)

**Step Two**  
Go to your VSTS project where your automated builds are running (note - the builds are setup automatically when you deploy a Build environment topology in LCS).  

Visit Build and Release -> Releases -> Create release definition
![Step_One](/step_two.jpg)

**Step Three**  
Attach the release definition to your build artifact.  Depending on your branching design, this could be Trunk or some other branch you have created.  Next, optionally create a Release from every new artifact.

Finally, add an environment that represennts your TEST environment. You may optionally set the deployment to be automatic when a Release is created or at some scheduled time.
![Step_One](/step_three.jpg)

**Step Four**  
Visit the Tasks section and update the Agent phase.  Ensure that you set the Agent Queue to be the queue you created in the first step.  Also, ensure that the Agent.Name property is that of your TEST enviornment as you don't want this to accidentally run on your Build server.
![Step_One](/step_four.jpg)

**Step Five**  
Add a Delete Files task.  Feel free to name it as you wish, and select the Source folder you wish to purge.  In this example, I'm using D:\Deployment directory as the D:\ drive is often SSD storage.
![Step_One](/step_five.jpg)

**Step Six**  
Add a Download Build Artifacts task.  I've set my example to download the Packages artifact from our Trunk build.  
![Step_One](/step_six.jpg)

**Step Seven**  
Add a Download Build Artifacts task.  I've set my exammple to download the DeploymentScripts task.  (Note - I've added a custom step to upload these scripts from source control to the DeploymentTasks artifact in the Trunk Build definition)
![Step_One](/step_seven.jpg)

**Step Eight**  
Add a Powershell task.  See the Arguments where we are specifying the Deployment directory, the Scripts directory, and the BuildNumber from our Trunk Build artifact.  
![Step_One](/step_eight.jpg)





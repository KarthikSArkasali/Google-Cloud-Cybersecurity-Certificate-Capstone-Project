 # ~ Respond and Recover from a data breach

  **Activity overview**

    This lab is part of the capstone project. In this lab, you’ll apply your knowledge of cloud cybersecurity to identify and remediate vulnerabilities.

    You’ll be given a scenario, and a set of tasks to complete in Google Cloud Security Command Center. These tasks will require you to use your skills to work to analyze and remediate active vulnerabilities relating 
    to a security incident, answer questions about the vulnerabilities, and complete challenges that will assess your cloud cybersecurity skills.

    There are also a number of challenges in the lab. A challenge is a task where you will be asked to complete the task on your own without instructions.

    By successfully completing this lab, you will demonstrate your ability to identify, prioritize, and remediate security vulnerabilities and misconfigurations within the cloud environment. These are essential 
    skills to enhance the security posture of Google Cloud environments, reducing the risk of data breaches, unauthorized access, and other security incidents.

  **Scenario**

    For the last year, you've been working as a junior cloud security analyst at Cymbal Retail. Cymbal Retail is a market powerhouse currently operating 170 physical stores and an online platform across 28 countries. 
    They reported $15 billion in revenue in 2022, and currently employ 80,400 employees across the world.

    Cymbal Retail boasts a vast customer base with a multitude of transactions happening daily on their online platform. The organization is committed to the safety and security of its customers, employees, and its 
    assets, ensuring that its operations meet internal and external regulatory compliance expectations in all the countries it operates in.

    Recently, the company has experienced a massive data breach. As a junior member of the security team, you’ll help support the security team through the lifecycle of this security incident. You'll begin by 
    identifying the vulnerabilities related to the breach, isolate and contain the breach to prevent further unauthorized access, recover the compromised systems, remediate any outstanding compliance related issues, 
    and verify compliance with frameworks.

    Here’s how you'll do this task: **First** you’ll examine the vulnerabilities and findings in Google Cloud Security Command Center. **Next**, you’ll shut the old VM down, and create a new VM from a snapshot. 
    **Then**, you’ll evoke public access to the storage bucket and switch to uniform bucket-level access control. **Next**, you’ll limit the firewall ports access and fix the firewall rules. **Finally**, you’ll run a 
    report to verify the remediation of the vulnerabilities.

  **Setup**
     
    Before you click Start Lab
      
    Read these instructions. Labs are timed and you cannot pause them. The timer, which starts when you click Start Lab, shows how long Google Cloud resources will be made available to you.

    This practical lab lets you do the activities yourself in a real cloud environment, not in a simulation or demo environment. It does so by giving you new, temporary credentials that you use to sign in and access 
    Google Cloud for the duration of the lab.

    To complete this lab, you need:

    Access to a standard internet browser (Chrome browser recommended).

    **Note** : Use an Incognito or private browser window to run this lab. This prevents any conflicts between your personal account and the Student account, which may cause extra charges incurred to 
    your personal account.

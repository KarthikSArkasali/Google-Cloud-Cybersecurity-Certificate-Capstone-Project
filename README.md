# Respond and Recover from a data breach

**Activity overview**

  This lab is part of the capstone project. In this lab, you’ll apply your knowledge of cloud cybersecurity to identify and remediate vulnerabilities.

  You’ll be given a scenario, and a set of tasks to complete in Google Cloud Security Command Center. These tasks will require you to use your skills to work to analyze and 
  remediate active vulnerabilities relating to a security incident, answer questions about the vulnerabilities, and complete challenges that will assess your cloud 
  cybersecurity skills.

  There are also a number of challenges in the lab. A challenge is a task where you will be asked to complete the task on your own without instructions.

  By successfully completing this lab, you will demonstrate your ability to identify, prioritize, and remediate security vulnerabilities and misconfigurations within the 
  cloud environment. These are essential skills to enhance the security posture of Google Cloud environments, reducing the risk of data breaches, unauthorized access, and 
  other security incidents.

 **Scenario**

  For the last year, you've been working as a junior cloud security analyst at Cymbal Retail. Cymbal Retail is a market powerhouse currently operating 170 physical stores 
  and an online platform across 28 countries. They reported $15 billion in revenue in 2022, and currently employ 80,400 employees across the world.

  Cymbal Retail boasts a vast customer base with a multitude of transactions happening daily on their online platform. The organization is committed to the safety and 
  security of its customers, employees, and its assets, ensuring that its operations meet internal and external regulatory compliance expectations in all the countries it 
  operates in.

  Recently, the company has experienced a massive data breach. As a junior member of the security team, you’ll help support the security team through the lifecycle of this 
  security incident. You'll begin by identifying the vulnerabilities related to the breach, isolate and contain the breach to prevent further unauthorized access, recover 
  the compromised systems, remediate any outstanding compliance related issues, and verify compliance with frameworks.

  Here’s how you'll do this task: **First** you’ll examine the vulnerabilities and findings in Google Cloud Security Command Center. **Next**, you’ll shut the old VM down, 
  and create a new VM from a snapshot. **Then**, you’ll evoke public access to the storage bucket and switch to uniform bucket-level access control. **Next**, you’ll limit 
  the firewall ports access and fix the firewall rules. **Finally**, you’ll run a report to verify the remediation of the vulnerabilities.

 **Setup**
     
 **Before you click Start Lab**
      
  Read these instructions. Labs are timed and you cannot pause them. The timer, which starts when you click **Start Lab**, shows how long Google Cloud resources will be made 
  available to you.

  This practical lab lets you do the activities yourself in a real cloud environment, not in a simulation or demo environment. It does so by giving you new, temporary 
  credentials that you use to sign in and access Google Cloud for the duration of the lab.

  To complete this lab, you need:

 * Access to a standard internet browser (Chrome browser recommended).

        Note: Use an Incognito or private browser window to run this lab. This prevents any conflicts between your personal account and the Student account, which may cause 
        extra charges incurred to your personal account.

 * Time to complete the lab---remember, once you start, you cannot pause a lab.

        Note: If you already have your own personal Google Cloud account or project, do not use it for this lab to avoid extra charges to your account.

 **How to start your lab and sign in to the Google Cloud console**

 **1.** Click the **Start Lab** button. On the left is the **Lab Details** panel with the following:

   * Time remaining
   * The **Open Google Cloud console** button
   * The temporary credentials that you must use for this lab
   * Other information, if needed, to step through this lab
     
         Note: If you need to pay for the lab, a pop-up opens for you to select your payment method.

 **2.** Click Open **Google Cloud console** (or right-click and select **Open Link in Incognito Window**) if you are running the Chrome browser. The **Sign in** 
          page opens in a new browser tab.

        Tip: You can arrange the tabs in separate, side-by-side windows to easily switch between them.

        Note: If the Choose an account dialog displays, click Use Another Account. 
        
 **3.** If necessary, copy the **Google Cloud username** below and paste it into the **Sign in** dialog. Click **Next**.

       "Google Cloud username"

 You can also find the **Google Cloud username** in the **Lab Details** panel.
   
 **4.** Copy the **Google Cloud password** below and paste it into the **Welcome** dialog. Click **Next**.

       "Google Cloud password"

 You can also find the **Google Cloud username** in the **Lab Details** panel.

       Important: You must use the credentials the lab provides you. Do not use your Google Cloud account credentials.

       Note: Using your own Google Cloud account for this lab may incur extra charges.

 **5.** Click through the subsequent pages:
  
   * Accept the terms and conditions
   * Do not add recovery options or two-factor authentication (because this is a temporary account)
   * Do not sign up for free trials
     
 After a few moments, the Console opens in this tab.

       Note: You can view the menu with a list of Google Cloud Products and Services by clicking the Navigation menu at the top-left.
   ![Image](https://github.com/user-attachments/assets/dfaaf2e9-f92b-4bf2-8c38-09396e887d11)

**Task 1. Analyze the data breach and gather information**

   One morning, the security team detects unusual activity within their systems. Further investigation into this activity quickly reveals that the company has suffered a 
   massive security breach across its applications, networks, systems, and data repositories. Attackers gained unauthorized access to sensitive customer information, 
   including credit card data, and personal details. This incident requires immediate attention and thorough investigation. The first step towards understanding the scope 
   and impact of this breach is to gather information and analyze the available data.

   In this task, you'll examine the vulnerabilities and findings in Google Cloud Security Command Center to determine how the attackers gained access to the data, and which 
   remediation steps to take.

     Important: The vulnerabilities listed in this section rely on specific security checks being run beforehand. If some checks haven't run yet, the related 
     vulnerabilities might not appear in the Security Command Center when you complete the steps in this section. Don't worry though! You can still use the information 
     provided in this task to analyze the available findings and proceed with the remediation steps in the tasks that follow.

**First**, navigate to the Security Command Center to view an overview of the active vulnerabilities.

   **1.** In the Google Cloud console, in the **Navigation menu** (navigation_menu), click **Security > Overview**. The Security Command Center Overview page opens.
   
   **2.** Scroll down to **Active vulnerabilities**. This provides an overview of current security vulnerabilities or issues that need attention within the Google Cloud 
          environment.
          
   **3.** Select the **Findings By Resource Type** tab. The security findings or vulnerabilities based on the type of cloud resource affected (e.g., instances, buckets, 
          databases) are organized. By reviewing active vulnerabilities and findings by resource type, you can prioritize and address security issues effectively.

   ![Second image](https://github.com/user-attachments/assets/5298f37e-72d3-4e79-90e5-cb90a86574e5)

 You'll note that there are both high and medium severity findings relating to the **Cloud Storage bucket**, the **Compute Instance virtual machine**, and the **firewall**.

     Which three resource types are listed with high severity findings?
        Bucket, Subnetwork, and ServiceAccountKey
        Network, Firewall, and Bucket
        Bucket, compute.Instance, and Firewall (Correct Answer)
        Network, Subnetwork, and compute.Instance

 **Next**, navigate to the PCI DSS report.

   **4.** In the **Security Command Center menu**, click **Compliance**. The Compliance page opens.
   
   **5.** In the **Google Cloud compliance standards** section, click **View details** in the **PCI DSS 3.2.1** tile. The PCI DSS 3.2.1 report opens.
   
   **6.** Click on the **Findings** column to sort the findings and display the active findings at the top of the list.

     Note: Make sure to follow these steps to assess the PCI report, and do not refresh the page, as the required filters will be removed, and the correct information won't 
     be displayed.

   The Payment Card Industry Data Security Standard (PCI DSS) is a set of security requirements that organizations must follow to protect sensitive cardholder data. As a 
   retail company that accepts and processes credit card payments, Cymbal Retail must also ensure compliance with the PCI DSS requirements, to protect cardholder data.

   As you examine the PCI DSS 3.2.1 report, notice that it lists the rules that are non-compliant, which relate to the data breach:

* **Firewall rule logging should be enabled so you can audit network access:** This medium severity finding indicates that firewall rule logging is disabled, meaning that 
    there is no record of which firewall rules are being applied and what traffic is being allowed or denied. This is a security risk as it makes it difficult to track and 
    investigate suspicious activity.
* **Firewall rules should not allow connections from all IP addresses on TCP or UDP port 3389:** This high severity finding indicates that the firewall is configured to 
    allow Remote Desktop Protocol (RDP) traffic for all instances in the network from the whole internet. This is a security risk as it allows anyone on the internet to 
    connect to the RDP port on any instance in the network.
* **Firewall rules should not allow connections from all IP addresses on TCP or SCTP port 22:** This high severity finding indicates that the firewall is configured to allow 
    Secure Shell (SSH) traffic to all instances in the network from the whole internet. SSH is a protocol that allows secure remote access to a computer. If an attacker can 
    gain access to a machine through SSH, they could potentially steal data, install malware, or disrupt operations.
* **VMs should not be assigned public IP addresses:** This high severity finding indicates that a particular IP address is actively exposed to the public internet and is 
    potentially accessible to unauthorized individuals. This finding is considered a potential security risk because it could allow attackers to scan for vulnerabilities or 
    launch attacks on the associated resource.
* **Cloud Storage buckets should not be anonymously or publicly accessible:** This high severity finding indicates that there is an Access Control List (ACL) entry for the 
    storage bucket that is publicly accessible which means that anyone on the internet can read files stored in the bucket. This is a high-risk security vulnerability that 
    needs to be prioritized for remediation.
* **Instances should not be configured to use the default service account with full access to all Cloud APIs:** This medium severity finding indicates that a particular 
    identity or service account has been granted full access to all Google Cloud APIs. This finding is considered a significant security risk because it grants the identity 
    or service account the ability to perform any action within the Google Cloud environment, including accessing sensitive data, modifying configurations, and deleting 
    resources.
  
Since you're focusing on identifying and remediating the issues related to the security incident, please disregard the following findings as they do not relate to the remediation tasks you’re completing:

* **VPC Flow logs should be Enabled for every subnet VPC Network:** There are a number of low severity findings for Flow Logs disabled. This indicates that Flow Logs are not     nabled for a number of subnetworks in the Google Cloud project used for this lab. This is a potential security risk because Flow Logs provide valuable insights into 
    network traffic patterns, which can help identify suspicious activity and investigate security incidents.

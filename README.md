# Respond and Recover from a data breach

   **Activity overview**

     This lab is part of the capstone project. In this lab, you’ll apply your knowledge of cloud cybersecurity to identify and remediate vulnerabilities.

     You’ll be given a scenario, and a set of tasks to complete in Google Cloud Security Command Center. These tasks will require you to use your skills to work to analyze 
     and remediate active vulnerabilities relating to a security incident, answer questions about the vulnerabilities, and complete challenges that will assess your cloud 
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

     Recently, the company has experienced a massive data breach. As a junior member of the security team, you’ll help support the security team through the lifecycle of 
     this security incident. You'll begin by identifying the vulnerabilities related to the breach, isolate and contain the breach to prevent further unauthorized access, 
     recover the compromised systems, remediate any outstanding compliance related issues, and verify compliance with frameworks.

     Here’s how you'll do this task: First you’ll examine the vulnerabilities and findings in Google Cloud Security Command Center. Next, you’ll shut the old VM 
     down, and create a new VM from a snapshot. Then, you’ll evoke public access to the storage bucket and switch to uniform bucket-level access control. Next, 
     you’ll limit the firewall ports access and fix the firewall rules. Finally, you’ll run a report to verify the remediation of the vulnerabilities.

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

# Task 1. Analyze the data breach and gather information

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
   ![1 Compliance](https://github.com/user-attachments/assets/7f3b7745-0285-4f29-b6dd-10648b2f9e89)
   **6.** Click on the **Findings** column to sort the findings and display the active findings at the top of the list.
    ![2  Findings](https://github.com/user-attachments/assets/53363d45-315e-4231-8db1-f3bb43f75bb2)
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

      Note: Enabling logging for cloud resources is important in maintaining observability. However, you will not remediate this finding in this lab activity as the 
      subnetworks are part of this lab environment. As a result, this finding will still be visible on the report after you have completed the remediation tasks.

* **Basic roles (Owner, Writer, Reader) are too permissive and should not be used:** This medium severity finding indicates that primitive roles are being used within the 
    Google Cloud environment. This is a potential security risk because primitive roles grant broad access to a wide range of resources.
* **An egress deny rule should be set:** This low severity finding indicates that no egress deny rule is defined for the monitored firewall. This finding raises potential 
    security concerns because it suggests that outbound traffic is not restricted, potentially exposing sensitive data or allowing unauthorized communication.

The following table pairs the rules listed in the report with their corresponding findings category. This will assist you when examining the findings according to resource type later:

| Findings category | Rule  |
|:---               |   :---|
|Firewall rule logging disabled| Firewall rule logging should be enabled so you can audit network access|
|Open RDP port	|Firewall rules should not allow connections from all IP addresses on TCP or UDP port 3389|
|Open SSH port	|Firewall rules should not allow connections from all IP addresses on TCP or SCTP port 22|
|ublic IP address	|VMs should not be assigned public IP addresses |
|Public bucket ACL |	Cloud Storage buckets should not be anonymously or publicly accessible|
|Full API access |	Instances should not be configured to use the default service account with full access to all Cloud APIs|
|Flow logs disabled |	VPC Flow logs should be Enabled for every subnet VPC Network|
|Primitive roles used |	Basic roles (Owner, Writer, Reader) are too permissive and should not be used|
|Egress deny rule not| set	An egress deny rule should be set|

Overall, these findings indicate a critical lack of security controls and non-compliance with essential PCI DSS requirements; they also point to the vulnerabilities associated with the data breach.

**Next**, navigate to the Security Command Center, and filter the findings for further examination and analysis of the vulnerabilities in the Google Cloud environment.

  **7.** In the Google Cloud console, in the **Navigation menu (navigation_menu)**, click **Security > Findings**. The **Findings** page opens.
  
  **8.** In the **Quick filters** panel, in the **Resource Type** section, select the checkbox for the **Google Cloud storage bucket** resource type.
  ![3 Bucket Misconfiguration](https://github.com/user-attachments/assets/0989d8c9-f715-4d50-8f3e-12d5eded0e02)
The following active findings pertaining to the storage bucket should be listed:

* **Public bucket ACL:** This finding is listed in the PCI DSS report, and indicates that anyone with access to the internet can read the data stored in the bucket.
* **Bucket policy only disabled:** This indicates that there is no explicit bucket policy in place to control who can access the data in the bucket.
* **Bucket logging disabled:** This indicates that there is no logging enabled for the bucket, so it will be difficult to track who is accessing the data.

These findings indicate that the bucket is configured with a combination of security settings that could expose the data to unauthorized access. You'll need to remediate these findings by removing the public access control list, disabling public bucket access, and enabling the uniform bucket level access policy.

      Note: Enabling logging for cloud resources is important in maintaining observability. However, you will not remediate the Bucket logging disabled finding in this lab 
      activity as this would require working with multiple projects. As a result, this finding will still be visible after you have completed the remediation tasks.
      
   **9.** In the **Quick filters panel**, in the **Resource Type** section, uncheck **Google Cloud storage bucket**, and select the checkbox for the **Google compute 
     instance** resource type.
     ![4  Compute Instance Mis](https://github.com/user-attachments/assets/7d668415-f410-4f0b-8b99-a091791423ed)
The following active findings that pertain to the virtual machine named **cc-app-01** should be listed:

* **Malware bad domain:** This finding indicates that a domain known to be associated with malware was accessed from the google.compute.instance named cc-app-01. Although 
    this finding is considered to be of low severity, it indicates that malicious activity has occurred on the virtual machine instance and that it has been compromised.
* **Compute secure boot disabled:** This medium severity finding indicates that secure boot is disabled for the virtual machine. This is a security risk as it allows the 
    virtual machine to boot with unauthorized code, which could be used to compromise the system.
* **Default service account used:** This medium severity finding indicates that the virtual machine is using the default service account. This is a security risk as the 
    default service account has a high level of access and could be compromised if an attacker gains access to the project.
* **Public IP address:** This high severity finding is listed in the PCI DSS report and indicates that the virtual machine has a public IP address. This is a security risk 
    as it allows anyone on the internet to connect to the virtual machine directly.
* **Full API access:** This medium severity finding is listed in the PCI DSS report, and indicates that the virtual machine has been granted full access to all Google Cloud 
    APIs.
  
  These findings indicate the virtual machine was configured in a way that left it very vulnerable to the attack. To remediate these findings you'll shut the original VM
  (cc-app-01) down, and create a VM (cc-app-02) using a clean snapshot of the disk. The new VM will have the following settings in place:

 * No compute service account
 * Firewall rule tag for a new rule for controlled SSH access
 * Secure boot enabled
 * Public IP address set to None

**10.** In the **Time range** field, expand the drop-down, and select **Last 30 days**. This will ensure the list includes findings for the last 30 days.

**11.** In the **Quick filters** panel, in the **Resource Type** section, uncheck **Google compute instance**, and select the checkbox for the **Google compute firewall** 
   resource type.
   ![5  Compute Firewall](https://github.com/user-attachments/assets/fb800b1a-8151-466a-8190-257d1f4fd3c9)
The following active findings should be listed that pertain to the firewall:

* **Open SSH port:** This high severity finding indicates that the firewall is configured to allow Secure Shell (SSH) traffic to all instances in the network from the whole 
    internet.
* **Open RDP port:** This high severity finding indicates that the firewall is configured to allow Remote Desktop Protocol (RDP) traffic to all instances in the network from 
    the whole internet.
* **Firewall rule logging disabled:** This medium severity finding indicates that firewall rule logging is disabled. This means that there is no record of which firewall 
    rules are being applied and what traffic is being allowed or denied.

These findings are all listed in the PCI DSS report and highlight a significant security gap in the network's configuration. The lack of restricted access to RDP and SSH ports, coupled with disabled firewall rule logging, makes the network highly vulnerable to unauthorized access attempts and potential data breaches. You'll need to remediate these by removing the existing firewall overly broad rules, and replacing them with a firewall rule that allows SSH access only from the addresses that are used by Google Cloud's IAP SSH service.

Now that you have analyzed the security vulnerabilities, it’s time to work on remediating the report findings.

Which of the following findings are listed as high severity findings?
 * Public IP address, Default service account used, Full API access, and Firewall rule logging disabled
 * Bucket policy only disabled, Bucket logging disabled, Malware bad domain, and Compute secure boot disabled
 * Firewall rule logging disabled, Compute secure boot disabled, Public IP address, and Bucket logging disabled
 * Public bucket ACL, Public IP address, Open SSH port, and Open RDP port (Correct Answer)

# Task 2. Fix the Compute Engine vulnerabilities

In this task, you'll shut down the vulnerable VM cc-app-01, and create a new VM from a snapshot taken before the malware infection. VM snapshots are effective in restoring the system to a clean state, and ensures that the new VM will not be infected with the same malware that compromised the original VM.

  1. In the Google Cloud console, click the **Navigation menu (navigation_menu)**.
   
  2. Select **Compute Engine > VM instances**. The VM instances page opens.
  ![1  VM Instance](https://github.com/user-attachments/assets/d881b613-1b9e-4aad-9a76-ec62ad4db294)
The current VM **cc-app-01** should be listed under VM instances. This is the vulnerable VM that has been compromised and must be shut down.

  3. Select the checkbox for the **cc-app-01** VM.
     
  4.  Click **Stop**.
     
  5.  A pop-up will appear asking you to confirm that the VM should be stopped, click **Stop**.

Click **Check my progress** to verify that you have completed this task correctly.

    Shut down the vulnerable VM
![2  VM Stopped](https://github.com/user-attachments/assets/1b62d681-b559-465e-9169-61b6c236863a)

**Next**, create a new VM from a snapshot. This snapshot has already been created as part of Cymbal Retail's long term data backup plan.

  6. In the action bar, click **+ Create instance**.
     
  7. In the **Name** field, type **cc-app-02**.
     
  8. In the **Machine type** section, expand the drop-down, select **Shared-core**, and then select **e2-medium**.
     
  9. In the **Boot disk** section, click **Change**. The Boot disk dialog opens.
      
  10. Select the **Snapshots** tab.
      
  11. Expand the **Snapshot** drop-down menu, and select **cc-app01-snapshot**.
      
  12. Click **Select**.
    
  13. In the **Identity and API access section**, expand the **Service accounts** drop-down menu, and select **Qwiklabs User Service Account**.
    
  14. Expand the **Advanced options** section.
    
  15. Expand the **Networking** section.
    
  16. In the **Network tags** field, type cc. You'll use this tag to apply firewall rules to this specific VM.
   
  17. In the **Network interfaces** section, expand the **default** network.
    
  18. Expand the **External IPv4 address** drop-down menu, and select **None**.
    
  19. Click **Create**.

The new VM **cc-app-02** should now be created from the **cc-app01-snapshot**. (It may take a few minutes for the new VM to be created.)

**Now**, turn Secure Boot on for the new VM **cc-app-02** to address the **Secure Boot disabled** finding.

  20. Select the checkbox for the **cc-app-02 VM**.
      
  21. Click **Stop**.
      
  22. A pop-up will appear asking you to confirm that the VM should be stopped, click **Stop**.

Wait for the **cc-app-02** VM to be stopped before you continue.

  23. In the **VM instances** section, click the **cc-app-02** link. The cc-app-02 page opens.
      
  24. In the **cc-app-02** toolbar, click **Edit**. The Edit cc-app-02 instance page opens.
      
  25. Scroll down to the **Security and access** section, and under **Shielded VM**, select the checkbox for the **Turn on Secure Boot** option. This will address the 
      **Compute secure boot disabled** finding.
  
  26. Click **Save**.
    ![4  Secure Boot for VM 2](https://github.com/user-attachments/assets/f2ea916e-0d0c-460c-b923-f70312c8157e)   
  27. In the **Compute Engine** menu, select **VM instances**.
      
  28. Select the checkbox for the **cc-app-02** VM.
      
  29. Click **Start/Resume**.
      
  30. A pop-up will appear asking you to confirm that the VM should be started, click **Start**.
      
  31. The **cc-app-02** VM instance will restart and the **Secure Boot disabled** finding will be remediated.

Click **Check my progress** to verify that you have completed this task correctly.

   Create a new VM from existing snapshot
![3  VM 2 Created](https://github.com/user-attachments/assets/dfc6bf8f-4bce-4173-acf2-aa2fb3c4e5f5)
**Challenge: Delete the compromised VM**

Delete the compromised VM **cc-app-01**.

Click **Check my progress** to verify that you have completed this task correctly.

    Delete the compromised VM
![5  Delete VM 1](https://github.com/user-attachments/assets/db7ebf2e-7d96-402d-9d5c-036879bf929e)
By following these steps, you have effectively created a new VM from the snapshot, ensuring it is free from malware and misconfigurations. You also deleted the compromised VM, eliminating the source of the security breach.

# Task 3. Fix Cloud Storage bucket permissions

In this task, you'll revoke public access to the storage bucket and switch to uniform bucket-level access control, significantly reducing the risk of data breaches. By removing all user permissions from the storage bucket, you can prevent unauthorized access to the data stored within.

  1. In the **Navigation menu (navigation_menu)**, select **Cloud Storage > Buckets**. The Buckets page opens.
  ![1  Navigate to Bucket](https://github.com/user-attachments/assets/72d5a908-eadd-4a60-b639-335090a84526)
  2. Click the **project_id_bucket** storage bucket link. The Bucket details page opens.
  ![2  Project Public](https://github.com/user-attachments/assets/1ca64625-133e-497e-a7e5-ce40f484eba6)
You'll note there is a **myfile.csv** file in the publicly accessible bucket. This is the file that contains the sensitive information that was dumped by the malicious actor. Perform the following steps to address the **Public bucket ACL** finding.

  3. Click the **Permissions** tab.
  ![3  Permission Tab](https://github.com/user-attachments/assets/401d87ef-f57f-483d-aac9-f6fbfda70ad7)
  4. In the **Public access** tile, click **Prevent public access**.
  ![4  Prevent Public Access](https://github.com/user-attachments/assets/10b56652-7127-4da6-b061-c8a16fe1fb8c)
  5. Click **Confirm**.

**Challenge: Modify storage bucket access**

Switch the access control to uniform and remove permissions for the **allUsers** principals from the storage bucket to enforce a single set of permissions for the bucket and its objects. You'll also need to ensure that users who rely on basic project roles to access the bucket won't lose their access.

Click **Check my progress** to verify that you have completed this task correctly.

    Modify storage bucket access.
![5  Edit Access Control](https://github.com/user-attachments/assets/7f78ef46-520e-4800-bfba-0d150ea7cb3d)
![6  Remove Permission](https://github.com/user-attachments/assets/f9d1c0e6-23b5-4f5e-80f0-c8ac56751e38)
By following these steps, you have effectively prevented public access to the bucket, switched to uniform bucket-level access control, and removed all user permissions, addressing the **Public bucket ACL, Bucket policy only disabled,** and **Bucket logging disabled findings**.

# Task 4. Limit firewall ports access

In this task, you'll restrict access to RDP and SSH ports to only authorized source networks to minimize the attack surface and reduce the risk of unauthorized remote access.

Exercise extreme caution before modifying overly permissive firewall rules. The rules may be allowing legitimate traffic, and improperly restricting it could disrupt critical operations. In this lab, ensure the Compute Engine virtual machine instances tagged with target tag "cc" remain accessible via SSH connections from the Google Cloud Identity-Aware Proxy address range (35.235.240.0/20). To maintain uninterrupted management access, create a new, limited-access firewall rule for SSH traffic before removing the existing rule allowing SSH connections from any address.

**Challenge: Restrict SSH access**

Create a new firewall rule. This rule must restrict SSH access to only authorized IP addresses from the source network **35.235.240.0/20** to compute instances with the target tag cc.

Click **Check my progress** to verify that you have completed this task correctly.

    Restrict SSH access 
![4 3 SSH Created](https://github.com/user-attachments/assets/11187a02-439b-48da-905f-64bc21dbe249)

# Task 5. Fix the firewall configuration

In this task, you'll delete three specific VPC firewall rules that are responsible for allowing unrestricted access to certain network protocols, namely ICMP, RDP, and SSH, from any source within the VPC network. Then, you'll enable logging on the remaining firewall rules.
![4 2 Firwall Rule list](https://github.com/user-attachments/assets/6c86868c-09c6-43a1-bb91-f229bc273448)
**Challenge: Customize firewall rules**

Delete the **default-allow-icmp, default-allow-rdp,** and **default-allow-ssh** firewall rules. These rules are overly broad and by deleting them, you'll allow for a more secure and controlled network environment.

By deleting these rules, you have restricted access to these protocols, limiting the potential for unauthorized access attempts and reducing the attack surface of your network.

    Customize firewall rules
![4 4 Delete SSH RDP](https://github.com/user-attachments/assets/09e99c72-7dcb-43da-929c-f9eecb1fbf4e)
**Challenge: Enable logging**

Enable logging for the remaining firewall rules **limit-ports** (the rule you created in a previous task) and **default-allow-internal**.

Enabling logging allows you to track and analyze the traffic that is allowed by this rule, which is likely to be internal traffic between instances within your VPC.

Click **Check my progress** to verify that you have completed this task correctly.

    Enable logging
![4 5 Logging Allow internal](https://github.com/user-attachments/assets/fa3aa043-f8fb-4d43-ab06-ec1535837de5)
![4 6 Logging Deny SSH](https://github.com/user-attachments/assets/b0d97139-8133-4065-98d3-1ae6e5954e85)
By customizing firewall rules and enabling logging, you've addressed the **Open SSH port, Open RDP port,** and **Firewall rule logging disabled** findings. The new firewall rule better protects the network and improves network visibility.

# Task 6. Verify compliance

After diligently addressing the vulnerabilities identified in the PCI DSS 3.2.1 report, it's crucial to verify the effectiveness of your remediation efforts. In this task, you'll run the report again to ensure that the previously identified vulnerabilities have been successfully mitigated and no longer pose a security risk to the environment.

  1. In the **Security Command Center** menu, click **Compliance**. The Compliance page opens.
     
  2. In the **Google Cloud compliance standards** section, click **View details** in the **PCI DSS 3.2.1** tile. The PCI DSS 3.2.1 report opens.
     
  3. Click on the **Findings** column to sort the findings and display the active findings at the top of the list.

All major vulnerabilities are now resolved.

    Note: While you addressed the high and medium severity vulnerabilities, the flow logs remain disabled for a number of subnetworks. This finding will still be 
    visible on the report after you have completed the remediation tasks, as this relates to this lab environment.

**Conclusion**

    Great work!

    You have helped the security team at Cymbal Bank to mitigate the impact of the data breach, address the identified vulnerabilities, and significantly enhanced the 
    security posture of Cymbal Bank’s Google Cloud environment.

    First, you examined and analyzed the vulnerabilities and findings in Google Cloud Security Command Centre.

    Next, you shut the old VM down and created a new VM from a snapshot taken before the malware infection.

    Then, you fixed the cloud storage permissions by revoking public access to the storage bucket and switching to uniform bucket-level access control. You also removed all 
    user permissions from the storage bucket.

    Next, you fixed the firewall rules by deleting the default-allow-icmp, default-allow-rdp, and default-allow-ssh firewall rules, and enabling logging for the remaining 
    firewall rules.

    Finally, you run a compliance report to confirm that the vulnerability issues have been remediated.

    Remember, as a security analyst it is crucial to maintain regular security audits and implement ongoing monitoring practices for continued protection against evolving 
    threats and vulnerabilities.

**End your lab**

    Before you end the lab, make sure you’re satisfied that you’ve completed all the tasks. When you're ready, click End Lab and then click Submit.

    Ending the lab will remove your access to the lab environment, and you won’t be able to access the work you've completed in it again.

    Copyright 2024 Google LLC All rights reserved. Google and the Google logo are trademarks of Google LLC. All other company and product names may be trademarks of the 
    respective companies with which they are associated.

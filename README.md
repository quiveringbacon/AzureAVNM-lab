# Azure AVNM lab
Hi all, this lab sets up a hub vnet and a couple of spoke vnets but manages security, connectivity, and routing with Azure virtual network manager in a hub and spoke topology. That means no traditional UDR's or NSG's or peerings here, it will also setup a verifier to show the reachability of the spoke1 vm. Internet traffic goes through the Azure firewall, except traffic to your public ip address for RDP access. RDP access is allowed to the spoke VM's and all 3 vnets are in 1 network group. More info on AVNM here: https://learn.microsoft.com/en-us/azure/virtual-network-manager/overview
This also creates a logic app that will delete the resource group in 24hrs.

The topology will look like this:
<img width="985" height="778" alt="avnmlab" src="https://github.com/user-attachments/assets/a194ee57-cd98-4cf4-9cc5-a8df9b4e0a49" />

You can run Terraform right from the Azure cloud shell by cloning this git repository with "git clone https://github.com/quiveringbacon/AzureAVNM-lab.git ./terraform".

Then, "cd terraform" then, "terraform init" and finally "terraform apply -auto-approve" to deploy.

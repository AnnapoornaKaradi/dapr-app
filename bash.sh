#!/bin/bash

set -x

error() {
    echo "ERROR: $1" >&2 #write to stderr
    exit 1
}

# Upgrade the system
echo "Updating OS"
sudo apt-get update || exit 1
echo "Setting non interactive for frontend"
sudo DEBIAN_FRONTEND="noninteractive" apt-get upgrade -y || exit 1

# Install gpg version 1 and make it the default
echo "Installing GPG version 1"
sudo apt-get install -y gnupg1 || error "gpg install failed"

# Install additional utilities
echo "Installing additional utilities"
sudo apt-get install -y unzip apt-transport-https || error "Additional utilities install failed"

# Add the Microsoft repository
echo "Adding Microsoft Repo"
curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc || error "Microsoft repo download failed"
echo | sudo apt-add-repository https://packages.microsoft.com/ubuntu/22.04/prod || error "Microsoft repo add failed"

# Pin Microsoft packages to the Microsoft repository
echo "Pinning Microsoft packages for Microsoft repo"
sudo tee -a /etc/apt/preferences.d/microsoft-dotnet.pref > /dev/null <<EOT
Package: *
Pin: origin "packages.microsoft.com"
Pin-Priority: 1001
EOT

sudo apt-get update || exit 1

# Install Azure CLI
echo "Installing Azure CLI"
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
sudo apt-get update || exit 1
sudo apt-get install -y azure-cli || error "Azure CLI failed to install" 

# Download the StackRox command line utility and install it
echo "Installing StackRox command line utility"
sudo az storage blob download --container-name ${container_name} --file "/usr/local/bin/roxctl" --name "roxctl" --account-name ${storage_account_name} --sas-token "${sas_token}" || error "Azure blob storage donload command failed"
sudo chmod +x /usr/local/bin/roxctl || error "StackRox ctl chmod command failed"

# Install Terraform v0.14.11
sudo rm /usr/local/bin/terraform
sudo wget https://releases.hashicorp.com/terraform/0.14.11/terraform_0.14.11_linux_amd64.zip || exit 1
sudo unzip terraform_0.14.11_linux_amd64.zip -d /usr/local/bin || exit 1
sudo rm terraform_0.14.11_linux_amd64.zip || exit 1

# Install Helm
echo "Installing Helm"
sudo rm -fr /usr/local/bin/helm || exit
sudo rm -fr /tmp/helm && sudo mkdir /tmp/helm || error "Removal of current helm directory and creation of new temp directory failed"
sudo wget https://get.helm.sh/helm-v3.16.3-linux-amd64.tar.gz || error "WGET of helm package failed" 
sudo tar -zxvf helm-v3.16.3-linux-amd64.tar.gz -C /tmp/helm || error "unzip command of helm package failed" 
sudo mv /tmp/helm/linux-amd64/helm /usr/local/bin/helm || error "Move command of temp helm directory to local bin failed"
sudo rm -R /tmp/helm || error "Removal of temp helm directory failed"

# Install kubectl v1.30
echo "Installing Kubectl"
sudo apt-get update && sudo apt-get install -y gnupg2 || error "Apt get system update and install gnupg2 failed" 
sudo mkdir -p /etc/apt/keyrings || error "Make directory for keyrings failed" 
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg || error "Curl and key ring add failed for kubectl failed"
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list || error "Keyring gpg add failed"
sudo apt-get update || error "Fourth system update failed"
sudo apt-get install -y kubectl || error "Kubectl install failed" 

# Install docker
echo "Installing docker"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/trusted.gpg.d/docker.asc || error "Curl and gpg key download for Docker failed"
echo | sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" || error "GPG key add failed for docker" 
sudo apt-get update || error "Fifth system update failed" 
sudo apt-get install -y docker-ce docker-ce-cli containerd.io || error "Docker CE and docker cli install failed" 

# Create an encryption key
echo "Creating an encryption key"
sudo head /dev/urandom | tr -dc A-Za-z0-9 | head -c 128 | sudo tee -a /root/enc_key || error "Encryption key creation failed" 

# Install the dotnet 6.0 and 8.0 SDK
echo "Installing DotNet SDKs"
sudo apt-get -y remove  dotnet* aspnetcore* netstandard* || error "Removal of dotnet, aspnetcore, and netstandard packages failed"
sudo rm -fr /etc/apt/sources.list.d/microsoft-prod.list || error "Removal of microsoft prod list failed"
sudo apt-get update || error "Sixth system update failed"
sudo apt-get install -y dotnet-sdk-6.0 || error "Installation of dotnet sdk 6.0 failed"
sudo apt-get install -y dotnet-sdk-8.0 || error "Installation of dotnet sdk 8.0 failed"


# Install mono
echo "Installing mono"
sudo apt-get install -y mono-complete || error "Installation of Mono failed"

# Install powershell
echo "Installing Powershell"
sudo curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/powershell-7.4.5-linux-x64.tar.gz || error "Curl of powershell failed"
sudo mkdir -p /opt/microsoft/powershell/7 || error "Directory make command for powershell failed"
sudo tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 || error "Unzip of powershell packaged failed"
sudo chmod +x /opt/microsoft/powershell/7/pwsh || error "Chmod of pwsh failed"
sudo ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh || error "Sudo link of pwsh failed"

# Install the Azure powershell module
echo "Installing Azure powershell module"
sudo pwsh -command "install-module -name az -allowclobber -force" || error "Azure powershwell module install failed"

# Install zip
echo "Installing zip utliity"
sudo apt-get install -y zip || error "Zip apt install failed"

# Install maven and jq
echo "Installing maven and jq"
sudo apt-get install -y maven jq || error "Maven and jq apt install failed"

# Install haveged to provide entropy for gpg commands
echo "Insalling havegod for gpg commands"
sudo apt-get install -y haveged || error "haveged apt install failed"

# Install python3 and related tools
echo "Instlaling Python3 and tools"
sudo apt-get install -y python3 python3-pip python3-venv || error "Python3 and pip apt install failed"

# Install additional python modules
echo "Installing azure-cli, requests and pyyaml through pip"
sudo pip3 install azure-cli || error "Pip3 azure cli install failed"
sudo pip3 install --upgrade requests || error "Pip3 requests install failed" 
sudo pip3 install pyyaml || error "Pip3 pyyaml install failed"

# Install MS SQL Linux tools
echo "Installing MS SQL linux tools"
sudo ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive apt-get install -y mssql-tools18 unixodbc-dev || error "MSSQL-tools18 and unixodbc apt install failed"
sudo ln -sfn /opt/mssql-tools18/bin/sqlcmd /usr/bin/sqlcmd || error "Sudo link for sqlcmd to usr bin failed"

# Install Google Chrome
echo "Installing Chrome"
wget -P /tmp https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb || error "WGET of google chrome deb package failed"
sudo apt-get install -y /tmp/google-chrome-stable_current_amd64.deb || error "Google chrome deb package install failed"

# Install Grype
echo "Installing Grype"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || error "Download and install of Grype failed"

# Install Cortex
echo "Installing Cortex"
sudo az storage blob download --container-name "cortex" --file "/tmp/FNF_Linux_8-7_sh.tar.gz" --name "FNF_Linux_8-7_sh.tar.gz" --account-name ${storage_account_name} --sas-token "${sas_token}" || error "Azure blob storage donload command failed"
sudo mkdir -p /tmp/cortex
sudo tar -zvxf /tmp/FNF_Linux_8-7_sh.tar.gz -C /tmp/cortex || error "Extractin Cortext file failed"
sudo mkdir -p /etc/panw 
sudo mv /tmp/cortex/cortex.conf /etc/panw/ || error "Moving cortex.conf to /etc/panw failed"
sudo chmod -x /tmp/cortex/cortex-8.7.0.131661.sh  || error "Add execute perms to cortext script"
sudo /usr/bin/bash /tmp/cortex/cortex-8.7.0.131661.sh -- --vm-template || error "Error installing Cortex"
sudo usermod -u 1909 cortexuser
sudo groupmod -g 1909 cortexuser

# Deprovision
nohup sudo sleep 5 && waagent -deprovision+user -force || exit 1 &

exit 0

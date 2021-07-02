#!/bin/bash

#Function to output message to StdErr
function echo_stderr ()
{
    echo "$@" >&2
    exit 1
}

#Function to display usage message
function usage()
{
  echo_stderr "./configureSSLForDCServerTemplate.sh <adminVMName> <wlsDomainName> <wlsUserName> <wlsPassword> <oracleHome> <wlsDomainPath> <managedServerPrefix> <numberOfExistingNodes> <isCoherenceEnabled> <numberOfCoherenceCacheInstances> <vmIndex> <enableAAD> <wlsADSSLCer> <isCustomSSLenabled> <customIdentityKeyStoreBase64String> <customIdentityKeyStorePassPhrase> <customIdentityKeyStoreType> <customTrustKeyStoreBase64String> <customTrustKeyStorePassPhrase> <customTrustKeyStoreType> <privateKeyAlias> <privateKeyPassPhrase>"
}

function validateInput()
{
    if [ -z "$adminVMName" ];
    then
        echo_stderr "adminVMName is required. "
    fi

    if [ -z "$wlsDomainName" ];
    then
        echo_stderr "wlsDomainName is required. "
    fi

    if [[ -z "$wlsUserName" || -z "$wlsPassword" ]]
    then
        echo_stderr "wlsUserName or wlsPassword is required. "
    fi

    if [ -z "$oracleHome" ];
    then
        echo_stderr "oracleHome is required. "
    fi

    if [ -z "$wlsDomainPath" ];
    then
        echo_stderr "wlsDomainPath is required. "
    fi

    if [[ "$enableAAD" == "true" ]];
    then
        if [[ -z "$wlsADSSLCer" ]]
        then
            echo_stderr "wlsADSSLCer is required. "
        fi
    fi

    if [[ -z "$managedServerPrefix" ]];
    then
        echo_stderr "managedServerPrefix is required. "
    fi

    if [ "$isCustomSSLEnabled" == "true" ];
    then
        if [[ -z "$customIdentityKeyStoreBase64String" || -z "$customIdentityKeyStorePassPhrase"  || -z "$customIdentityKeyStoreType" ||
              -z "$customTrustKeyStoreBase64String" || -z "$customTrustKeyStorePassPhrase"  || -z "$customTrustKeyStoreType" ||
              -z "$privateKeyAlias" || -z "$privateKeyPassPhrase" ]]
        then
            echo_stderr "customIdentityKeyStoreBase64String, customIdentityKeyStorePassPhrase, customIdentityKeyStoreType, customTrustKeyStoreBase64String, customTrustKeyStorePassPhrase, customTrustKeyStoreType, privateKeyAlias and privateKeyPassPhrase are required. "
            exit 1
        fi
    else
        echo "SSL configuration not enabled as iscustomSSLEnabled was set to false. Please set the flag to true and retry."
        exit 1
    fi
}

#Function to cleanup all temporary files
function cleanup()
{
    echo "Cleaning up temporary files..."
    rm -rf $wlsDomainPath/managed-domain.yaml
    rm -rf $wlsDomainPath/weblogic-deploy.zip
    rm -rf $wlsDomainPath/weblogic-deploy
    rm -rf $wlsDomainPath/*.py
    rm -rf ${SCRIPT_PATH}/*
    echo "Cleanup completed."
}

#configure SSL on Admin Server
function configureSSLOnDynamicClusterServerTemplate()
{
    echo "Configuring SSL on Dynamic Cluster Server Template"
    cat <<EOF >${SCRIPT_PATH}/configureSSLServerTemplate.py

isCustomSSLEnabled='${isCustomSSLEnabled}'

connect('$wlsUserName','$wlsPassword','t3://$wlsAdminURL')
edit("$dynamicClusterServerTemplate")
startEdit()

if isCustomSSLEnabled == 'true' :
    cd('/ServerTemplates/$dynamicClusterServerTemplate')
    cmo.setKeyStores('CustomIdentityAndCustomTrust')
    cmo.setCustomIdentityKeyStoreFileName('$customSSLIdentityKeyStoreFile')
    cmo.setCustomIdentityKeyStoreType('$customIdentityKeyStoreType')
    set('CustomIdentityKeyStorePassPhrase', '$customIdentityKeyStorePassPhrase')
    cmo.setCustomTrustKeyStoreFileName('$customSSLTrustKeyStoreFile')
    cmo.setCustomTrustKeyStoreType('$customTrustKeyStoreType')
    set('CustomTrustKeyStorePassPhrase', '$customTrustKeyStorePassPhrase')

    cd('/ServerTemplates/$dynamicClusterServerTemplate/SSL/$dynamicClusterServerTemplate')
    cmo.setServerPrivateKeyAlias('$privateKeyAlias')
    set('ServerPrivateKeyPassPhrase', '$privateKeyPassPhrase')
    cmo.setHostnameVerificationIgnored(true)

cd('/ServerTemplates/$dynamicClusterServerTemplate/ServerStart/$dynamicClusterServerTemplate')
arguments = '-Dweblogic.security.SSL.ignoreHostnameVerification=true -Dweblogic.management.server=http://$wlsAdminURL ${wlsCoherenceArgs}'
cmo.setArguments(arguments)

save()
resolve()
activate()
destroyEditSession("$dynamicClusterServerTemplate")
disconnect()
EOF

sudo chown -R $username:$groupname ${SCRIPT_PATH}/configureSSLServerTemplate.py

echo "Running wlst script to configure SSL on $dynamicClusterServerTemplate"
runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; java $WLST_ARGS weblogic.WLST ${SCRIPT_PATH}/configureSSLServerTemplate.py"
if [[ $? != 0 ]]; then
     echo "Error : SSL Configuration for $dynamicClusterServerTemplate failed"
     exit 1
fi

}


#This function to wait for admin server 
function wait_for_admin()
{
echo "Waiting for admin server to start"
 #wait for admin to start
count=1
CHECK_URL="http://$adminVMName:$wlsAdminChannelPort/weblogic/ready"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`

if [ "$status" == "200" ];
then
    echo "Server admin started succesfully..."
    return
else
    while [[ "$status" != "200" ]]
    do
      echo "admin server still not reachable at $CHECK_URL .. $count"
      count=$((count+1))
      if [ $count -le 10 ];
      then
          sleep 1m
      else
         echo "Error : Maximum attempts exceeded while starting admin server"
         exit 1
      fi
      status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
      if [ "$status" == "200" ];
      then
         echo "Server $wlsServerName started succesfully..."
         break
      fi
    done
fi
}


function parseLDAPCertificate()
{
    echo "create key store"
    cer_begin=0
    cer_size=${#wlsADSSLCer}
    cer_line_len=64
    mkdir ${SCRIPT_PWD}/security
    touch ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt
    while [ ${cer_begin} -lt ${cer_size} ]
    do
        cer_sub=${wlsADSSLCer:$cer_begin:$cer_line_len}
        echo ${cer_sub} >> ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt
        cer_begin=$((cer_begin+$cer_line_len))
    done

    openssl base64 -d -in ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt -out ${SCRIPT_PWD}/security/AzureADTrust.cer
    addsCertificate=${SCRIPT_PWD}/security/AzureADTrust.cer
}

function importAADCertificateIntoWLSCustomTrustKeyStore()
{
    if [ "${isCustomSSLEnabled,,}" == "true" ];
    then
        # set java home
        . $oracleHome/oracle_common/common/bin/setWlstEnv.sh

        #validate Trust keystore
        runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -storetype $customTrustKeyStoreType | grep 'Entry type:' | grep 'trustedCertEntry'"

        if [[ $? != 0 ]]; then
            echo "Error : Trust Keystore Validation Failed !!"
            exit 1
        fi

        # For SSL enabled causes AAD failure #225
        # ISSUE: https://github.com/wls-eng/arm-oraclelinux-wls/issues/225

        echo "Importing AAD Certificate into WLS Custom Trust Key Store: "

        sudo ${JAVA_HOME}/bin/keytool -noprompt -import -trustcacerts -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -alias aadtrust -file ${addsCertificate} -storetype $customTrustKeyStoreType
    else
        echo "customSSL not enabled. Not required to configure AAD for WebLogic Custom SSL"
    fi
}

function validateSSLKeyStores()
{
   sudo chown -R $username:$groupname $KEYSTORE_PATH

   #validate identity keystore
   runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLIdentityKeyStoreFile -storepass $customIdentityKeyStorePassPhrase -storetype $customIdentityKeyStoreType | grep 'Entry type:' | grep 'PrivateKeyEntry'"

   if [[ $? != 0 ]]; then
       echo "Error : Identity Keystore Validation Failed !!"
       exit 1
   fi

   #validate Trust keystore
   runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -storetype $customTrustKeyStoreType | grep 'Entry type:' | grep 'trustedCertEntry'"

   if [[ $? != 0 ]]; then
       echo "Error : Trust Keystore Validation Failed !!"
       exit 1
   fi

   echo "ValidateSSLKeyStores Successfull !!"
}

function parseAndSaveCustomSSLKeyStoreData()
{
    echo "create key stores for custom ssl settings"

    mkdir -p ${KEYSTORE_PATH}
    touch ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt

    echo "$customIdentityKeyStoreBase64String" > ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt
    cat ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt | base64 -d > ${KEYSTORE_PATH}/identity.keystore
    customSSLIdentityKeyStoreFile=${KEYSTORE_PATH}/identity.keystore

    rm -rf ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt

    mkdir -p ${KEYSTORE_PATH}
    touch ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt

    echo "$customTrustKeyStoreBase64String" > ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt
    cat ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt | base64 -d > ${KEYSTORE_PATH}/trust.keystore
    customSSLTrustKeyStoreFile=${KEYSTORE_PATH}/trust.keystore

    rm -rf ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt

    validateSSLKeyStores
}

#main script starts here

SCRIPT_PWD=`pwd`

# store arguments in a special array 
args=("$@") 
# get number of elements 
ELEMENTS=${#args[@]} 
 
# echo each element in array  
# for loop 
#for (( i=0;i<$ELEMENTS;i++)); do 
#    echo "ARG[${args[${i}]}]"
#done

if [ $# -lt 15 ]
then
    usage
    exit 1
fi
wlsServerName="admin"

adminVMName=$1
wlsDomainName=$2
wlsUserName=$3
wlsPassword=$4
oracleHome=$5
wlsDomainPath=$6

managedServerPrefix=${7}
coherenceServerPrefix="${managedServerPrefix}Storage"
dynamicClusterSize="${8}"
maxDynamicClusterSize="${9}"

wlsServerName="admin"

enableAAD="${10}"
enableAAD="${enableAAD,,}"

wlsADSSLCer="${11}"

isCustomSSLEnabled="${12}"
isCustomSSLEnabled="${isCustomSSLEnabled,,}"

if [ "${isCustomSSLEnabled,,}" == "true" ];
then
    customIdentityKeyStoreBase64String="${13}"
    customIdentityKeyStorePassPhrase="${14}"
    customIdentityKeyStoreType="${15}"
    customTrustKeyStoreBase64String="${16}"
    customTrustKeyStorePassPhrase="${17}"
    customTrustKeyStoreType="${18}"
    privateKeyAlias="${19}"
    privateKeyPassPhrase="${20}"
fi

wlsAdminPort=7001
wlsAdminSSLPort=7002
wlsAdminChannelPort=7005
wlsManagedServerPort=8001
wlsCoherenceServerPort=7501
wlsAdminURL="$adminVMName:$wlsAdminChannelPort"

coherenceLocalport=42000
coherenceLocalportAdjust=42200
coherenceDebugSettings="-Djavax.net.debug=ssl,handshake -Dcoherence.log.level=9"
wlsCoherenceArgs="-Dcoherence.localport=$coherenceLocalport -Dcoherence.localport.adjust=$coherenceLocalportAdjust"

username="oracle"
groupname="oracle"

clusterName="cluster1"
coherenceClusterName="storage1"
dynamicClusterServerTemplate="myServerTemplate"

KEYSTORE_PATH="$wlsDomainPath/$wlsDomainName/keystores"
SCRIPT_PATH="/u01/app/scripts"

mkdir -p ${SCRIPT_PATH}
sudo chown -R ${username}:${groupname} ${SCRIPT_PATH}

validateInput
cleanup
parseAndSaveCustomSSLKeyStoreData

if [ "$enableAAD" == "true" ];
then
    parseLDAPCertificate
    importAADCertificateIntoWLSCustomTrustKeyStore
fi

configureSSLOnDynamicClusterServerTemplate

wait_for_admin

cleanup


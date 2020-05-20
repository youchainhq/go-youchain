#!/usr/bin/env bash
app_name=feature-ci
version=`git show -s --pretty=format:%h`
job="yctest-$version"
bran=`git name-rev --name-only HEAD`
appbranch=${bran#*origin/}
time=$(date +%Y%m%d%H%M%S)
###########################################################################################################################################
#
app_name_version="$app_name-$version"
app_image_version="$app_name:$version"
yaml="combo.yaml_$version"
/bin/cp combo.yaml $yaml
jobstat=null
#
deploy()
{
         sed -i "s/{ci_identify_app_name_version}/$app_name_version/g" $yaml
         sed -i "s/{ci_identify_app_image_version}/$app_image_version/g" $yaml
         sed -i "s/{ci_identify_job_name}/$job/g" $yaml
         sed -i "s#{branch}#$appbranch#g" $yaml
         sed -i "s/{commit}/$version/g" $yaml
         sed -i "s/{timeci}/$time/g" $yaml
         scp -P 65535 $yaml root@$APISERVERIP:/tmp/$yaml
         ssh -p 65535 root@$APISERVERIP "kubectl create -f /tmp/$yaml"
         rm -rf $yaml
}

test()
{
sleep 3s
# get log
podname=$(curl -X GET $APISERVER/api/v1/namespaces/default/pods?labelSelector={app=$job} -s --header "Authorization: Bearer $APITOKEN" --insecure | jq -r .items[0].metadata.name )
echo $podname
curl -X GET $APISERVER/api/v1/namespaces/default/pods/$podname/log?follow=true -s --header "Authorization: Bearer $APITOKEN" --insecure
# check job status
status=$(curl -X GET $APISERVER/apis/batch/v1/namespaces/default/jobs/$job/status -s --header "Authorization: Bearer $APITOKEN" --insecure)

stat=$(echo "$status"|jq .status)
echo "$stat"
if [ "$stat" = "\"Failure\"" ]; then
  jobstat=failed
else
  active=$(echo "$status"|jq .status.active)
  while [ "$active" = "1" ]; do
    sleep 1s
    curl -X GET $APISERVER/api/v1/namespaces/default/pods/$podname/log?follow=true -s --header "Authorization: Bearer $APITOKEN" --insecure
    status=$(curl -X GET $APISERVER/apis/batch/v1/namespaces/default/jobs/$job/status -s --header "Authorization: Bearer $APITOKEN" --insecure)
    active=$(echo "$status"|jq .status.active)
  done
  # job is done, check result
  fc=$(echo "$status"|jq .status.failed)
  if [ "$fc" = "1" ]; then
    jobstat=failed
  else
    jobstat=successed
  fi
fi

podIp=$(curl -X GET $APISERVER/api/v1/namespaces/default/pods?labelSelector={app=youchain-$app_name_version} -s --header "Authorization: Bearer $APITOKEN" --insecure | jq -r .items[0].status.podIP)
echo "label:\tyouchain-"$app_name_version
echo "dump state of pod:\t"$podIp
ssh -p 65535 root@$APISERVERIP "curl -s -X POST http://$podIp:8283 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"dev_stateDump\",\"params\":[]}'"

ssh -p 65535 root@$APISERVERIP "kubectl delete -f /tmp/$yaml"

# return
if [ "$jobstat" = "failed" ]; then
    exit 1
fi
}
#
################
#
$1
#
###########################################################################################################################################

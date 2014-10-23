vSphereTool
=========

Introduction
------------

> The vSphere is a single file script to help administrators automate the creation of resources as well as being a swiss army knife for vSphere administrators to help make their lives a bit easier. It makes use of the pyVmomi Module to interact with the vSphere API to action requests around the orchestration of the vSphere infrastructure.

TLDR;
----
```
usage: main [-h] [-l LOGFILE] [-q] [-s] [-v] -f FARM -m MODE [-d DETAIL] [-e EXTRA] [-c CONFIG] [-D] [-r REGEX] 
[-C COMMAND] [-S SCRIPT][-A] [-a ARTIFACT] [-T] [-TC]

optional arguments:
-h, --help                          show this help message and exit
-l LOGFILE, --logfile               LOGFILE log to file (default: log to stdout)
-q, --quiet                         decrease the verbosity
-s, --silent                        only log warnings
-v, --verbose                       raise the verbosity
-f FARM, --farm FARM                Which vSphere you want to connect to in your config
-m MODE, --mode MODE                What to make vSphere do. Excepted Values: 
                                    ['index','create','command','script','snapshot','powercycle','filedrop']
-d DETAIL, --detail DETAIL          What to search for ['datastore','vms','hostsystems','dvport','templates',
                                    'resourcepool','datacentres','folders','vlans']
-e EXTRA, --extra EXTRA             Extra detail to add to a given mode
-c CONFIG, --config CONFIG          Change the Configuration file to use
-r REGEX, --regex REGEX             Changes the script behaviour to search for instances
-C COMMAND, --Command COMMAND       Which command to run with arguements separated by the space character 
-S SCRIPT, --script SCRIPT          Which script to be run on the GuestOS on the VM
-A, --auto                          Changes script to not prompt for instruction and take best fit where possible!
-a ARTIFACT, --artifact ARTIFACT    A List of files to be dropped on the server (Does not work recursivly on folders! You
                                    may want to tar/zip files!) e.g. -a artifact1 -a artifact2
-T, --tokenize                      Action to decide if a script that you are running on the Virtual Instance needs to be
                                    de-tokenized - Requires a definitions.py file
-TC, --tokenize-config              Action to decide if a run list being processed should be de-tokenized - Requires a
                                    definitions.py file
```

Assumptions
-----------

- You are cloning/deploying through Templates
- Your Templates have been prepared as described [here]
- You have a standard naming convention for your Instances
- You use vSphere API 4.0 and ESXi 5.1 or greater
- Your templates have the latest VMWare tools installed

Setup
-----

**install**

> First, install all the required modules with:

```
pip install -r requirements.txt
```

**config file**

> Fill in the YAML configuration to give the script the needed parameters to connect to your vSphere API

```
---
vsphere:
  DATACENTRE-1: #Farm Name
    username: 'SuperAdminAccount'
    password: "" #LeaveBlank to be prompted 
    hostname: "1.1.1.1"
    port: 1234
  DATACENTRE-A: #Farm Name
    username: 'SuperAdminAccount'
    password: "" #LeaveBlank to be prompted 
    hostname: "1.1.1.2"
    port: 1234
```

> At this point you can use a lot of the functionality of the script, but to get more control and repeatability of your environment you can configure the definitions file and runlists.

Runlists
--------

> Runlists are a powerful way of creating your infrastructure in an ordered way. It can allow you to build an environment with a single command and provides updates while you watch the infrastructure build.
> Using this functionality with tokens allows you to create repeatable environments that can be different depending on how the tokens are placed. You can even use tokens to populate other tokens to allow the operator to keep convention while maintaining a single set of scripts and runlists.

> For Example:

```
---
- Instance1:
  name: slightly-awesome-server-@DC_LOWER@-001
  order: serial #Instructs the script to wait for the build to finish
  template: basic_base
  memory: 2048
  cpu: 1
  domain: superawesomedomain
  ip: 1.1.1.2
  subnet: 0.0.0.0
  gw: 1.1.1.254
  folder: /@DC_UPPER@/VMs
  datacentre: @DC_UPPER@
  datastore: @DC_UPPER@_SHARED_DATA
  resourcepool: Resources
  notes: 
  vlan: e1000:@DC_UPPER@-INFRA-123 
  scripts:
  - ./scripts/hello_world.sh @@DC_UPPER@_FRIENDLY_MESSAGE@ #Double token
  artifacts:
  - ./artifacts/passwds.zip
  commands:
  - ./bin/ls
- Instance2:
  order: parallel #Makes the instance build in a background thread!
  name: awesome-server-@DC_LOWER@-001
  template: basetemplate
  memory: 2048
  cpu: 1
  domain: superawesomedomain
  ip: 1.1.1.3
  subnet: 0.0.0.0
  gw: 1.1.1.254
  folder: /@DC_UPPER@/VMs
  datacentre: @DC_UPPER@
  datastore: @DC_UPPER@_SHARED_DATA
  resourcepool: Resources
  notes: DNS
  vlan: e1000:@DC_UPPER@-INFRA-123
  scripts:
  - ./scripts/dns.sh
  artifacts:
  commands:
```

Definitions and Tokenisation
----------------------------

> The Definitions file is where the script gets its information to tokenise the scripts, runlists and data supplied to creations commands.
> It is a python Dictionary and it is pretty easy to understand, Just add your Key and Value to this file and the add your Key to any script or runlist to allow it be detokenised.

```
#!/usr/bin/env python

#If a token requires another token then please specify it before the needed token

def definitions(self):
    definitions = {
      '@DATA_CENTRE-A_FRIENDLY_MESSAGE@' : "Hello World!",
      '@DATA_CENTRE-1_FRIENDLY_MESSAGE@' : "World Hello!",
      '@FRIENDLY_MESSAGE@'               : "@@CU_UPPER@_FRIENDLY_MESSAGE@",
      '@DC_LOWER@'                       : str(self.params.farm).lower(),
      '@DC_UPPER@'                       : self.params.farm,
      }
```

Modes
-----

> The script was designed to be a single file script but has grown many functions, to run the script you need to select a mode to run in.

#index

> The index mode allows the user to catalogue the resources of the vSphere but needs to know what to show. The user has the following choices:

- datastore
- vms
- hostsystems
- dvport
- templates
- resourcepool
- datacentres
- folders
- vlans

> For example:

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m index -d <OPTION> [-r <REGEX TO SEARCH ACROSS>]
```

#create

> Allows the creation of VMs from templates. The script will run through a given runlist to create and deploy the requested Instances, this includes dropping files, running scripts as well as simple commands.

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m create -e ./runlists/dummy.yaml [-A] [-T] [-TC] #A for Auto mode - T For tokenisation of the variables supplied
```

#command

> Allows the operator to run individual commands on a single, or many instances through the VMWare guest tools interface as long as the user can authenticate on the guest operating system

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m command -r <REGEX TO MATCH THE INSTANCES>  -C '/usr/bin/puppet agent -vt'  [-A] [-T] [-TC] #A for Auto mode - T For tokenisation of the variables supplied
```

#script

> Allows the operator to run a bash script on one or many instances fitting a given regex. The file is uploaded through the VMWare API and then run through the guest VMWare tools.

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m scripts -r <REGEX TO MATCH THE INSTANCES>  -S './script/helloworld.sh -a red'  [-A] [-T] [-TC] #A for Auto mode - T For tokenisation of the variables supplied
```

#powercycle

> Allows the user to power cycle one or many Instances via the API and VMWare tools running on the Guest OS

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m powercycle -r <REGEX TO MATCH THE INSTANCES>  -C '/usr/bin/puppet agent -vt'  [-A] #A for Auto mode
```

#filedrop

> Allows the operator to drop one or many files (Not recursivly, the user should zip them first) on one or many Instances.

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m filedrop -r <REGEX TO MATCH THE INSTANCES>  -a './artifacts/dummy.zip' -a './artifacts/dummy2.sh'  [-A] #A for Auto mode
```

NOT IMPLEMENTED YET
-------------------

#snapshot

> Allows the operator to quickly create a snapshot, should be used while patching in case a quick roll back is needed

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m snapshot -r <REGEX TO MATCH THE INSTANCES>  [-A] #A for Auto mode
```

#migrate

> Allows the operator to migrate a VM from one host to another, the user should make sure that vMotion is available and in use or should power the instance down before using this option.

```
$ ./vSphere.py -f <VSPHERE LABEL IN CONFIG FILE> -m powercycle -r <REGEX TO MATCH THE INSTANCES>  [-A] #A for Auto mode
```

License
----

> MIT

[meh]:http://www.test.com
[here]:http://lonesysadmin.net/2013/03/26/preparing-linux-template-vms/
